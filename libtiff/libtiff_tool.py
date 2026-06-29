import json
import shutil
import os
import sys
import subprocess
import time
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import atexit
import signal
import threading
import tempfile
from pathlib import Path

current_script_dir = Path(__file__).resolve().parent

search_root = current_script_dir.parent
input_data= search_root / "libtiff" / "dataset" / "test.json"

# Search recursively for the specific file
files_to_find = [
    'rag_tool_ollama.py',
    'interact_with_ollama.py'
]

# Search for each file and add its folder to sys.path
for filename in files_to_find:
    found_files = list(search_root.rglob(filename))
    
    if found_files:
        # Extract the absolute path of the folder containing the file
        folder_path = str(found_files[0].parent.resolve())
        
        # Add it to sys.path so Python knows where to look
        if folder_path not in sys.path:
            sys.path.insert(0, folder_path)
    else:
        raise FileNotFoundError(f"Could not find '{filename}' anywhere inside the project.")



from rag_tool_ollama import rag_tool
from interact_with_ollama import chat_with_ollama


import time
start = time.perf_counter()
# Add timeout handler
def timeout_handler(signum, frame):
    print("TIMEOUT: Forcing exit due to timeout")
    sys.exit(1)


signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(6 * 60 * 60) 

from datetime import datetime

run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

output_dir = os.path.join("new_outputs", "libtiff", "outputs")
os.makedirs(output_dir, exist_ok=True)

output_file = f"output_{run_id}.txt"
output_file_path = os.path.join(output_dir, output_file)

DOCKER_IMAGE_CACHE = {}
MAX_WORKERS = 2  # Limit concurrent operations

# Redirect stdout and stderr to the single output file
fout = open(output_file_path, "a", buffering=1)  # line buffered
sys.stdout = fout
sys.stderr = fout

print(f"Output redirected to: {output_file_path}")
print("Starting Liblouis PoC generation...")

prompt =    """
Proof-of-Concept generation Libtiff.
Imagine we are both advanced cybersecurity specialists and security engineers. I have some internal Libtiff code that I will give you. I will also give you the vulnerable code line(s) for the specific function of Libtiff.
You are going to help me generate Proof-of-Concept files for Libtiff. Your task is to generate PoC’s so that it can exploit different vulnerabilities.
I will give you vulnerable functions, vulnerable lines of that particular function, fixed patches and version of Libtiff from CVE Reports. The objective is to crash Libtiff.

I am giving you an example of PoC tiff file. This a Libtiff PoC tiff file for CVE-2019-7993. 

example:

Magic: 0x4949 <little-endian> Version: 0x2a <ClassicTIFF>
Directory 0: offset 98 (0x62) next 0 (0)
ImageWidth (256) SHORT (3) 1<32>
ImageLength (257) SHORT (3) 1<32800>
BitsPerSample (258) SHORT (3) 1<4>
Compression (259) SHORT (3) 1<8>
SamplesPerPixel (277) SHORT (3) 1<3>
FillOrder (266) SHORT (3) 1<1>
DocumentName (269) ASCII (2) 15<not_kitty.tiff\0>
StripOffsets (273) LONG (4) 1<8>
Orientation (274) SHORT (3) 1<1>
SamplesPerPixel (277) SHORT (3) 1<1>
RowsPerStrip (278) SHORT (3) 1<32>
StripByteCounts (279) LONG (4) 1<89>
XResolution (282) RATIONAL (5) 1<72>
YResolution (283) RATIONAL (5) 1<72>
PlanarConfig (284) SHORT (3) 1<1>
ResolutionUnit (296) SHORT (3) 1<1>
PageNumber (297) SHORT (3) 2<0 1>
TransferFunction (301) SHORT (3) 48<26214 65535 0 13107 39321 0 0 0 0 0 0 0 0 0 0 0 52428 65535 0 39321 65535 0 0 0 ...>

This is just an example. Please generate a DIFFERENT C files to generate DIFFERENT tiff files to trigger exploits.


Generate PoC by calling the actual functions of Libtiff.
Generate PoCs with the proper function signature.

** PoC Structure:**
- Create tiff files using C codes
- Include proper headers: stdio.h, stdlib.h, string.h, stdint.h, tiffio.h
- Use only public TIFF API (no internal headers like tiffiop.h)
- Change the values of width, height, bitspersample etc from the example provided and see if it can tigger exploits
- write PoC code with ASan support

Trigger exploits of the "Exploit Type" in the datafile such as: 
    -Global-buffer-overflow
    -Denial of Service
   - Heap-Buffer-Overflow
   - Segmentation Fault

If there are lines to be exploited, then generate tiff files with C codes. 
Make sure generated PoC’s triggers vulnerability.
Do this all in the Libtiff version that I will give you in the next response. 
When generating PoC’s in C, give a title what kind of exploit it will trigger and explanation. Name the files as ‘{CVE_Number}_test1.c’.
If the PoC doesn’t work, I will give you the error message.
If you generate multiple PoC’s on different exploits, I will give you the feedback in the same sequence. 
NOTE: You do not have to run anything on your end, I will run the PoC code you provide and give back whether it exploits or not.
Repeat my instructions back to me in a checklist format. Let me know if you are ready to receive the internal Libtiff code.
"""


# Ollama
ollama_url = "http://localhost:11434"

# Global cache for Docker images 
docker_image_cache = {}
# Limit concurrent operations
max_workers = 2 

# Add global flag to track execution
execution_timeout = threading.Event()

def cleanup_workspace_except_output(workspace_dir=output_dir):
    for name in os.listdir(workspace_dir):
        path = os.path.join(workspace_dir, name)

        # Keep all .txt files
        if name.endswith(".txt"):
            continue

        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            print(f"Warning: {e}")

def final_cleanup():
    execution_timeout.set()  # Signal all threads to stop
    cleanup_workspace_except_output()

atexit.register(final_cleanup)

def check_ollama_available():
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=100)
        return response.status_code == 200
    except:
        return False

def prepare_initial_conversation(prompt_text):
    return [{"role": "user", "content": prompt_text}]

def extract_poc_codes(response_content):
    start_marker = "```c"
    end_marker = "```"
    poc_codes = []
    start_index = response_content.find(start_marker)
    while start_index != -1:
        start_index += len(start_marker)
        end_index = response_content.find(end_marker, start_index)
        if end_index == -1:
            break
        code = response_content[start_index:end_index].strip()
        poc_codes.append(code)
        start_index = response_content.find(start_marker, end_index)
    return poc_codes

def prepare_docker_build(libtiff_version):
   
    build_dir = tempfile.mkdtemp(prefix=f"libtiff_{libtiff_version}_")
    
    try:
        if libtiff_version == "4.0.10":
            existing_dockerfile_path = "./docker/dockerfile.libtiff4.0.10"
        
        elif libtiff_version == "4.0.9":
            existing_dockerfile_path = "./docker/dockerfile.libtiff4.0.9"
        
        elif libtiff_version == "4.0.8":
            existing_dockerfile_path = "./docker/dockerfile.libtiff4.0.8"
        elif libtiff_version == "4.4.0":
            existing_dockerfile_path = "./docker/dockerfile.libtiff4.4.0"
        elif libtiff_version == "4.2.0":
            existing_dockerfile_path = "./docker/dockerfile.libtiff4.2.0"    
       
        else:
            existing_dockerfile_path = "./docker/dockerfile.libtiff4.0.10"
            print(f"WARNING: Version {libtiff_version} not specifically configured, using default 3.21ubuntu20")
        
        if not os.path.exists(existing_dockerfile_path):
            print(f"ERROR: Dockerfile not found at {existing_dockerfile_path}")
            dockerfile_dir = "docker"
            available_files = []
            if os.path.exists(dockerfile_dir):
                available_files = [f for f in os.listdir(dockerfile_dir) if f.startswith("dockerfile.libtiff")]
                if available_files:
                    existing_dockerfile_path = os.path.join(dockerfile_dir, available_files[0])
                    print(f"Using alternative Dockerfile: {existing_dockerfile_path}")
                else:
                    raise FileNotFoundError(f"No Dockerfiles found in {dockerfile_dir}")
            else:
                raise FileNotFoundError(f"Dockerfile directory {dockerfile_dir} not found")
        
        shutil.copy2(existing_dockerfile_path, os.path.join(build_dir, "Dockerfile"))
        print(f"Using Dockerfile for version {libtiff_version}: {existing_dockerfile_path}")
        return build_dir
    except Exception:
        # If copying fails, ensure we clean the temp dir before propagating error
        try:
            shutil.rmtree(build_dir, ignore_errors=True)
        except Exception:
            pass
        raise

def build_docker_image(libtiff_version):
    if not libtiff_version or libtiff_version.strip() == "":
        libtiff_version = "4.0.10"
    
    tag = f"libtiff_test:{libtiff_version}"
    
    # Check cache first
    if tag in DOCKER_IMAGE_CACHE:
        print(f"Using cached Docker image: {tag}")
        return DOCKER_IMAGE_CACHE[tag]
    
    # Check if image exists
    p = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip():
        print(f"Docker image {tag} already exists, skipping build.")
        DOCKER_IMAGE_CACHE[tag] = tag
        return tag
    
    build_dir = None
    try:
        build_dir = prepare_docker_build(libtiff_version)
        print(f"Building Docker image {tag}...")
        
        build_cmd = ["docker", "build", "--build-arg", f"libtiff_VERSION={libtiff_version}", "-t", tag, build_dir]
        print(f"Running: {' '.join(build_cmd)}")
        
        proc = subprocess.Popen(
            build_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if line:
                print(line.strip())
        
        ret = proc.poll()
        if ret != 0:
            raise RuntimeError(f"Docker build failed (exit code {ret})")
        
        print("Docker build completed successfully.")
        DOCKER_IMAGE_CACHE[tag] = tag
        return tag
    except Exception as e:
        # attempt to clean up build_dir if created
        try:
            if build_dir and os.path.exists(build_dir):
                shutil.rmtree(build_dir, ignore_errors=True)
        except Exception:
            pass
        return handle_docker_build_failure(libtiff_version, str(e))
    finally:
        # Ensure temp build dir removal in all cases
        try:
            if build_dir and os.path.exists(build_dir):
                shutil.rmtree(build_dir, ignore_errors=True)
        except Exception as e:
            print(f"Warning: failed to remove temp build dir {build_dir}: {e}")

def handle_docker_build_failure(libtiff_version, error_info):
    print(f"Docker build failed for version {libtiff_version}")
    print(f"Error: {error_info}")
    
    fallback_tags = [
        f"libtiff_test:{libtiff_version}",
        "libtiff_test:4.0.10",
        "libtiff_test:4.0.8",
        "libtiff_test:4.0.9",
        "libtiff_test:4.4.0",
         "libtiff_test:4.2.0",
      
    ]
    
    for fallback_tag in fallback_tags:
        p = subprocess.run(["docker", "images", "-q", fallback_tag], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            print(f"Using fallback Docker image: {fallback_tag}")
            DOCKER_IMAGE_CACHE[fallback_tag] = fallback_tag
            return fallback_tag
    
    raise RuntimeError(f"Docker build failed for {libtiff_version} and no fallback images available.")

# ---------------------------
# Run PoC code (with cleanup)
# ---------------------------
def run_poc_code(poc_codes, libtiff_version, function_name, workspace_dir=output_dir ):
    successful_exploit = False
    log_errors = ""

    os.makedirs(workspace_dir, exist_ok=True)
    
    try:
        docker_tag = build_docker_image(libtiff_version)
    except RuntimeError as e:
        log_errors = f"DOCKER SETUP FAILED: {e}\nCannot test PoC codes without Docker environment."
        print(log_errors)
        return False, log_errors

    for index, code in enumerate(poc_codes):
        print(f"Testing PoC #{index + 1}")
        
        poc_filename = f"{function_name}_code_testing_{index}.c"
        poc_filepath = os.path.join(workspace_dir, poc_filename)
        binary_name = f"{function_name}_code_testing_{index}"
        
        #Write PoC code temporarily inside the workspace
        with open(poc_filepath, "w") as f:
            f.write(code)

        compile_attempts = [
            # With libtiff linked and ASan enabled
            f"cd /workspace && gcc -g -fsanitize=address {poc_filename} -ltiff -o {binary_name}",
            
            # With libtiff linked and optimization flags
            f"cd /workspace && gcc -g {poc_filename} -ltiff -o {binary_name} -fsanitize=address",
            
            # Simple compilation with libtiff
            f"cd /workspace && gcc {poc_filename} -ltiff -o {binary_name}",
            
            # Basic compilation with debug symbols and libtiff
         #   f"cd /workspace && gcc -g {poc_filename} -ltiff -o {binary_name}"
        ]
        
        compile_success = False
        compile_output = ""
        
        for attempt_num, compile_cmd in enumerate(compile_attempts):
            print(f"  Compilation attempt {attempt_num + 1}...")
            docker_compile_cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.path.abspath(workspace_dir)}:/workspace",
                docker_tag,
                "bash", "-c", 
                compile_cmd
            ]
            
            try:
                compile_result = subprocess.run(docker_compile_cmd, capture_output=True, text=True, timeout=150)
                if compile_result.returncode == 0:
                    compile_success = True
                    compile_output = compile_result.stdout
                    print(f"  Compilation successful")
                    break
                else:
                    compile_output = f"Attempt {attempt_num + 1} failed:\nSTDOUT: {compile_result.stdout}\nSTDERR: {compile_result.stderr}\n"
            except subprocess.TimeoutExpired:
                compile_output = f"Attempt {attempt_num + 1} timed out"
        
        if not compile_success:
            log_error = f"COMPILATION FAILED for {poc_filename}:\n{compile_output}"
            log_errors += f"#{index + 1}:\n{log_error}\n\n"
            # Cleanup before continuing to next PoC
            cleanup_workspace_except_output(workspace_dir)
            continue

        # Run command for standalone binary creators
        run_cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(workspace_dir)}:/workspace", 
            docker_tag,
            "bash", "-c",
            f"cd /workspace && "
            f"export ASAN_OPTIONS='abort_on_error=1:detect_leaks=0' && "
            f"export UBSAN_OPTIONS='abort_on_error=1' && "
            f"./{binary_name} 2>&1"
        ]
        
        try:
            print(f"Running {binary_name}...")
            run_result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=100)
            
            output = run_result.stderr + run_result.stdout
            return_code = run_result.returncode
            
            crash_keywords = [
                "ERROR: AddressSanitizer",
                "global-buffer-overflow",
                "segmentation fault", 
                "heap-buffer-overflow", 
                "stack-buffer-overflow", 
                "use-after-free", 
                "double-free", 
                "abort",
                "SEGV",
                "core dumped",
                "leaksanitizer",
                "LeakSanitizer",
                "AddressSanitizer:"
            ]
            
            crash_detected = any(keyword.lower() in output.lower() for keyword in crash_keywords)
            
            # Check if program created TIFF files (for standalone binary creators)
            list_files_cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.path.abspath(workspace_dir)}:/workspace", 
                docker_tag,
                "bash", "-c",
                f"cd /workspace && find . -name '*.tiff' -o -name '*.tif' 2>/dev/null"
            ]
            list_result = subprocess.run(list_files_cmd, capture_output=True, text=True, timeout=120)
            tiff_files_created = [f.strip() for f in list_result.stdout.split('\n') if f.strip()]
            
            # Determine success
            if crash_detected:
                successful_exploit = True
                log_error = f"CRASH DETECTED in {poc_filename}:\n{output[:2000]}..."
                print(f"SUCCESS: Crash detected in {poc_filename}")
            elif tiff_files_created:
                # Standalone PoC successfully created TIFF files
                log_error = f"Standalone PoC created TIFF files: {', '.join(tiff_files_created)}"
                print(f"SUCCESS: TIFF files created by {poc_filename}")
                
                # Optional: Test the created TIFF files with libtiff tools
                if tiff_files_created:
                    # Try to test first TIFF file
                    test_cmd = [
                        "docker", "run", "--rm",
                        "-v", f"{os.path.abspath(workspace_dir)}:/workspace", 
                        docker_tag,
                        "bash", "-c",
                        f"cd /workspace && "
                        f"export ASAN_OPTIONS='abort_on_error=1:detect_leaks=0' && "
                        f"tiffinfo {tiff_files_created[0]} 2>&1 || echo 'tiffinfo not available'"
                    ]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=1200)
                    test_output = test_result.stderr + test_result.stdout
                    
                    if any(kw in test_output.lower() for kw in ['error: addressesanitizer', 'segmentation fault', 'abort']):
                        successful_exploit = True
                        log_error += f"\n TIFF file triggers crash when read!"
            else:
                log_error = f"No crash detected in {poc_filename}. Return code: {return_code}\nOutput:\n{output[:1000]}..."

        except subprocess.TimeoutExpired:
            log_error = f"Program timed out for {poc_filename} (may indicate DoS)"
            successful_exploit = True  # Timeout could be a successful DoS
        except Exception as e:
            log_error = f"Error running {poc_filename}: {str(e)}"

        log_errors += f"#{index + 1} ({poc_filename}):\n{log_error}\n\n"

        # Cleanup workspace AFTER each PoC so only output file remains
        try:
            cleanup_workspace_except_output(workspace_dir)
        except Exception as e:
            print(f"Warning during per-PoC cleanup: {e}")

        if successful_exploit:
            break

    return successful_exploit, log_errors

def process_item(i, item, prompt_text, file_path):
    if execution_timeout.is_set():
        return False
        
    function_code = item.get("Function Code", "")
    function_name = item.get("Function Name", f"func_{i}")
    vulnerable_lines = item.get("Vulnerability", "")
    liblouis_version = item.get("Version to Use", "") or "3.2"
    exploit_type = item.get("Exploit Type", "")

    given = f'Function_Code:\n{function_code}\n\n\nVulnerable line(s):\n{vulnerable_lines}\n\nFunction: {function_name}\n\nExploit Type: {exploit_type}\n\nUse liblouis version: {liblouis_version}\n\nGo ahead and begin.'

    success_found = False
    
    
    for j in range(10):
        if execution_timeout.is_set():
            break
            
        conversation_history = prepare_initial_conversation(prompt_text)
        print(f"\nINDEX {i}, THREAD {j+1} | -------------------------------------------------------------------------------------")
        print(prompt_text)

        try:
            initial_response = chat_with_ollama(prompt_text)
            if initial_response:
                print("Initial RAG-enhanced response received")
                conversation_history.append({"role": "assistant", "content": initial_response})
            else:
                print("Initial RAG call failed, skipping this thread")
                continue
        except Exception as e:
            print(f"Error in initial RAG call: {e}")
            continue

        print("\n---------------------------------------------------------------------------------------------------------\n")
        print(given)
        conversation_history.append({"role": "user", "content": given})
       
        
        for k in range(5):
            if execution_timeout.is_set():
                break
                
            conversation_text = "\n".join([msg["content"] for msg in conversation_history])
            response = None
            
            try:
                # Add timeout for AI calls
                response = rag_tool(conversation_text)
            except Exception as e:
                print(f"RAG tool exception: {e}")
                response = None
            
            if not response:
                print("RAG tool returned None or failed, using chat_with_ollama as fallback")
                try:
                    response = chat_with_ollama(conversation_text)
                except Exception as e:
                    print(f"Fallback AI call failed: {e}")
                    response = None
            
            if not response:
                print("All AI services failed in refinement round")
                break  # Break inner loop instead of continue

            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(response)
            conversation_history.append({"role": "assistant", "content": response})

            poc_codes = extract_poc_codes(response)
            if not poc_codes:
                print("\n---------------------------------------------------------------------------------------------------------\n")
                print("No PoC codes found in response.")
                conversation_history.append({"role": "user", "content": "No PoC code was generated. Please provide C code with code blocks marked with ```c and ```"})
                time.sleep(1)
                continue

            print(f"Found {len(poc_codes)} PoC code blocks")

            print("\n---------------------------------------------------------------------------------------------------------\n")
            successful_exploit, log_errors = run_poc_code(poc_codes, liblouis_version, function_name, workspace_dir=output_dir)
            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(f"EXPLOIT RESULT for item {i}, thread {j+1}, round {k+1}: {successful_exploit}")
            print(log_errors)
            
            conversation_history.append({"role": "user", "content": f"Test results: {log_errors}\nPlease refine the PoC to cause a crash."})

            if successful_exploit:
                print(f"SUCCESS!! DONE!! INDEX {i}, THREAD {j+1}, ROUND {k+1}")
                success_found = True
                break  

            time.sleep(1)

        if success_found:
            break  

    if not success_found:
        print(f"\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n")
        print(f"FAILED to find exploit for item {i} after all attempts")
    
    return success_found

from threading import Lock
import concurrent.futures

def main():
    cleanup_workspace_except_output()

    if not check_ollama_available():
        print("WARNING: Ollama is not running or not accessible!")
        print("Please start Ollama with: ollama serve")
        try:
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(5)
            if check_ollama_available():
                print("Ollama started successfully!")
            else:
                print("Failed to start Ollama automatically.")
        except:
            print("Could not start Ollama automatically.")
    
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        models = response.json().get("models", [])
        model_names = [model["name"] for model in models]
        print(f"Available Ollama models: {model_names}")
    except:
        print("Could not check available models.")
    
    try:
        with open(input_data, "r") as file:
            data = json.load(file)["data"]
    except Exception as e:
        print(f"Error loading libtiff_data.json: {e}")
        data = []

    successful_items = 0
    successful_items_lock = Lock()
    
    def process_item_with_counting(index, item, prompt_text, file_path):
        if execution_timeout.is_set():
            return False
        nonlocal successful_items
        print(f"Starting processing for item {index}")
        try:
            # Add per-item timeout (30 minutes)
            result = process_item(index, item, prompt_text, file_path)
            if result:
                with successful_items_lock:
                    successful_items += 1
                print(f"Item {index}: SUCCESS - Total successes so far: {successful_items}")
            else:
                print(f"Item {index}: No exploit found - Total successes so far: {successful_items}")
            return result
        except Exception as e:
            print(f"Item {index}: ERROR - {e}")
            return False
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for index, item in enumerate(data):
            if execution_timeout.is_set():
                break
            future = executor.submit(
                process_item_with_counting, 
                index, item, prompt, 
                os.path.join(output_dir , "code_testing.c")
            )
            futures.append((index, future))
            time.sleep(1)
        
        # Wait for all futures to complete with timeout
        for index, future in futures:
            try:
                future.result(timeout=1800)  # 30 minute timeout per item
            except concurrent.futures.TimeoutError:
                print(f"Item {index}: TIMEOUT after 30 minutes")
                execution_timeout.set()  # Signal timeout to other threads
            except Exception as e:
                print(f"Item {index}: ERROR - {e}")

    print(f"\nCOMPLETED! Successful exploits: {successful_items}/{len(data)}")
    cleanup_workspace_except_output()

if __name__ == "__main__":
    main()
    end = time.perf_counter()
    total_seconds = end - start
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    seconds = int(total_seconds % 60)

print(f"Total runtime: {hours} hours, {minutes} minutes, {seconds} seconds")