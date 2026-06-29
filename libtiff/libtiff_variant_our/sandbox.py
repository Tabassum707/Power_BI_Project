import os
import signal
import subprocess
import time
import re

# Get the absolute path to the directory containing this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


libtiff_VERSION_ENV = {
    "4.0.10": "test4.0.10",
    "4.0.9": "test4.0.9", 
    "4.0.8": "test4.0.8",
    "4.4.0": "test4.4.0",
    "4.2.0": "test4.2.0"

}

def run_in_sandbox(poc_code, libtiff_version, file_path):
    """
    Execute PoC code in a Docker sandbox with the specified libtiff version.
    Returns a tuple: (success: bool, log: str)
    """
    # Strip ```c and ``` markers from the PoC code
  #  poc_code_cleaned = re.sub(r'^```c\n|```$', '', poc_code, flags=re.MULTILINE).strip()

    # Write cleaned PoC code to temporary file
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(poc_code)

    # Get Docker image for the specified libtiff version
    if libtiff_version not in libtiff_VERSION_ENV:
        # Fix: Use libtiff in error message
        return False, f"Error: Unsupported libtiff version '{libtiff_version}'. Supported versions: {list(libtiff_VERSION_ENV.keys())}"
    
    docker_image = libtiff_VERSION_ENV[libtiff_version]
    
    # Extract file details for compilation
    workspace_dir = os.path.dirname(os.path.abspath(file_path))
    poc_filename = os.path.basename(file_path)
    binary_name = os.path.splitext(poc_filename)[0]  # Remove extension for binary name
    
    # FIXED: Proper compilation command (single command, not a list)
    compile_cmd = f"cd /workspace && gcc -g -fsanitize=address {poc_filename} -ltiff -o {binary_name}"
    
    # Alternative compilation commands for fallback (if needed)
    compile_alternatives = [
        compile_cmd,
        f"cd /workspace && gcc -g -fsanitize=address -fno-omit-frame-pointer {poc_filename} -ltiff -o {binary_name}",
   
        f"cd /workspace && gcc -g {poc_filename} -ltiff -o {binary_name}",
        f"cd /workspace && gcc {poc_filename} -ltiff -o {binary_name}"
    ]

    # Execution command with fuzzer parameters
    run_cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.path.abspath(workspace_dir)}:/workspace", 
        docker_image,
        "bash", "-c",
        f"cd /workspace && "
        f"export ASAN_OPTIONS='abort_on_error=1:detect_leaks=0' && "
        f"export UBSAN_OPTIONS='abort_on_error=1' && "
        f"./{binary_name} 2>&1"
    ]

    try:
        # Step 1: Try multiple compilation approaches
        print(f"Compiling {poc_filename}...")
        compile_success = False
        compile_error = ""
        
        for compile_cmd_try in compile_alternatives:
            compile_cmd_list = ["docker", "run", "--rm",
                              "-v", f"{os.path.abspath(workspace_dir)}:/workspace",
                              docker_image,
                              "bash", "-c", compile_cmd_try]
            
            compile_result = subprocess.run(
                compile_cmd_list, 
                capture_output=True, 
                text=True, 
                timeout=120
            )
            
            if compile_result.returncode == 0:
                compile_success = True
                break
            else:
                compile_error = f"Compilation attempt failed:\nCommand: {compile_cmd_try}\nSTDERR: {compile_result.stderr}\nSTDOUT: {compile_result.stdout}\n"
        
        if not compile_success:
            return False, f"COMPILATION FAILED for {poc_filename}:\n{compile_error}"

        # Step 2: Run the compiled binary
        print(f"Running {binary_name}...")
        run_result = subprocess.run(
            run_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Combine stdout and stderr for analysis
        output = run_result.stdout + run_result.stderr
        returncode = run_result.returncode

    except subprocess.TimeoutExpired:
        output = "TimeoutExpired:  timed out after 60 seconds"
        returncode = -1
    except Exception as e:
        output = f"Execution error: {str(e)}"
        returncode = -1

    # Check for crash-related keywords
    crash_keywords = [
        "addresssanitizer", "heap-buffer-overflow", "stack-buffer-overflow",
        "global-buffer-overflow", "use-after-free", "double-free", "null pointer",
        "segmentation fault", "sigsegv", "sigabrt", "abort", "core dumped",
        "assertion failed", "buffer overflow", "memory corruption",
        "invalid read", "invalid write", "leaksanitizer"
    ]
    
    # Additional check for fuzzer crash artifacts
    has_crash_artifact = f"Test unit written to" in output or f"{binary_name}_crash-" in output
    crash_detected = any(keyword.lower() in output.lower() for keyword in crash_keywords)
    
    # Success if we detected either crash keywords or fuzzer found a crash
    success = crash_detected or has_crash_artifact or returncode != 0

    # Clean up compiled binary
    try:
        binary_path = os.path.join(workspace_dir, binary_name)
        if os.path.exists(binary_path):
            os.remove(binary_path)
    except Exception as e:
        print(f"Warning: Could not clean up binary {binary_name}: {e}")

    return success, output

def extract_crash_type(log_text):
    """
    Extract the type of crash or exploit-related error from libtiff logs.
    Returns a descriptive string.
    """
    
    log_text = log_text.lower()

    # AddressSanitizer-related errors (prefer specific ASAN signals)
    if "addresssanitizer" in log_text or "asan:" in log_text:
        if "heap-buffer-overflow" in log_text:
            return "Heap Buffer Overflow"
        if "stack-buffer-overflow" in log_text:
            return "Stack Buffer Overflow"
        if "global-buffer-overflow" in log_text:
            return "Global Buffer Overflow"
        if "use-after-free" in log_text or "heap-use-after-free" in log_text:
            return "Use After Free"
        if "double-free" in log_text:
            return "Double Free"
        if "dynamic-stack-buffer-overflow" in log_text:
            return "Dynamic Stack Buffer Overflow"
        if "null" in log_text and "pointer" in log_text:
            return "Null Pointer Dereference"
        if "invalid read" in log_text or re.search(r'invalid read of size \d+', log_text):
            return "Invalid Read"
        if "invalid write" in log_text or re.search(r'invalid write of size \d+', log_text):
            return "Invalid Write"
        if "memory leak" in log_text or "leak" in log_text:
            return "Memory Leak"
        if "integer overflow" in log_text:
            return "Integer Overflow"
        return "AddressSanitizer Error"

    # Core crash patterns (no sanitizer)
    if "segmentation fault" in log_text or "sigsegv" in log_text:
        return "Segmentation Fault"
    if "assertion failed" in log_text or "abort" in log_text or "sigabrt" in log_text:
        return "Assertion Failed / Abort"
    if "stack smashing detected" in log_text:
        return "Stack Buffer Overflow"
    if "malloc(): corrupted" in log_text or "corrupted" in log_text:
        return "Heap Corruption"
    
    if "free(): invalid pointer" in log_text or "double free" in log_text:
        return "Invalid Free / Double Free"
    if "out of memory" in log_text or "bad_alloc" in log_text:
        return "Out of Memory"
    if "timeout" in log_text or "timeoutexpired" in log_text:
        return "Timeout / Hang"
    if "undefined-behavior" in log_text or "ubsan" in log_text:
        return "Undefined Behavior"
    if "threadsanitizer" in log_text or "tsan:" in log_text:
        return "Thread Race Condition"

    # Global invalid read/write checks
    if "invalid read" in log_text or re.search(r'invalid read of size \d+', log_text):
        return "Invalid Read"
    if "invalid write" in log_text or re.search(r'invalid write of size \d+', log_text):
        return "Invalid Write"

    return "None"