import os
import time
import requests
import pandas as pd
import re
import logging
import uuid
from sandbox import run_in_sandbox, extract_crash_type
from extract_feature_libtiff_2 import extract_libtiff_features_from_code



from pathlib import Path

current_script_dir = Path(__file__).resolve().parent

search_root = current_script_dir.parent
input_data= search_root  / "dataset" / "poc.csv"

from datetime import datetime

run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

output_dir = Path("new_outputs") / "libtiff" / "libtiff_variants" / "output"
output_dir.mkdir(parents=True, exist_ok=True)

#output_txt = output_dir / f"output_{run_id}.txt"
output_xlsx = output_dir / f"results_{run_id}.xlsx"

# === Logging Configuration ===
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def save_to_excel(results, filename=None):
    if filename is None:
        filename = output_dir / f"results_{run_id}.xlsx"

    logger.debug(f"Saving results to {filename}")

    try:
        df = pd.DataFrame(results, columns=[
            "Source File",
            "Variant",
            "Attempt",
            "Exploit Successful",
            "Crash Type",
            "Log Snippet",
            "Variant Code"
        ])

        df.to_excel(filename, index=False)
        logger.info(f"Results saved to {filename}")

    except Exception as e:
        logger.exception("Failed to save results to Excel: %s", e)

# === Prompt Builder ===
def build_prompt(poc_code):
    prompt_poc = extract_libtiff_features_from_code(poc_code)
    prompt = prompt_poc.get('prompt_template') if isinstance(prompt_poc, dict) else prompt_poc
    if not prompt:
        logger.warning("Extractor returned no prompt; falling back to minimal prompt.")
        prompt = f"Given this PoC:\n```c\n{poc_code}\n```\nGenerate 3 crash-focused fuzz-only C variants (no main)."
    print("Prompt:\n", prompt)
    return prompt


def chat_with_ollama(poc_code, model="deepseek-r1:70b", url="http://localhost:11434/api/generate"):
    prompt = build_prompt(poc_code)
    headers = {"Content-Type": "application/json"}
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=1200)
    except Exception as e:
        logger.exception("Request to Ollama failed: %s", e)
        return None

    if not response.ok:
        logger.error("Ollama returned error %s: %s", response.status_code, response.text)
        return None

    try:
        j = response.json()
    except Exception:
        return response.text

    for key in ("response", "output", "result", "text"):
        if isinstance(j, dict) and key in j:
            val = j[key]
            if isinstance(val, list):
                try:
                    return " ".join([str(x) for x in val])
                except:
                    return str(val)
            return str(val)
    return str(j)

# === Extract Variants ===
def extract_variants_from_response(response_text):
    if not response_text:
        return []

    # First try to extract code blocks
    code_blocks = re.findall(r'```c\n(.*?)\n```', response_text, flags=re.DOTALL)
    if code_blocks:
        cleaned_blocks = []
        for block in code_blocks:
            # Clean up the block - remove variant headers inside the code block
            lines = block.split('\n')
            # Skip lines that are just variant headers
            filtered_lines = []
            for line in lines:
                if not re.match(r'^\s*//\s*Variant\s*\d+\s*-\s*', line):
                    filtered_lines.append(line)
            cleaned_blocks.append('\n'.join(filtered_lines).strip())
        return cleaned_blocks

    # Fallback: look for variant patterns
    pattern = r'(?:^|\n)(?://|#|\s*)\s*Variant\s*\d+\s*-\s*.*?\n(.*?)(?=(?:\n(?:\s*(?://|#|\s*)\s*Variant\s*\d+)|\Z))'
    blocks = re.findall(pattern, response_text, flags=re.DOTALL | re.IGNORECASE)
    
    if not blocks:
        splits = re.split(r'(?m)^(?:\s*(?://|#|\s*)\s*)?Variant\s*\d+\s*-\s*.*\n', response_text)
        blocks = [s.strip() for s in splits[1:] if s.strip()]
    
    cleaned = []
    for b in blocks:
        lines = b.split('\n')
        filtered_lines = []
        for line in lines:
            # Remove comment markers but keep #include directives
            if line.lstrip().startswith('//') or line.lstrip().startswith('#'):
                if 'include' in line.lower() or 'define' in line.lower():
                    # Keep preprocessor directives
                    filtered_lines.append(line)
                elif 'variant' in line.lower():
                    # Skip variant headers
                    continue
                else:
                    # Remove comment markers from other comment lines
                    filtered_lines.append(re.sub(r'^\s*(//|#)\s*', '', line))
            else:
                filtered_lines.append(line)
        cleaned.append('\n'.join(filtered_lines).strip())
    
    return cleaned

# === Helper to pick CSV columns flexibly ===
def get_csv_columns(df):
    if "Index" in df.columns and "PoC Exploit Code" in df.columns:
        return "Index", "PoC Exploit Code"
    for idx_col in ("Index", "index", "ID", "id"):
        for poc_col in ("PoC Exploit Code", "poc_exploit_code", "Code", "code", "POC"):
            if idx_col in df.columns and poc_col in df.columns:
                return idx_col, poc_col
    if len(df.columns) >= 2:
        return df.columns[0], df.columns[1]
    raise ValueError("CSV does not contain usable columns for index and PoC code.")

# === Main Script ===
# === Main Script ===
def main(csv_path=input_data, output_xlsx=output_xlsx):
    if not os.path.exists(csv_path):
        logger.error("CSV path does not exist: %s", csv_path)
        return

    df = pd.read_csv(csv_path, dtype=str).fillna("")
    try:
        idx_col, poc_col = get_csv_columns(df)
    except Exception as e:
        logger.exception("Unable to find columns in CSV: %s", e)
        return

    all_results = []

    # Updated: Create a proper wrapper for the variant code
    def create_complete_code(variant_code):
        # Check if variant already has a main function
        if "int main" in variant_code or "void main" in variant_code:
            # If it has main, use as-is
            return variant_code
        
        # Otherwise wrap it properly
        wrapper = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <tiffio.h>

int main() {
    %s
    return 0;
}
"""
        # Clean indentation in variant code
        lines = variant_code.strip().split('\n')
        # Remove common leading whitespace
        if lines:
            # Find minimum indentation (excluding empty lines)
            min_indent = float('inf')
            for line in lines:
                if line.strip():  # non-empty line
                    indent = len(line) - len(line.lstrip())
                    min_indent = min(min_indent, indent)
            
            # Remove common indentation
            if min_indent > 0 and min_indent != float('inf'):
                lines = [line[min_indent:] if line.strip() else line for line in lines]
        
        cleaned_code = '\n'.join(lines)
        
        # Insert proper indentation for wrapper
        indented_lines = []
        for line in cleaned_code.split('\n'):
            if line.strip():
                indented_lines.append('    ' + line)
            else:
                indented_lines.append('')
        
        indented_code = '\n'.join(indented_lines)
        return wrapper + "\n\n" + indented_code

    for _, row in df.iterrows():
        idx = row.get(idx_col, "<no-index>")
        poc_code = row.get(poc_col, "")

        logger.info("Processing Index %s", idx)
        if not isinstance(poc_code, str) or not poc_code.strip():
            logger.warning("Skipping Index %s: Invalid or missing PoC code.", idx)
            continue

        response = chat_with_ollama(poc_code)
        if not response:
            logger.warning("Index %s: No response received.", idx)
            continue

        variants = extract_variants_from_response(response)
        if not variants:
            logger.warning("Index %s: No valid variants extracted.", idx)
            continue

        for i, variant_code in enumerate(variants):
            print(f"\n===== Variant {i+1} for Index {idx} =====")
            print(variant_code[:500] + "..." if len(variant_code) > 500 else variant_code)
            print("=" * 50)

            # Create complete code with proper wrapper
            complete_code = create_complete_code(variant_code)
            
            # Debug: Save the complete code to inspect
            with open(f"debug_variant_{idx}_{i+1}.c", "w", encoding="utf-8") as f:
                f.write(complete_code)
            
            # create a unique temp filename
            base_temp = f"temp_variant_exec_{idx}_v{i+1}"
            attempt = 0
            max_attempts = 10
            success = False
            logs = ""
            crash_type = "None"

            while attempt < max_attempts and not success:
                attempt += 1
                temp_file = f"{base_temp}_{uuid.uuid4().hex[:8]}.c"
                logger.info("Attempt %d for Index %s Variant %d", attempt, idx, i + 1)
                
                try:
                    # Write the complete code to file
                    with open(temp_file, "w", encoding="utf-8") as f:
                        f.write(complete_code)

                    # Test with multiple libtiff versions
                    libtiff_versions = ["4.0.10", "4.0.9", "4.0.8", "4.4.0", "4.2.0"]
                    version_results = {}
                    
                    for version in libtiff_versions:
                        try:
                            success_v, logs_v = run_in_sandbox(complete_code, version, temp_file)
                            crash_type_v = extract_crash_type(logs_v)
                            version_results[version] = {
                                "success": success_v,
                                "crash_type": crash_type_v,
                                "logs": logs_v
                            }
                            print(f"Version {version}: {crash_type_v}")
                            
                            # If any version causes a crash, we consider it successful
                            if success_v:
                                success = True
                                logs = logs_v
                                crash_type = crash_type_v
                                break
                        except Exception as e:
                            version_results[version] = {
                                "success": False,
                                "crash_type": "TEST_ERROR",
                                "error": str(e)
                            }
                    
                    # If we didn't find a crash in any version, use the first version's result
                    if not success and version_results:
                        first_version = list(version_results.keys())[0]
                        logs = version_results[first_version].get("logs", "")
                        crash_type = version_results[first_version].get("crash_type", "None")
                        
                except Exception as e:
                    logger.exception("run_in_sandbox failed: %s", e)
                    success = False
                    logs = f"run_in_sandbox exception: {e}"
                    crash_type = "Exception"

                if success:
                    logger.info("Variant %d Crash Type: %s", i + 1, crash_type)
                else:
                    logger.debug("Attempt %d failed for Index %s Variant %d", attempt, idx, i + 1)
                
                # Clean up temp file
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
                
                time.sleep(0.2)
            
            result_entry = [
                f"Index_{idx}",
                f"Variant_{i+1}",
                attempt,
                bool(success),
                crash_type or "None",
                (logs or "")[:300].strip().replace('\n', ' '),
                variant_code
            ]
            all_results.append(result_entry)

    save_to_excel(all_results, filename=output_xlsx)
    logger.info("Finished processing CSV: %s", csv_path)

if __name__ == "__main__":
    main()