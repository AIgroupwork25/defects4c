"""
test_ablation.py — smoke test for the ablation pipeline.
Picks one random CVE test case, runs it through VA (loc + classification only),
augments the prompt, sends to LLM, and saves results to a txt file.
Hardcoded values are intentional — this is a dev/debug script.
"""

import json
import os
import random
import re
import requests
import time
from datetime import datetime
from pathlib import Path
from openai import OpenAI

# ── Hardcoded config ──────────────────────────────────────────────────────────
DEFECTS4C_BASE_URL = "http://127.0.0.1:11111"
OLLAMA_HOST        = "http://100.97.159.90:11434"
VA_HOST           = "http://100.78.242.59:8000"
MODEL              = "deepseek-coder:6.7b"
TEMPERATURE        = 0.01
SEED               = 42
AUGMENT            = "all"   # localisation + classification + retrieval

CVE_DATA_DIR   = Path("../defectsc_tpl/data/buggy_errmsg_cve")
CVE_DATA_FILES = [
    "single_function_repair.json",
    "single_function_single_hunk_repair.json",
    "single_function_single_line_repair.json",
]

BASE_SYSTEM_PROMPT = "You are a C/CPP code program repair expert"
INFILL_SPLIT = ">>> [ INFILL ] <<<"
OUT_FILE = f"test_ablation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_cve_data() -> tuple:
    """Returns (shas set, sha -> list of (key, entry) dict)."""
    shas = set()
    cve_entries = {}
    for fname in CVE_DATA_FILES:
        data = json.load(open(CVE_DATA_DIR / fname))
        for key, entry in data.items():
            sha = key.split("___")[0]
            shas.add(sha)
            cve_entries.setdefault(sha, []).append((key, entry))
    return shas, cve_entries


def get_vulnerable_code(sha: str, cve_entries: dict, src_files: list) -> str:
    """Return the actual vulnerable function body from CVE data, matched by source file."""
    entries = cve_entries.get(sha, [])
    if not entries:
        return None
    if src_files:
        src_basenames = [os.path.basename(f) for f in src_files]
        matched = [(k, v) for k, v in entries if any(b in k for b in src_basenames)]
        if matched:
            return matched[0][1].get("buggy")
    return entries[0][1].get("buggy")


def patch_user_message(user_content: str, vulnerable_code: str) -> str:
    """Replace the INFILL code block with the actual vulnerable code,
    substitute any occurrence of 'buggy' with 'vulnerable', and update
    the task description to match the repair (not infill) format."""
    patched = re.sub(
        r"```(?:cpp|c)?\n.*?" + re.escape(INFILL_SPLIT) + r".*?```",
        f"```c\n{vulnerable_code}\n```",
        user_content,
        flags=re.DOTALL,
    )
    patched = re.sub(r"\bbuggy\b", "vulnerable", patched, flags=re.IGNORECASE)
    for _variant in [
        "The following code contains a vulnerable line that has been removed.",
        "The following code contains a vulnerable hunk that has been removed.",
        "The following code contains a vulnerable function that has been removed.",
    ]:
        patched = patched.replace(_variant, "The following code contains a vulnerable function. Fix the vulnerability.")
    return patched


def extract_code(llm_response: str) -> str:
    match = re.search(r"```(?:cpp|c)?\n(.*?)\n```", llm_response, re.DOTALL)
    if match:
        return match.group(1).strip()
    return llm_response.strip()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    client = OpenAI(api_key="ollama", base_url=f"{OLLAMA_HOST}/v1/")

    # Pick a random CVE test case
    cve_shas, cve_entries = load_cve_data()
    all_ids  = requests.get(f"{DEFECTS4C_BASE_URL}/list_defects_bugid").json()["defects"]
    cve_ids  = [b for b in all_ids if b.split("@")[-1] in cve_shas]
    bug_id   = random.choice(cve_ids)
    sha      = bug_id.split("@")[-1]

    print(f"Selected bug: {bug_id}")

    # Step 1: Fetch defect
    defect_data = requests.get(f"{DEFECTS4C_BASE_URL}/get_defect/{bug_id}").json()
    assert defect_data.get("status") == "success", f"get_defect failed: {defect_data}"
    base_prompts = defect_data["prompt_data"]["prompt"]

    # Step 1b: Look up actual vulnerable code and patch the prompt
    src_files = (defect_data.get("additional_info", {})
                             .get("metadata", {})
                             .get("files", {})
                             .get("src", []))
    vulnerable_code = get_vulnerable_code(sha, cve_entries, src_files)

    if vulnerable_code is not None:
        base_prompts = [
            {**m, "content": patch_user_message(m["content"], vulnerable_code)}
            if m["role"] == "user" else m
            for m in base_prompts
        ]

    # Step 2: Call VA with the actual vulnerable code
    code_for_va = vulnerable_code
    if code_for_va is None:
        user_content = next(m["content"] for m in base_prompts if m["role"] == "user")
        code_match   = re.search(r"```(?:cpp|c)?\n(.*?)\n```", user_content, re.DOTALL)
        code_for_va = code_match.group(1) if code_match else user_content

    print("Calling VA API...")
    va_resp       = requests.post(f"{VA_HOST}/inference/",
                                   headers={"Content-Type": "application/json"},
                                   json={"code": code_for_va}, timeout=120)
    va_data       = va_resp.json()
    localisation   = va_data.get("localisation", "")
    classification = va_data.get("classification", "")
    retrieval      = va_data.get("retrieval", "")
    print(f"  localisation  : {localisation}")
    print(f"  classification: {classification}")
    print(f"  retrieval     : {str(retrieval)[:100]}")

    # Step 3: Build augmented messages
    system_msg = "\n".join(filter(None, [
        BASE_SYSTEM_PROMPT,
        f"Fault localisation: {localisation}" if localisation else "",
        f"Bug classification: {classification}" if classification else "",
    ]))
    user_msg = next(m["content"] for m in base_prompts if m["role"] == "user")
    if retrieval:
        user_msg = user_msg + f"\n\nSimilar examples:\n{retrieval}"

    messages = [{"role": "system", "content": system_msg}]
    for m in base_prompts:
        if m["role"] == "system":
            continue
        elif m["role"] == "user":
            messages.append({"role": "user", "content": user_msg})
        else:
            messages.append(m)

    # Step 4: Call LLM
    print(f"Calling LLM ({MODEL})...")
    ai_response  = client.chat.completions.create(
        model=MODEL, messages=messages,
        temperature=TEMPERATURE, max_tokens=4096, seed=SEED,
    )
    llm_response    = ai_response.choices[0].message.content
    extracted_patch = extract_code(llm_response)
    print(f"  LLM response: {llm_response[:80].strip()}...")

    # Step 5: Build patch
    patch_data = requests.post(
        f"{DEFECTS4C_BASE_URL}/build_patch",
        headers={"Content-Type": "application/json"},
        json={"bug_id": bug_id, "llm_response": llm_response,
              "method": "direct", "generate_diff": True, "persist_flag": True},
    ).json()

    compile_result = patch_data.get("success", False)
    patch_path     = patch_data.get("fix_p", "")
    print(f"  Compile: {compile_result}")

    # Step 6: Submit fix and poll
    fix_result = False
    return_code = None
    if compile_result:
        fix_data = requests.post(
            f"{DEFECTS4C_BASE_URL}/fix",
            headers={"Content-Type": "application/json"},
            json={"bug_id": bug_id, "patch_path": patch_path},
        ).json()

        if "handle" in fix_data:
            handle = fix_data["handle"]
            start  = time.time()
            while time.time() - start < 300:
                status_data = requests.get(f"{DEFECTS4C_BASE_URL}/status/{handle}").json()
                if status_data.get("status") in ("completed", "failed"):
                    return_code = status_data.get("return_code", -1)
                    fix_result  = (return_code == 0)
                    break
                time.sleep(10)

    print(f"  Fixed  : {fix_result}")

    # ── Write output file ─────────────────────────────────────────────────────
    lines = [
        "TEST ABLATION RUN",
        "=" * 60,
        f"Timestamp         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Model             : {MODEL}",
        f"Ablation          : {AUGMENT} (localisation + classification + retrieval)",
        f"Temperature       : {TEMPERATURE}",
        f"Seed              : {SEED}",
        f"Base system prompt: {BASE_SYSTEM_PROMPT}",
        "=" * 60,
        "",
        f"Bug ID : {bug_id}",
        f"SHA    : {sha}",
        "",
        "VA outputs:",
        f"  localisation  : {localisation}",
        f"  classification: {classification}",
        f"  retrieval     : {str(retrieval)[:300]}{'...' if len(str(retrieval)) > 300 else ''}",
        "",
        "Prompt sent to LLM:",
        f"  [system] {system_msg}",
        f"  [user]   {user_msg[:300]}{'...' if len(user_msg) > 300 else ''}",
        "",
        "Extracted patch:",
        extracted_patch if extracted_patch else "(none)",
        "",
        f"Compile : {compile_result}",
        f"Fixed   : {fix_result}",
        "",
        "=" * 60,
        "RESULT",
        "=" * 60,
        f"Compile Rate : {'1 / 1 (100.0%)' if compile_result else '0 / 1 (0.0%)'}",
        f"Pass@1       : {'1 / 1 (100.0%)' if fix_result else '0 / 1 (0.0%)'}",
    ]

    with open(OUT_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\nSaved to {OUT_FILE}")


if __name__ == "__main__":
    main()
