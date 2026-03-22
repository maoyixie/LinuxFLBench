#!/usr/bin/env python3
"""
Deep analysis of LinuxFLBench bugs:
1. Verify ground truth files exist in kernel source
2. Call trace analysis: can we map trace functions back to buggy files?
3. Quirk/device_table bug analysis
"""

import json
import os
import re
import subprocess
from collections import Counter, defaultdict

DATASET = "dataset/LINUXFLBENCH_dataset.jsonl"
ANALYSIS_DIR = "analysis"
KERNEL_BASE = "/home1/maoyi/RCA/linux"

def load_bugs():
    bugs = []
    with open(DATASET) as f:
        for line in f:
            bugs.append(json.loads(line.strip()))
    return bugs

def find_kernel_dir(version):
    """Find the kernel source directory for a given version string."""
    # Try exact match first
    candidate = os.path.join(KERNEL_BASE, f"linux-{version}")
    if os.path.isdir(candidate):
        return candidate

    # Try without patch level (e.g., 2.6.30.1 -> 2.6.30)
    parts = version.rsplit(".", 1)
    if len(parts) == 2:
        candidate2 = os.path.join(KERNEL_BASE, f"linux-{parts[0]}")
        if os.path.isdir(candidate2):
            return candidate2

    return None


# ══════════════════════════════════════════════
# Analysis 1: Verify ground truth files exist
# ══════════════════════════════════════════════

def analysis_1_verify_ground_truth(bugs):
    """Check if each bug's buggy file exists in the corresponding kernel version."""
    print("=" * 60)
    print("ANALYSIS 1: Verify ground truth files in kernel source")
    print("=" * 60)

    results = []
    missing_kernel = []
    missing_file = []
    found = []

    for bug in bugs:
        bug_id = bug["id"]
        version = bug.get("Kernel Version", "")
        paths = bug.get("paths", [])

        kernel_dir = find_kernel_dir(version)
        if not kernel_dir:
            missing_kernel.append({"id": bug_id, "version": version})
            results.append({
                "id": bug_id, "version": version,
                "status": "kernel_not_found",
                "paths": paths
            })
            continue

        for path in paths:
            full_path = os.path.join(kernel_dir, path)
            if os.path.isfile(full_path):
                found.append({"id": bug_id, "version": version, "path": path})
                results.append({
                    "id": bug_id, "version": version,
                    "status": "found", "path": path
                })
            else:
                missing_file.append({
                    "id": bug_id, "version": version,
                    "path": path, "kernel_dir": kernel_dir
                })
                results.append({
                    "id": bug_id, "version": version,
                    "status": "file_not_found",
                    "path": path, "kernel_dir": kernel_dir
                })

    print(f"\nResults:")
    print(f"  Found:             {len(found)}/{len(bugs)}")
    print(f"  Kernel not found:  {len(missing_kernel)}")
    print(f"  File not found:    {len(missing_file)}")

    if missing_kernel:
        print(f"\n  Missing kernel versions:")
        for m in missing_kernel:
            print(f"    Bug {m['id']}: version {m['version']}")

    if missing_file:
        print(f"\n  Missing files (kernel exists but file not found):")
        for m in missing_file:
            print(f"    Bug {m['id']}: {m['path']} (kernel: {m['version']})")

    return {
        "total": len(bugs),
        "found": len(found),
        "missing_kernel": missing_kernel,
        "missing_file": missing_file,
        "details": results
    }


# ══════════════════════════════════════════════
# Analysis 2: Call trace function → file mapping
# ══════════════════════════════════════════════

def extract_trace_functions(desc):
    """Extract function names from call trace in description."""
    functions = []

    # Pattern: function_name+0xoffset/0xsize
    funcs1 = re.findall(r'\b(\w+)\+0x[0-9a-f]+/0x[0-9a-f]+', desc)
    functions.extend(funcs1)

    # Pattern: [<hex>] function_name
    funcs2 = re.findall(r'\[<[0-9a-f]+>\]\s*(\w+)', desc)
    functions.extend(funcs2)

    # Pattern: RIP: ... function_name+0x
    funcs3 = re.findall(r'RIP:.*?(\w+)\+0x', desc)
    functions.extend(funcs3)

    # Pattern: EIP: ... function_name+0x
    funcs4 = re.findall(r'EIP:.*?(\w+)\+0x', desc)
    functions.extend(funcs4)

    # Pattern: in function_name (for BUG/WARNING messages)
    funcs5 = re.findall(r'(?:BUG|WARNING).*?in\s+(\w+)', desc)
    functions.extend(funcs5)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for f in functions:
        if f not in seen and not f.startswith("0x"):
            seen.add(f)
            unique.append(f)

    return unique


def grep_function_in_kernel(kernel_dir, func_name):
    """Find which .c files define a given function in the kernel source."""
    try:
        # Search for function definition patterns
        result = subprocess.run(
            ["grep", "-rl", "--include=*.c",
             f"{func_name}(", kernel_dir],
            capture_output=True, text=True, timeout=30
        )
        files = [f.replace(kernel_dir + "/", "") for f in result.stdout.strip().split("\n") if f]

        # Also try a more precise definition match
        result2 = subprocess.run(
            ["grep", "-rn", "--include=*.c",
             f"^[a-zA-Z_].*{func_name}\\s*(",  kernel_dir],
            capture_output=True, text=True, timeout=30
        )
        def_files = set()
        for line in result2.stdout.strip().split("\n"):
            if line and ":" in line:
                fpath = line.split(":")[0].replace(kernel_dir + "/", "")
                def_files.add(fpath)

        return {
            "all_references": files[:20],  # limit
            "likely_definitions": list(def_files)[:10]
        }
    except (subprocess.TimeoutExpired, Exception) as e:
        return {"error": str(e)}


def analysis_2_call_trace(bugs):
    """For bugs with call traces, try to map functions back to source files."""
    print("\n" + "=" * 60)
    print("ANALYSIS 2: Call trace function → file mapping")
    print("=" * 60)

    trace_bugs = []
    for bug in bugs:
        funcs = extract_trace_functions(bug["description"])
        if funcs:
            trace_bugs.append((bug, funcs))

    print(f"\nBugs with extractable trace functions: {len(trace_bugs)}")

    results = []
    hit_count = 0
    partial_hit_count = 0

    for bug, funcs in trace_bugs:
        bug_id = bug["id"]
        version = bug.get("Kernel Version", "")
        ground_truth = bug["paths"][0]
        kernel_dir = find_kernel_dir(version)

        result = {
            "id": bug_id,
            "version": version,
            "ground_truth_file": ground_truth,
            "trace_functions": funcs[:15],  # limit display
            "total_trace_functions": len(funcs),
        }

        if not kernel_dir:
            result["status"] = "kernel_not_found"
            results.append(result)
            continue

        # For each trace function, find where it's defined
        gt_found_via = []
        other_files = set()
        function_locations = {}

        # Only check top 10 functions to keep it fast
        for func in funcs[:10]:
            locations = grep_function_in_kernel(kernel_dir, func)
            defs = locations.get("likely_definitions", [])
            function_locations[func] = defs

            for d in defs:
                if d == ground_truth:
                    gt_found_via.append(func)
                else:
                    other_files.add(d)

        result["function_locations"] = function_locations
        result["gt_found_via_functions"] = gt_found_via
        result["other_candidate_files"] = list(other_files)[:20]

        if gt_found_via:
            result["status"] = "ground_truth_hit"
            hit_count += 1
        elif ground_truth.rsplit("/", 1)[0] in str(other_files):
            result["status"] = "correct_directory_hit"
            partial_hit_count += 1
        else:
            result["status"] = "miss"

        results.append(result)

    print(f"\nResults (out of {len(trace_bugs)} bugs with traces):")
    print(f"  Ground truth file found via trace:  {hit_count} ({hit_count/len(trace_bugs)*100:.1f}%)")
    print(f"  Correct directory found:            {partial_hit_count}")
    print(f"  Miss:                               {len(trace_bugs) - hit_count - partial_hit_count}")

    # Interesting cases: trace points to different file than ground truth
    mismatch_cases = [r for r in results if r.get("status") == "miss" and r.get("function_locations")]
    if mismatch_cases:
        print(f"\n  Interesting 'miss' cases (trace functions not in buggy file):")
        for r in mismatch_cases[:10]:
            print(f"    Bug {r['id']}: GT={r['ground_truth_file']}")
            print(f"      Trace functions: {r['trace_functions'][:5]}")
            top_files = list(r.get("other_candidate_files", []))[:3]
            if top_files:
                print(f"      Trace points to: {top_files}")

    return {
        "total_trace_bugs": len(trace_bugs),
        "ground_truth_hit": hit_count,
        "correct_directory_hit": partial_hit_count,
        "miss": len(trace_bugs) - hit_count - partial_hit_count,
        "details": results
    }


# ══════════════════════════════════════════════
# Analysis 3: Quirk / device_table bugs
# ══════════════════════════════════════════════

def is_quirk_bug(bug):
    """Determine if a bug's fix is a quirk/device table entry addition."""
    patches = bug.get("patch", [])
    full_patch = "\n".join(patches).lower()

    quirk_keywords = [
        "dmi_match", "quirk", "blacklist", "horkage",
        "iwl_dev_info", "pci_device_id", "dmi_system_id",
        "device_id", "usb_device_id", "acpi_dmi_table",
        "video_detect_dmi_table", "ata_device_blacklist",
        "force_native", "force_vendor",
    ]

    # Also check if patch is mainly adding table entries (few logic changes)
    added_lines = re.findall(r'^\+[^+](.*)$', "\n".join(patches), re.MULTILINE)
    table_entry_lines = sum(1 for l in added_lines if any(kw in l.lower() for kw in quirk_keywords))

    is_quirk = any(kw in full_patch for kw in quirk_keywords)

    return is_quirk, table_entry_lines


def analysis_3_quirk_bugs(bugs):
    """Analyze quirk/device_table bugs for common patterns."""
    print("\n" + "=" * 60)
    print("ANALYSIS 3: Quirk / device_table bug analysis")
    print("=" * 60)

    quirk_bugs = []
    for bug in bugs:
        is_quirk, table_lines = is_quirk_bug(bug)
        if is_quirk:
            quirk_bugs.append((bug, table_lines))

    print(f"\nTotal quirk/device_table bugs: {len(quirk_bugs)}")

    results = []
    # Analyze patterns
    symptom_counter = Counter()
    product_counter = Counter()
    component_counter = Counter()
    file_counter = Counter()
    fix_patterns = []

    for bug, table_lines in quirk_bugs:
        bug_id = bug["id"]
        title = bug["title"]
        desc = bug["description"]
        paths = bug["paths"]
        product = bug.get("Product", "")
        component = bug.get("Component", "")

        product_counter[product] += 1
        component_counter[component] += 1

        for p in paths:
            file_counter[p] += 1

        # Classify the symptom
        text = (title + " " + desc).lower()
        if any(kw in text for kw in ["not work", "doesn't work", "does not work", "broken"]):
            symptom_counter["device_not_working"] += 1
        elif any(kw in text for kw in ["missing", "not found", "not detected", "not recognized"]):
            symptom_counter["device_missing"] += 1
        elif any(kw in text for kw in ["brightness", "backlight"]):
            symptom_counter["backlight_issue"] += 1
        elif any(kw in text for kw in ["suspend", "resume", "sleep", "wake"]):
            symptom_counter["suspend_resume"] += 1
        elif any(kw in text for kw in ["error", "spam", "flood"]):
            symptom_counter["error_spam"] += 1
        else:
            symptom_counter["other"] += 1

        # What clues does the description give?
        clues = []
        # Hardware model/vendor mentioned?
        if re.search(r'(?:vendor|model|product|laptop|notebook|desktop).*?[:=]?\s*\w+', desc, re.IGNORECASE):
            clues.append("hardware_model_mentioned")
        # PCI/USB IDs mentioned?
        if re.search(r'(?:0x[0-9a-f]{4}|[0-9a-f]{4}:[0-9a-f]{4})', desc, re.IGNORECASE):
            clues.append("device_ids_in_description")
        # DMI info mentioned?
        if re.search(r'dmi|bios|board_name|product_name|sys_vendor', desc, re.IGNORECASE):
            clues.append("dmi_info_in_description")
        # lspci/lsusb output?
        if any(kw in desc.lower() for kw in ["lspci", "lsusb"]):
            clues.append("lspci_lsusb_output")
        # Specific driver name mentioned?
        driver_mentions = re.findall(r'\b(\w+)\.ko\b|\bmodule\s+(\w+)\b', desc, re.IGNORECASE)
        if driver_mentions:
            clues.append("driver_name_mentioned")

        # Analyze what the patch actually does
        patch_text = "\n".join(bug.get("patch", []))
        fix_type = "unknown"
        if "dmi_match" in patch_text.lower() or "dmi_system_id" in patch_text.lower():
            fix_type = "dmi_quirk_addition"
        elif "iwl_dev_info" in patch_text.lower():
            fix_type = "wifi_device_id_addition"
        elif "horkage" in patch_text.lower() or "blacklist" in patch_text.lower():
            fix_type = "device_blacklist_addition"
        elif "pci_device_id" in patch_text.lower() or "usb_device_id" in patch_text.lower():
            fix_type = "pci_usb_id_addition"
        elif "quirk" in patch_text.lower():
            fix_type = "quirk_function_addition"

        result = {
            "id": bug_id,
            "title": title,
            "product": product,
            "component": component,
            "buggy_file": paths,
            "fix_type": fix_type,
            "table_entry_lines_added": table_lines,
            "description_clues": clues,
            "patch_size": len(re.findall(r'^\+[^+]', patch_text, re.MULTILINE)) +
                         len(re.findall(r'^-[^-]', patch_text, re.MULTILINE)),
        }

        # Can we derive the buggy file from the description?
        potential_strategies = []
        if "device_ids_in_description" in clues:
            potential_strategies.append("grep_device_id_in_kernel_source")
        if "dmi_info_in_description" in clues:
            potential_strategies.append("search_dmi_tables_in_drivers")
        if "lspci_lsusb_output" in clues:
            potential_strategies.append("map_pci_usb_id_to_driver")
        if "hardware_model_mentioned" in clues:
            potential_strategies.append("search_for_model_specific_quirks")
        if component and component not in ["Other"]:
            potential_strategies.append(f"narrow_by_component:{component}")

        result["potential_strategies"] = potential_strategies
        results.append(result)

    print(f"\n  Symptom distribution:")
    for s, c in symptom_counter.most_common():
        print(f"    {s}: {c}")

    print(f"\n  Fix type distribution:")
    fix_type_counter = Counter(r["fix_type"] for r in results)
    for ft, c in fix_type_counter.most_common():
        print(f"    {ft}: {c}")

    print(f"\n  Product distribution:")
    for p, c in product_counter.most_common():
        print(f"    {p}: {c}")

    print(f"\n  Most common buggy files:")
    for f, c in file_counter.most_common(10):
        print(f"    {f}: {c}")

    print(f"\n  Available clues in description:")
    clue_counter = Counter()
    for r in results:
        for c in r["description_clues"]:
            clue_counter[c] += 1
    for cl, c in clue_counter.most_common():
        print(f"    {cl}: {c}/{len(results)}")

    print(f"\n  Potential localization strategies:")
    strat_counter = Counter()
    for r in results:
        for s in r["potential_strategies"]:
            strat_counter[s] += 1
    for s, c in strat_counter.most_common():
        print(f"    {s}: {c}/{len(results)}")

    return {
        "total_quirk_bugs": len(quirk_bugs),
        "symptom_distribution": dict(symptom_counter.most_common()),
        "fix_type_distribution": dict(fix_type_counter.most_common()),
        "product_distribution": dict(product_counter.most_common()),
        "common_buggy_files": dict(file_counter.most_common(10)),
        "details": results
    }


# ══════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════

def main():
    bugs = load_bugs()
    print(f"Loaded {len(bugs)} bugs\n")

    # Analysis 1
    result1 = analysis_1_verify_ground_truth(bugs)
    with open(os.path.join(ANALYSIS_DIR, "_verification.json"), "w") as f:
        json.dump(result1, f, indent=2, ensure_ascii=False)

    # Analysis 2
    result2 = analysis_2_call_trace(bugs)
    with open(os.path.join(ANALYSIS_DIR, "_call_trace_analysis.json"), "w") as f:
        json.dump(result2, f, indent=2, ensure_ascii=False)

    # Analysis 3
    result3 = analysis_3_quirk_bugs(bugs)
    with open(os.path.join(ANALYSIS_DIR, "_quirk_analysis.json"), "w") as f:
        json.dump(result3, f, indent=2, ensure_ascii=False)

    # Update each bug's individual analysis file with deep analysis results
    # Map results by bug id
    trace_map = {r["id"]: r for r in result2["details"]}
    quirk_map = {r["id"]: r for r in result3["details"]}
    verify_map = defaultdict(list)
    for r in result1["details"]:
        verify_map[r["id"]].append(r)

    for bug in bugs:
        bug_id = bug["id"]
        analysis_path = os.path.join(ANALYSIS_DIR, f"{bug_id}.json")
        if os.path.exists(analysis_path):
            with open(analysis_path) as f:
                analysis = json.load(f)
        else:
            analysis = {"id": bug_id}

        # Add verification result
        if bug_id in verify_map:
            analysis["source_verification"] = verify_map[bug_id]

        # Add call trace analysis
        if bug_id in trace_map:
            analysis["call_trace_analysis"] = trace_map[bug_id]

        # Add quirk analysis
        if bug_id in quirk_map:
            analysis["quirk_analysis"] = quirk_map[bug_id]

        with open(analysis_path, "w") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)

    print("\n\nAll analysis results saved to analysis/ directory.")
    print("  - _verification.json: Ground truth verification")
    print("  - _call_trace_analysis.json: Call trace analysis")
    print("  - _quirk_analysis.json: Quirk/device_table analysis")
    print("  - Each bug's individual file updated with deep analysis")


if __name__ == "__main__":
    main()
