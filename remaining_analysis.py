#!/usr/bin/env python3
"""
Analyze:
1. 17 call-trace-miss bugs: WHY does the trace mislead?
2. 169 remaining bugs (no trace, no quirk): what patterns exist and how to approach them?
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
    bugs = {}
    with open(DATASET) as f:
        for line in f:
            b = json.loads(line.strip())
            bugs[b["id"]] = b
    return bugs


def find_kernel_dir(version):
    candidate = os.path.join(KERNEL_BASE, f"linux-{version}")
    if os.path.isdir(candidate):
        return candidate
    parts = version.rsplit(".", 1)
    if len(parts) == 2:
        candidate2 = os.path.join(KERNEL_BASE, f"linux-{parts[0]}")
        if os.path.isdir(candidate2):
            return candidate2
    return None


def grep_in_kernel(kernel_dir, pattern, file_glob="*.c", max_results=20):
    """grep a pattern in kernel source, return list of matching files."""
    try:
        result = subprocess.run(
            ["grep", "-rl", "--include=" + file_glob, pattern, kernel_dir],
            capture_output=True, text=True, timeout=30
        )
        files = [f.replace(kernel_dir + "/", "")
                 for f in result.stdout.strip().split("\n") if f]
        return files[:max_results]
    except Exception:
        return []


def extract_trace_functions(desc):
    functions = []
    funcs1 = re.findall(r'\b(\w+)\+0x[0-9a-f]+/0x[0-9a-f]+', desc)
    functions.extend(funcs1)
    funcs2 = re.findall(r'\[<[0-9a-f]+>\]\s*(\w+)', desc)
    functions.extend(funcs2)
    funcs3 = re.findall(r'RIP:.*?(\w+)\+0x', desc)
    functions.extend(funcs3)
    funcs4 = re.findall(r'EIP:.*?(\w+)\+0x', desc)
    functions.extend(funcs4)
    seen = set()
    unique = []
    for f in functions:
        if f not in seen and not f.startswith("0x"):
            seen.add(f)
            unique.append(f)
    return unique


# ══════════════════════════════════════════════
# Part 1: Trace-miss bugs deep dive
# ══════════════════════════════════════════════

def analyze_trace_miss_bugs(bugs, trace_miss_ids):
    """Deep dive into why call trace doesn't point to the buggy file."""
    print("=" * 70)
    print("PART 1: Why call trace misleads (17 trace-miss bugs)")
    print("=" * 70)

    results = []

    for bug_id in sorted(trace_miss_ids):
        bug = bugs[bug_id]
        desc = bug["description"]
        gt_file = bug["paths"][0]
        gt_methods = bug["methods"]
        version = bug.get("Kernel Version", "")
        kernel_dir = find_kernel_dir(version)

        trace_funcs = extract_trace_functions(desc)

        # Classify the mismatch pattern
        gt_dir = "/".join(gt_file.split("/")[:-1])
        gt_subsystem = "/".join(gt_file.split("/")[:2])

        # Check where trace functions are defined
        trace_file_map = {}
        trace_subsystems = set()
        if kernel_dir:
            for func in trace_funcs[:8]:
                result = subprocess.run(
                    ["grep", "-rn", "--include=*.c",
                     f"^[a-zA-Z_].*\\b{func}\\s*(", kernel_dir],
                    capture_output=True, text=True, timeout=15
                )
                def_files = set()
                for line in result.stdout.strip().split("\n"):
                    if line and ":" in line:
                        fpath = line.split(":")[0].replace(kernel_dir + "/", "")
                        def_files.add(fpath)
                trace_file_map[func] = list(def_files)[:5]
                for df in def_files:
                    trace_subsystems.add("/".join(df.split("/")[:2]))

        # Determine the mismatch type
        mismatch_type = "unknown"

        # Type A: Trace is in infrastructure code (scheduler, IRQ, timer, memory)
        infra_keywords = ["kernel/", "lib/", "mm/", "arch/"]
        trace_in_infra = any(
            any(tf.startswith(kw) for kw in infra_keywords)
            for func_files in trace_file_map.values()
            for tf in func_files
        )

        # Type B: Trace is in the same subsystem but different file
        trace_in_same_subsystem = gt_subsystem in trace_subsystems

        # Type C: Trace is in a different subsystem entirely (error propagation)
        trace_in_different_subsystem = not trace_in_same_subsystem and len(trace_subsystems) > 0

        if trace_in_infra and trace_in_different_subsystem:
            mismatch_type = "trace_in_infrastructure"
        elif trace_in_same_subsystem and not trace_in_infra:
            mismatch_type = "same_subsystem_different_file"
        elif trace_in_different_subsystem:
            mismatch_type = "cross_subsystem_propagation"
        elif trace_in_infra:
            mismatch_type = "trace_in_infrastructure"

        # Check if ANY trace function is actually called from the GT file
        gt_calls_trace_func = False
        if kernel_dir and os.path.isfile(os.path.join(kernel_dir, gt_file)):
            try:
                with open(os.path.join(kernel_dir, gt_file), 'r', errors='ignore') as f:
                    gt_content = f.read()
                for func in trace_funcs[:10]:
                    if func in gt_content:
                        gt_calls_trace_func = True
                        break
            except:
                pass

        # Check if GT methods appear in trace
        gt_method_in_trace = any(m in trace_funcs for m in gt_methods)

        result = {
            "id": bug_id,
            "title": bug["title"],
            "ground_truth_file": gt_file,
            "ground_truth_methods": gt_methods,
            "ground_truth_subsystem": gt_subsystem,
            "trace_functions_top8": trace_funcs[:8],
            "trace_function_locations": trace_file_map,
            "trace_subsystems": list(trace_subsystems),
            "mismatch_type": mismatch_type,
            "gt_calls_trace_func": gt_calls_trace_func,
            "gt_method_in_trace": gt_method_in_trace,
            "product": bug.get("Product", ""),
            "component": bug.get("Component", ""),
        }

        results.append(result)

        print(f"\n  Bug {bug_id}: {bug['title'][:60]}")
        print(f"    GT: {gt_file} -> {gt_methods}")
        print(f"    Trace funcs: {trace_funcs[:5]}")
        print(f"    Trace subsystems: {list(trace_subsystems)[:5]}")
        print(f"    Mismatch type: {mismatch_type}")
        print(f"    GT file references trace func: {gt_calls_trace_func}")
        print(f"    GT method in trace: {gt_method_in_trace}")

    # Summarize mismatch types
    type_counter = Counter(r["mismatch_type"] for r in results)
    print(f"\n  Mismatch type summary:")
    for t, c in type_counter.most_common():
        print(f"    {t}: {c}")

    gt_refs_trace = sum(1 for r in results if r["gt_calls_trace_func"])
    gt_in_trace = sum(1 for r in results if r["gt_method_in_trace"])
    print(f"\n  GT file references a trace function: {gt_refs_trace}/{len(results)}")
    print(f"  GT method appears in trace: {gt_in_trace}/{len(results)}")

    return {"details": results, "mismatch_types": dict(type_counter)}


# ══════════════════════════════════════════════
# Part 2: Remaining 169 bugs (no trace, no quirk)
# ══════════════════════════════════════════════

def classify_remaining_bug(bug):
    """Classify a non-trace, non-quirk bug by its characteristics."""
    title = bug["title"]
    desc = bug["description"]
    text = (title + " " + desc).lower()
    patches = bug.get("patch", [])
    full_patch = "\n".join(patches)

    categories = []

    # ── Symptom-based classification ──

    # Hang / deadlock
    if any(kw in text for kw in ["hang", "hung", "freeze", "deadlock",
                                  "lockup", "lock up", "unresponsive",
                                  "soft lockup", "rcu stall"]):
        categories.append("hang/deadlock")

    # Sleep / suspend / resume failure
    if any(kw in text for kw in ["suspend", "resume", "s3", "s4",
                                  "hibernate", "sleep fail", "wake"]):
        categories.append("suspend/resume")

    # Wrong output / functional error
    if any(kw in text for kw in ["wrong", "incorrect", "invalid", "broken",
                                  "unexpected value", "should be",
                                  "not display", "not report",
                                  "miscalculated", "bad value"]):
        categories.append("wrong_output")

    # Resource leak / memory issue
    if any(kw in text for kw in ["leak", "oom", "out of memory",
                                  "memory corruption", "use after free",
                                  "double free"]):
        categories.append("resource_leak")

    # Performance / slowness
    if any(kw in text for kw in ["slow", "performance", "latency",
                                  "throughput"]):
        categories.append("performance")

    # Boot failure
    if any(kw in text for kw in ["boot fail", "doesn't boot",
                                  "won't boot", "boot stop",
                                  "kernel panic on boot"]):
        categories.append("boot_failure")

    # Data corruption
    if any(kw in text for kw in ["corrupt", "data loss", "filesystem damage"]):
        categories.append("data_corruption")

    if not categories:
        categories.append("other_functional")

    # ── Fix-based classification ──

    fix_types = []

    # Null pointer / missing check
    if re.search(r'^\+.*\bif\s*\(.*(?:NULL|!|== 0)', full_patch, re.MULTILINE):
        fix_types.append("null_check_added")

    # Lock fix
    if any(kw in full_patch for kw in ["mutex_lock", "spin_lock", "spin_unlock",
                                        "mutex_unlock", "lock_kernel", "rcu_read"]):
        fix_types.append("locking_fix")

    # Return value / error path fix
    if re.search(r'^\+.*return\s+-E', full_patch, re.MULTILINE):
        fix_types.append("error_return_fix")

    # Initialization fix
    if re.search(r'^\+.*=\s*(?:0|NULL|false|true|\{\s*\})\s*;', full_patch, re.MULTILINE):
        fix_types.append("init_fix")

    # Type / cast fix
    if re.search(r'^\+.*\(\s*(?:u8|u16|u32|u64|int|long|unsigned)\s*\)', full_patch, re.MULTILINE):
        fix_types.append("type_cast_fix")

    # Boundary / off-by-one
    if re.search(r'^\+.*(?:<=|>=|< |> ).*(?:len|size|count|max|min|limit)', full_patch, re.MULTILINE):
        fix_types.append("boundary_fix")

    # Function call change (different function / different args)
    added_calls = re.findall(r'^\+.*\b(\w+)\s*\(', full_patch, re.MULTILINE)
    removed_calls = re.findall(r'^-.*\b(\w+)\s*\(', full_patch, re.MULTILINE)
    new_calls = set(added_calls) - set(removed_calls)
    if new_calls:
        fix_types.append("new_function_calls")

    if not fix_types:
        fix_types.append("other_fix")

    # ── What localization clues exist? ──

    clues = []
    clue_details = {}

    # Error messages that can be grepped
    error_strings = re.findall(r'"([^"]{15,80})"', desc)
    kernel_error_strings = [s for s in error_strings if any(
        kw in s.lower() for kw in ["error", "fail", "warn", "unable", "cannot", "invalid"]
    )]
    if kernel_error_strings:
        clues.append("greppable_error_strings")
        clue_details["error_strings"] = kernel_error_strings[:5]

    # /proc or /sys paths hint at subsystem
    proc_sys = re.findall(r'(/(?:proc|sys)/[\w/]+)', desc)
    if proc_sys:
        clues.append("proc_sys_paths")
        clue_details["proc_sys_paths"] = list(set(proc_sys))

    # Specific kernel messages (not in call trace)
    kernel_msgs = re.findall(r'\[\s*\d+\.\d+\]\s+(.+)', desc)
    if kernel_msgs:
        clues.append("kernel_log_messages")
        clue_details["kernel_msg_count"] = len(kernel_msgs)
        # Extract printk-style messages that could be grepped
        greppable_msgs = []
        for msg in kernel_msgs:
            # Remove timestamp-like prefixes, keep the message
            clean = re.sub(r'^[\w\s]+:\s*', '', msg).strip()
            if len(clean) > 15 and '"' not in clean:
                greppable_msgs.append(clean[:80])
        if greppable_msgs:
            clue_details["greppable_kernel_msgs"] = greppable_msgs[:5]
            clues.append("greppable_kernel_messages")

    # Component/product metadata
    component = bug.get("Component", "")
    product = bug.get("Product", "")
    if component and component not in ["Other", "other bugs"]:
        clues.append("known_component")
        clue_details["component"] = component
    if product:
        clue_details["product"] = product

    # Module / driver name in description
    module_mentions = re.findall(r'\b(\w+)\.ko\b', desc)
    driver_mentions = re.findall(r'\bdriver\s+(\w+)\b', desc, re.IGNORECASE)
    if module_mentions or driver_mentions:
        clues.append("driver_module_named")
        clue_details["modules"] = list(set(module_mentions + driver_mentions))

    # Specific config options
    configs = re.findall(r'(CONFIG_\w+)', desc)
    if configs:
        clues.append("config_options")
        clue_details["configs"] = list(set(configs))

    # Command/tool output (like acpi, lspci, etc.)
    if any(kw in desc.lower() for kw in ["lspci", "lsusb", "lsmod", "dmesg", "acpidump"]):
        clues.append("diagnostic_tool_output")

    # Regression info
    regression = bug.get("Regression", "")
    if regression == "Yes" or any(kw in text for kw in ["regression", "bisect", "used to work"]):
        clues.append("is_regression")

    if not clues:
        clues.append("minimal_clues")

    return {
        "symptom_categories": categories,
        "fix_types": fix_types,
        "localization_clues": clues,
        "clue_details": clue_details,
    }


def analyze_remaining_bugs(bugs, remaining_ids):
    """Analyze the 169 non-trace, non-quirk bugs."""
    print("\n" + "=" * 70)
    print(f"PART 2: Remaining {len(remaining_ids)} bugs (no call trace, no quirk)")
    print("=" * 70)

    results = []
    symptom_counter = Counter()
    fix_counter = Counter()
    clue_counter = Counter()
    subsystem_counter = Counter()

    # Group by localization strategy potential
    strategy_groups = defaultdict(list)

    for bug_id in sorted(remaining_ids):
        bug = bugs[bug_id]
        classification = classify_remaining_bug(bug)

        gt_file = bug["paths"][0]
        gt_subsystem = "/".join(gt_file.split("/")[:2])
        subsystem_counter[gt_subsystem] += 1

        for s in classification["symptom_categories"]:
            symptom_counter[s] += 1
        for f in classification["fix_types"]:
            fix_counter[f] += 1
        for c in classification["localization_clues"]:
            clue_counter[c] += 1

        # Determine best localization strategy
        clues = classification["localization_clues"]
        if "greppable_error_strings" in clues or "greppable_kernel_messages" in clues:
            strategy = "grep_error_strings"
        elif "proc_sys_paths" in clues:
            strategy = "map_proc_sys_to_subsystem"
        elif "driver_module_named" in clues:
            strategy = "search_named_driver"
        elif "config_options" in clues:
            strategy = "search_config_related_code"
        elif "known_component" in clues:
            strategy = "narrow_by_component_metadata"
        elif "is_regression" in clues:
            strategy = "check_recent_commits"
        elif "diagnostic_tool_output" in clues:
            strategy = "parse_diagnostic_output"
        elif "kernel_log_messages" in clues:
            strategy = "grep_kernel_messages"
        else:
            strategy = "semantic_understanding_only"

        strategy_groups[strategy].append(bug_id)

        result = {
            "id": bug_id,
            "title": bug["title"],
            "ground_truth_file": gt_file,
            "ground_truth_subsystem": gt_subsystem,
            "ground_truth_methods": bug["methods"],
            "product": bug.get("Product", ""),
            "component": bug.get("Component", ""),
            "best_strategy": strategy,
            **classification
        }
        results.append(result)

    print(f"\n  Symptom distribution:")
    for s, c in symptom_counter.most_common():
        print(f"    {s}: {c}")

    print(f"\n  Fix type distribution:")
    for f, c in fix_counter.most_common():
        print(f"    {f}: {c}")

    print(f"\n  Available localization clues:")
    for c, n in clue_counter.most_common():
        print(f"    {c}: {n}/{len(remaining_ids)} ({n/len(remaining_ids)*100:.0f}%)")

    print(f"\n  Best localization strategy distribution:")
    for s, ids in sorted(strategy_groups.items(), key=lambda x: -len(x[1])):
        print(f"    {s}: {len(ids)} bugs")

    print(f"\n  Top subsystems:")
    for s, c in subsystem_counter.most_common(15):
        print(f"    {s}: {c}")

    # Cross-tabulate: strategy vs difficulty
    print(f"\n  Strategy breakdown with examples:")
    for strategy, ids in sorted(strategy_groups.items(), key=lambda x: -len(x[1])):
        print(f"\n    === {strategy} ({len(ids)} bugs) ===")
        # Show a few examples
        for bid in ids[:3]:
            bug = bugs[bid]
            r = next(r for r in results if r["id"] == bid)
            print(f"      Bug {bid}: {bug['title'][:55]}")
            print(f"        GT: {bug['paths'][0]}")
            print(f"        Clues: {r['localization_clues']}")
            if r.get("clue_details", {}).get("error_strings"):
                print(f"        Error strings: {r['clue_details']['error_strings'][:2]}")
            if r.get("clue_details", {}).get("proc_sys_paths"):
                print(f"        Proc/sys: {r['clue_details']['proc_sys_paths'][:3]}")

    return {
        "total": len(remaining_ids),
        "symptom_distribution": dict(symptom_counter.most_common()),
        "fix_type_distribution": dict(fix_counter.most_common()),
        "clue_distribution": dict(clue_counter.most_common()),
        "strategy_distribution": {s: len(ids) for s, ids in strategy_groups.items()},
        "strategy_bug_ids": {s: ids for s, ids in strategy_groups.items()},
        "subsystem_distribution": dict(subsystem_counter.most_common()),
        "details": results,
    }


# ══════════════════════════════════════════════
# Part 3: Overall category map of all 250 bugs
# ══════════════════════════════════════════════

def build_overall_map(bugs, trace_data, quirk_data, trace_miss_result, remaining_result):
    """Build a complete categorization of all 250 bugs."""
    print("\n" + "=" * 70)
    print("OVERALL: Complete categorization of all 250 bugs")
    print("=" * 70)

    trace_hit_ids = {r['id'] for r in trace_data['details'] if r['status'] == 'ground_truth_hit'}
    trace_dir_ids = {r['id'] for r in trace_data['details'] if r['status'] == 'correct_directory_hit'}
    trace_miss_ids = {r['id'] for r in trace_data['details'] if r['status'] == 'miss'}
    quirk_ids = {r['id'] for r in quirk_data['details']}

    # Build non-overlapping categories
    categories = {}
    for bug_id in bugs:
        if bug_id in trace_hit_ids:
            cat = "A_trace_hits_gt_file"
        elif bug_id in trace_dir_ids:
            cat = "B_trace_hits_gt_directory"
        elif bug_id in trace_miss_ids:
            cat = "C_trace_misleads"
        elif bug_id in quirk_ids:
            cat = "D_quirk_device_table"
        else:
            # Find the strategy from remaining analysis
            r = next((r for r in remaining_result["details"] if r["id"] == bug_id), None)
            if r:
                strategy = r["best_strategy"]
                cat = f"E_{strategy}"
            else:
                cat = "F_unclassified"
        categories[bug_id] = cat

    cat_counter = Counter(categories.values())
    print(f"\n  Category distribution:")
    for cat, count in sorted(cat_counter.items()):
        print(f"    {cat}: {count}")

    # Summarize localization approach per category
    approach_map = {
        "A_trace_hits_gt_file": "Parse call trace → grep function name → find file (39.6% success)",
        "B_trace_hits_gt_directory": "Parse call trace → find directory → enumerate files in directory",
        "C_trace_misleads": "Call trace points to symptom, not cause → need causal reasoning",
        "D_quirk_device_table": "Extract HW model/device ID → grep in driver quirk tables",
        "E_grep_error_strings": "Grep error message strings from description in kernel source",
        "E_map_proc_sys_to_subsystem": "Map /proc or /sys path to subsystem → narrow search",
        "E_search_named_driver": "Driver/module name mentioned → search directly",
        "E_narrow_by_component_metadata": "Use Bugzilla component metadata to narrow directory",
        "E_check_recent_commits": "Regression bug → check recent commits in related area",
        "E_grep_kernel_messages": "Grep kernel log messages in source",
        "E_search_config_related_code": "Search CONFIG_* option usage in source",
        "E_parse_diagnostic_output": "Parse lspci/lsusb output to identify driver",
        "E_semantic_understanding_only": "Pure semantic understanding needed — hardest category",
    }

    print(f"\n  Recommended approach per category:")
    for cat in sorted(cat_counter.keys()):
        approach = approach_map.get(cat, "Needs investigation")
        print(f"    {cat} ({cat_counter[cat]}): {approach}")

    return {
        "category_distribution": dict(cat_counter.most_common()),
        "bug_categories": categories,
        "approach_map": approach_map,
    }


def main():
    bugs = load_bugs()

    with open(os.path.join(ANALYSIS_DIR, "_call_trace_analysis.json")) as f:
        trace_data = json.load(f)
    with open(os.path.join(ANALYSIS_DIR, "_quirk_analysis.json")) as f:
        quirk_data = json.load(f)

    trace_ids = {r['id'] for r in trace_data['details']}
    trace_miss_ids = {r['id'] for r in trace_data['details'] if r['status'] == 'miss'}
    quirk_ids = {r['id'] for r in quirk_data['details']}
    remaining_ids = set(bugs.keys()) - trace_ids - quirk_ids

    # Part 1
    trace_miss_result = analyze_trace_miss_bugs(bugs, trace_miss_ids)
    with open(os.path.join(ANALYSIS_DIR, "_trace_miss_deep.json"), "w") as f:
        json.dump(trace_miss_result, f, indent=2, ensure_ascii=False)

    # Part 2
    remaining_result = analyze_remaining_bugs(bugs, remaining_ids)
    with open(os.path.join(ANALYSIS_DIR, "_remaining_analysis.json"), "w") as f:
        json.dump(remaining_result, f, indent=2, ensure_ascii=False)

    # Part 3: Overall map
    overall = build_overall_map(bugs, trace_data, quirk_data, trace_miss_result, remaining_result)
    with open(os.path.join(ANALYSIS_DIR, "_overall_categorization.json"), "w") as f:
        json.dump(overall, f, indent=2, ensure_ascii=False)

    # Update individual bug analysis files
    for r in trace_miss_result["details"]:
        path = os.path.join(ANALYSIS_DIR, f"{r['id']}.json")
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            data["trace_miss_analysis"] = r
            with open(path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

    for r in remaining_result["details"]:
        path = os.path.join(ANALYSIS_DIR, f"{r['id']}.json")
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            data["remaining_analysis"] = r
            with open(path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

    # Save category to each bug
    for bug_id, cat in overall["bug_categories"].items():
        path = os.path.join(ANALYSIS_DIR, f"{bug_id}.json")
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            data["overall_category"] = cat
            with open(path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

    print("\n\nAll results saved.")


if __name__ == "__main__":
    main()
