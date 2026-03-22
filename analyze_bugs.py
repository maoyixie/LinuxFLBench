#!/usr/bin/env python3
"""Analyze each bug in LinuxFLBench dataset and generate per-bug analysis files."""

import json
import re
import os

INPUT_FILE = "dataset/LINUXFLBENCH_dataset.jsonl"
OUTPUT_DIR = "analysis"

# ──────────────────────────────────────────────
# 1. Symptom / Bug-type classification
# ──────────────────────────────────────────────

def classify_symptom(title, desc):
    """Classify bug symptom based on title + description keywords."""
    text = (title + " " + desc).lower()
    symptoms = []

    # Crash / Panic / Oops
    if any(kw in text for kw in [
        "oops", "panic", "bug:", "bug at", "kernel bug",
        "null pointer", "null deref", "general protection fault",
        "unable to handle kernel", "segfault", "crash",
        "rip:", "call trace", "calltrace"
    ]):
        symptoms.append("crash/panic/oops")

    # Hang / Lockup / Freeze
    if any(kw in text for kw in [
        "hang", "hung", "freeze", "frozen", "lockup", "lock up",
        "deadlock", "dead lock", "stops responding", "unresponsive",
        "soft lockup", "hard lockup", "rcu stall",
        "stops at", "stops progressing", "machine is not completely hung"
    ]):
        symptoms.append("hang/lockup")

    # Error log spam
    if any(kw in text for kw in [
        "error storm", "error spam", "flood of", "endless stream",
        "many mb of error", "dmesg full", "log spam", "repeated error",
        "keeps printing", "continuously print"
    ]):
        symptoms.append("error_log_spam")

    # Device not working / not recognized
    if any(kw in text for kw in [
        "not recognized", "not detected", "not found",
        "device not work", "doesn't work", "does not work",
        "not working", "no longer works", "stopped working",
        "fails to load", "firmware not", "not loaded",
        "missing pci", "missing device"
    ]):
        symptoms.append("device_not_working")

    # Performance
    if any(kw in text for kw in [
        "slow", "performance", "latency", "throughput",
        "degradation", "regression in speed", "takes too long"
    ]):
        symptoms.append("performance")

    # Wrong behavior / functional
    if any(kw in text for kw in [
        "wrong", "incorrect", "broken", "invalid",
        "unexpected", "should be", "instead of",
        "doesn't report", "not display", "not update",
        "reports wrong", "shows wrong", "miscalculated"
    ]):
        symptoms.append("wrong_behavior")

    # Power / sleep / resume issues
    if any(kw in text for kw in [
        "suspend", "resume", "sleep", "hibernate",
        "s3", "s4", "wakeup", "wake up",
        "shutdown", "reboot", "poweroff", "power off"
    ]):
        symptoms.append("power/sleep")

    # Compile / build issues
    if any(kw in text for kw in [
        "compile error", "build error", "warning:",
        "undefined reference", "implicit declaration",
        "does not compile"
    ]):
        symptoms.append("compile_error")

    if not symptoms:
        symptoms.append("other")

    return symptoms


# ──────────────────────────────────────────────
# 2. Description clue analysis
# ──────────────────────────────────────────────

def analyze_description_clues(desc):
    """Extract what kind of diagnostic clues the description contains."""
    clues = {}

    # Call trace / stack trace
    call_trace_patterns = [
        r"call trace", r"call_trace", r"stack trace",
        r"\bRIP\b:", r"\bEIP\b:", r"\[<[0-9a-f]+>\]",
        r"at \w+\.c:\d+", r"BUG: ", r"Oops:",
        r"\bbacktrace\b"
    ]
    has_call_trace = any(re.search(p, desc, re.IGNORECASE) for p in call_trace_patterns)
    clues["has_call_trace"] = has_call_trace

    # Extract function names from call trace
    trace_functions = re.findall(r'\[<[0-9a-f]+>\]\s+(\w+)', desc)
    if not trace_functions:
        trace_functions = re.findall(r'(?:RIP|EIP).*?(\w+)\+0x', desc)
    if not trace_functions:
        # patterns like "function_name+0x1a/0x30"
        trace_functions = re.findall(r'\b(\w+)\+0x[0-9a-f]+/0x[0-9a-f]+', desc)
    clues["trace_functions"] = list(set(trace_functions))

    # File paths mentioned in description
    file_paths = re.findall(r'(?:drivers|fs|net|arch|kernel|mm|sound|include|lib|block|security|crypto)/[\w/]+\.\w+', desc)
    clues["mentioned_file_paths"] = list(set(file_paths))

    # Kernel source file references (like "evgpe-835" -> evgpe.c line 835)
    source_refs = re.findall(r'(\w+)-(\d+)\)', desc)
    clues["source_references"] = [{"file": r[0], "line": r[1]} for r in source_refs]

    # Error messages
    error_msgs = re.findall(r'(?:error|ERROR|Error)[:\s]+(.{10,80})', desc)
    clues["error_messages"] = error_msgs[:5]  # keep top 5

    # /proc or /sys paths (often hint at subsystem)
    proc_sys_paths = re.findall(r'(/(?:proc|sys)/[\w/]+)', desc)
    clues["proc_sys_paths"] = list(set(proc_sys_paths))

    # dmesg / kernel log lines
    dmesg_lines = re.findall(r'\[\s*\d+\.\d+\]\s+(.+)', desc)
    clues["has_dmesg_logs"] = len(dmesg_lines) > 0
    clues["dmesg_line_count"] = len(dmesg_lines)

    # Workaround mentioned
    workaround_kw = ["workaround", "work around", "disabling", "reverting",
                     "booting with", "if i", "turning off", "adding.*to.*command"]
    clues["has_workaround"] = any(re.search(kw, desc, re.IGNORECASE) for kw in workaround_kw)

    # Reproduction steps
    clues["has_repro_steps"] = any(kw in desc.lower() for kw in [
        "steps to reproduce", "how to reproduce", "to reproduce",
        "reproduction", "reproduce the"
    ])

    # Regression info in description
    clues["mentions_regression"] = any(kw in desc.lower() for kw in [
        "regression", "used to work", "worked before", "worked in",
        "broke in", "broken since", "bisect"
    ])

    # Hardware info
    clues["mentions_hardware_model"] = bool(re.search(
        r'(?:laptop|notebook|desktop|model|board|chipset|cpu)\s*[:=]?\s*\w+', desc, re.IGNORECASE
    ))

    # Config hints
    clues["mentions_kernel_config"] = bool(re.search(
        r'CONFIG_\w+|\.config|menuconfig|kconfig', desc, re.IGNORECASE
    ))

    # Description length
    clues["description_length"] = len(desc)
    clues["description_word_count"] = len(desc.split())

    return clues


# ──────────────────────────────────────────────
# 3. Patch analysis
# ──────────────────────────────────────────────

def analyze_patch(patches):
    """Analyze patch characteristics."""
    analysis = {}
    if not patches:
        analysis["has_patch"] = False
        return analysis

    analysis["has_patch"] = True
    full_patch = "\n".join(patches)

    # Count added/removed lines
    added = len(re.findall(r'^\+[^+]', full_patch, re.MULTILINE))
    removed = len(re.findall(r'^-[^-]', full_patch, re.MULTILINE))
    analysis["lines_added"] = added
    analysis["lines_removed"] = removed
    analysis["patch_size"] = added + removed

    # Classify patch type
    patch_types = []

    # Quirk / DMI table / device ID addition
    if any(kw in full_patch.lower() for kw in [
        "dmi_match", "quirk", "blacklist", "whitelist",
        "iwl_dev_info", "horkage", "pci_device_id",
        "dmi_system_id", "device_id"
    ]):
        patch_types.append("quirk/device_table")

    # Adding a new function
    new_funcs = re.findall(r'^\+\s*(?:static\s+)?(?:int|void|bool|long|unsigned|struct|enum)\s+(\w+)\s*\(', full_patch, re.MULTILINE)
    if new_funcs:
        patch_types.append("new_function")
        analysis["new_functions"] = new_funcs

    # Conditional logic change
    if re.search(r'^\+.*\b(?:if|else|switch|case)\b', full_patch, re.MULTILINE):
        patch_types.append("logic_change")

    # Error handling
    if any(kw in full_patch for kw in [
        "error", "err", "ret <", "return -E", "goto err", "goto fail",
        "WARN", "BUG_ON", "WARN_ON"
    ]):
        patch_types.append("error_handling")

    # Config / ifdef
    if re.search(r'^\+.*#(?:ifdef|ifndef|if defined|endif)', full_patch, re.MULTILINE):
        patch_types.append("config/ifdef")

    # Initialization / assignment fix
    if re.search(r'^\+.*=\s*(?:0|NULL|false|true);', full_patch, re.MULTILINE):
        patch_types.append("init_fix")

    # Lock / synchronization
    if any(kw in full_patch for kw in [
        "mutex", "spin_lock", "spin_unlock", "lock", "unlock",
        "semaphore", "rcu", "barrier"
    ]):
        patch_types.append("synchronization")

    # Memory management
    if any(kw in full_patch for kw in [
        "kfree", "kmalloc", "kzalloc", "vmalloc", "free",
        "alloc", "memset", "memcpy", "leak"
    ]):
        patch_types.append("memory")

    if not patch_types:
        patch_types.append("other")

    analysis["patch_types"] = patch_types

    # Number of hunks
    hunks = re.findall(r'^@@', full_patch, re.MULTILINE)
    analysis["num_hunks"] = len(hunks)

    # Modified functions (from @@ headers)
    hunk_funcs = re.findall(r'@@.*@@\s*(?:static\s+)?(?:\w+\s+)*(\w+)\s*\(', full_patch)
    analysis["hunk_functions"] = list(set(hunk_funcs))

    return analysis


# ──────────────────────────────────────────────
# 4. Buggy file location analysis
# ──────────────────────────────────────────────

def analyze_location(paths):
    """Analyze the buggy file location characteristics."""
    if not paths:
        return {"error": "no paths"}

    path = paths[0]  # single-file benchmark
    parts = path.split("/")
    analysis = {}
    analysis["full_path"] = path
    analysis["filename"] = parts[-1]
    analysis["directory"] = "/".join(parts[:-1])
    analysis["depth"] = len(parts)

    # Top-level subsystem
    analysis["top_level"] = parts[0] if parts else ""

    # Second-level
    analysis["second_level"] = parts[1] if len(parts) > 1 else ""

    # Subsystem categorization
    if path.startswith("drivers/"):
        if len(parts) > 2:
            analysis["driver_subsystem"] = parts[1] + "/" + parts[2] if len(parts) > 2 else parts[1]
        else:
            analysis["driver_subsystem"] = parts[1]
    elif path.startswith("arch/"):
        analysis["arch"] = parts[1] if len(parts) > 1 else ""

    # File extension
    ext = path.rsplit(".", 1)[-1] if "." in path else ""
    analysis["extension"] = ext

    return analysis


# ──────────────────────────────────────────────
# 5. Localizability assessment
# ──────────────────────────────────────────────

def assess_localizability(desc_clues, patch_analysis, location, bug_data):
    """Assess how easy/hard this bug is to localize, and what strategies might work."""
    signals = []
    strategies = []

    # Strong signals
    if desc_clues["has_call_trace"]:
        signals.append("call_trace_available")
        strategies.append("parse_call_trace_to_identify_functions_and_files")

    if desc_clues["mentioned_file_paths"]:
        signals.append("file_paths_in_description")
        strategies.append("direct_file_path_matching")

    if desc_clues["trace_functions"]:
        signals.append(f"trace_has_{len(desc_clues['trace_functions'])}_functions")
        strategies.append("match_trace_functions_to_source_files")

    if desc_clues["proc_sys_paths"]:
        signals.append("proc_sys_paths_hint_subsystem")
        strategies.append("map_proc_sys_path_to_driver_or_subsystem")

    if desc_clues["source_references"]:
        signals.append("source_file_line_references")
        strategies.append("use_source_references_to_locate_file")

    if desc_clues["has_dmesg_logs"]:
        signals.append("dmesg_logs_available")
        strategies.append("grep_error_messages_in_kernel_source")

    # Metadata signals
    component = bug_data.get("Component", "")
    product = bug_data.get("Product", "")
    if component and component not in ["Other", "other bugs"]:
        signals.append(f"component_known:{component}")
        strategies.append("narrow_search_by_component")

    if bug_data.get("Regression") == "Yes":
        signals.append("is_regression")
        strategies.append("bisect_or_check_recent_commits")

    # Patch-based difficulty indicators
    if patch_analysis.get("patch_types"):
        if "quirk/device_table" in patch_analysis["patch_types"]:
            signals.append("fix_is_quirk_table_entry")
            strategies.append("search_for_quirk_tables_in_related_drivers")

    # Difficulty assessment
    difficulty = "medium"
    if desc_clues["mentioned_file_paths"]:
        difficulty = "easy"
    elif desc_clues["has_call_trace"] and desc_clues["trace_functions"]:
        difficulty = "easy-medium"
    elif not desc_clues["has_call_trace"] and not desc_clues["has_dmesg_logs"] and not desc_clues["mentioned_file_paths"]:
        difficulty = "hard"

    if patch_analysis.get("patch_types") and "quirk/device_table" in patch_analysis["patch_types"]:
        if difficulty != "easy":
            difficulty = "hard"  # quirk additions are hard to locate without domain knowledge

    return {
        "difficulty": difficulty,
        "signals": signals,
        "strategies": strategies
    }


# ──────────────────────────────────────────────
# Main: process all bugs
# ──────────────────────────────────────────────

def process_bug(bug_data):
    """Generate full analysis for a single bug."""
    title = bug_data["title"]
    desc = bug_data["description"]

    symptoms = classify_symptom(title, desc)
    desc_clues = analyze_description_clues(desc)
    patch_anal = analyze_patch(bug_data.get("patch", []))
    location = analyze_location(bug_data.get("paths", []))
    localizability = assess_localizability(desc_clues, patch_anal, location, bug_data)

    analysis = {
        "id": bug_data["id"],
        "title": title,
        "kernel_version": bug_data.get("Kernel Version", ""),
        "product": bug_data.get("Product", ""),
        "component": bug_data.get("Component", ""),
        "hardware": bug_data.get("Hardware", ""),
        "is_regression": bug_data.get("Regression", ""),
        "symptom_classification": symptoms,
        "ground_truth": {
            "buggy_file": bug_data.get("paths", []),
            "buggy_methods": bug_data.get("methods", []),
            "num_methods": len(bug_data.get("methods", []))
        },
        "description_clues": desc_clues,
        "patch_analysis": patch_anal,
        "location_analysis": location,
        "localizability": localizability
    }

    return analysis


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    bugs = []
    with open(INPUT_FILE, "r") as f:
        for line in f:
            bugs.append(json.loads(line.strip()))

    print(f"Processing {len(bugs)} bugs...")

    for bug in bugs:
        analysis = process_bug(bug)
        output_path = os.path.join(OUTPUT_DIR, f"{bug['id']}.json")
        with open(output_path, "w") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)

    print(f"Done. {len(bugs)} analysis files written to {OUTPUT_DIR}/")

    # ── Generate summary statistics ──
    all_analyses = []
    for bug in bugs:
        all_analyses.append(process_bug(bug))

    summary = generate_summary(all_analyses)
    with open(os.path.join(OUTPUT_DIR, "_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"Summary written to {OUTPUT_DIR}/_summary.json")


def generate_summary(analyses):
    """Generate aggregate statistics across all bugs."""
    from collections import Counter

    summary = {}

    # Symptom distribution
    symptom_counter = Counter()
    for a in analyses:
        for s in a["symptom_classification"]:
            symptom_counter[s] += 1
    summary["symptom_distribution"] = dict(symptom_counter.most_common())

    # Difficulty distribution
    diff_counter = Counter(a["localizability"]["difficulty"] for a in analyses)
    summary["difficulty_distribution"] = dict(diff_counter.most_common())

    # Clue availability
    summary["clue_stats"] = {
        "has_call_trace": sum(1 for a in analyses if a["description_clues"]["has_call_trace"]),
        "has_file_paths_mentioned": sum(1 for a in analyses if a["description_clues"]["mentioned_file_paths"]),
        "has_dmesg_logs": sum(1 for a in analyses if a["description_clues"]["has_dmesg_logs"]),
        "has_proc_sys_paths": sum(1 for a in analyses if a["description_clues"]["proc_sys_paths"]),
        "has_trace_functions": sum(1 for a in analyses if a["description_clues"]["trace_functions"]),
        "has_error_messages": sum(1 for a in analyses if a["description_clues"]["error_messages"]),
        "has_workaround": sum(1 for a in analyses if a["description_clues"]["has_workaround"]),
        "has_repro_steps": sum(1 for a in analyses if a["description_clues"]["has_repro_steps"]),
        "mentions_regression": sum(1 for a in analyses if a["description_clues"]["mentions_regression"]),
        "mentions_hardware_model": sum(1 for a in analyses if a["description_clues"]["mentions_hardware_model"]),
        "mentions_kernel_config": sum(1 for a in analyses if a["description_clues"]["mentions_kernel_config"]),
    }

    # Patch type distribution
    patch_type_counter = Counter()
    for a in analyses:
        for pt in a["patch_analysis"].get("patch_types", []):
            patch_type_counter[pt] += 1
    summary["patch_type_distribution"] = dict(patch_type_counter.most_common())

    # Patch size statistics
    sizes = [a["patch_analysis"].get("patch_size", 0) for a in analyses if a["patch_analysis"].get("has_patch")]
    summary["patch_size_stats"] = {
        "min": min(sizes) if sizes else 0,
        "max": max(sizes) if sizes else 0,
        "mean": round(sum(sizes) / len(sizes), 1) if sizes else 0,
        "median": sorted(sizes)[len(sizes)//2] if sizes else 0,
    }

    # Location analysis
    top_level_counter = Counter(a["location_analysis"].get("top_level", "") for a in analyses)
    summary["top_level_directory"] = dict(top_level_counter.most_common())

    # Product/Component distribution
    product_counter = Counter(a["product"] for a in analyses)
    component_counter = Counter(a["component"] for a in analyses)
    summary["product_distribution"] = dict(product_counter.most_common())
    summary["component_distribution"] = dict(component_counter.most_common(20))

    # Regression stats
    regression_counter = Counter(a["is_regression"] for a in analyses)
    summary["regression_distribution"] = dict(regression_counter.most_common())

    # Methods per bug
    method_counts = [a["ground_truth"]["num_methods"] for a in analyses]
    summary["methods_per_bug"] = {
        "min": min(method_counts),
        "max": max(method_counts),
        "mean": round(sum(method_counts) / len(method_counts), 1),
        "1_method": sum(1 for m in method_counts if m == 1),
        "2_methods": sum(1 for m in method_counts if m == 2),
        "3+_methods": sum(1 for m in method_counts if m >= 3),
    }

    # Description length stats
    desc_lens = [a["description_clues"]["description_word_count"] for a in analyses]
    summary["description_word_count_stats"] = {
        "min": min(desc_lens),
        "max": max(desc_lens),
        "mean": round(sum(desc_lens) / len(desc_lens), 1),
        "median": sorted(desc_lens)[len(desc_lens)//2],
    }

    # Strategy distribution
    strategy_counter = Counter()
    for a in analyses:
        for s in a["localizability"]["strategies"]:
            strategy_counter[s] += 1
    summary["applicable_strategies"] = dict(strategy_counter.most_common())

    # Cross-analysis: difficulty vs has_call_trace
    summary["difficulty_vs_call_trace"] = {}
    for diff_level in ["easy", "easy-medium", "medium", "hard"]:
        bugs_at_level = [a for a in analyses if a["localizability"]["difficulty"] == diff_level]
        if bugs_at_level:
            summary["difficulty_vs_call_trace"][diff_level] = {
                "count": len(bugs_at_level),
                "with_call_trace": sum(1 for a in bugs_at_level if a["description_clues"]["has_call_trace"]),
                "with_dmesg": sum(1 for a in bugs_at_level if a["description_clues"]["has_dmesg_logs"]),
            }

    return summary


if __name__ == "__main__":
    main()
