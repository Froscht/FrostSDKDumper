#!/usr/bin/env python3
import subprocess
import sys
import time
import os
import json
import argparse
from pathlib import Path

ConfigPath = Path(__file__).parent / "auto_join_config.json"

DefaultConfig = {
    "window_title": "ARC Raiders",
    "steps": [
        {"action": "wait", "seconds": 5, "label": "initial_settle"},
        {"action": "key", "key": "Escape", "label": "dismiss_popup"},
        {"action": "wait", "seconds": 2, "label": "after_dismiss"},
        {"action": "click", "x": 960, "y": 800, "label": "play_button"},
        {"action": "wait", "seconds": 3, "label": "after_play"},
        {"action": "click", "x": 960, "y": 600, "label": "practice_range"},
        {"action": "wait", "seconds": 3, "label": "after_practice"},
        {"action": "click", "x": 960, "y": 700, "label": "confirm_start"},
        {"action": "wait", "seconds": 5, "label": "loading_start"},
        {"action": "key", "key": "Return", "label": "accept_prompt"},
        {"action": "wait", "seconds": 60, "label": "loading_map"}
    ],
    "resolution": {"width": 1920, "height": 1080}
}


def LoadConfig():
    if ConfigPath.exists():
        with open(ConfigPath) as F:
            return json.load(F)
    SaveConfig(DefaultConfig)
    return DefaultConfig


def SaveConfig(Cfg):
    with open(ConfigPath, "w") as F:
        json.dump(Cfg, F, indent=2)


def FindWindow(Title):
    try:
        Result = subprocess.run(
            ["xdotool", "search", "--name", Title],
            capture_output=True, text=True, timeout=5
        )
        WindowIds = Result.stdout.strip().split("\n")
        WindowIds = [W for W in WindowIds if W.strip()]
        if WindowIds:
            return WindowIds[-1]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def FocusWindow(WindowId):
    try:
        subprocess.run(
            ["xdotool", "windowactivate", "--sync", WindowId],
            timeout=5, capture_output=True
        )
        time.sleep(0.5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def ClickAt(X, Y, WindowId=None):
    try:
        if WindowId:
            subprocess.run(
                ["xdotool", "windowactivate", "--sync", WindowId],
                timeout=5, capture_output=True
            )
            time.sleep(0.3)
        subprocess.run(
            ["xdotool", "mousemove", "--window", WindowId or "0", str(X), str(Y)],
            timeout=5, capture_output=True
        )
        time.sleep(0.1)
        subprocess.run(
            ["xdotool", "click", "1"],
            timeout=5, capture_output=True
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def PressKey(Key, WindowId=None):
    try:
        if WindowId:
            subprocess.run(
                ["xdotool", "windowactivate", "--sync", WindowId],
                timeout=5, capture_output=True
            )
            time.sleep(0.2)
        subprocess.run(
            ["xdotool", "key", Key],
            timeout=5, capture_output=True
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def TakeScreenshot(OutPath):
    for Cmd in [
        ["gnome-screenshot", "-f", OutPath],
        ["scrot", OutPath],
        ["maim", OutPath],
        ["import", "-window", "root", OutPath],
    ]:
        try:
            subprocess.run(Cmd, timeout=10, capture_output=True)
            if os.path.exists(OutPath):
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return False


def RunCalibrate(Cfg):
    print("=== Calibration Mode ===")
    print(f"Window title: {Cfg['window_title']}")
    WindowId = FindWindow(Cfg["window_title"])
    if not WindowId:
        print(f"Window '{Cfg['window_title']}' not found")
        print("Make sure the game is running and visible")
        return

    print(f"Found window: {WindowId}")
    FocusWindow(WindowId)

    SsPath = "/tmp/frost_calibrate.png"
    if TakeScreenshot(SsPath):
        print(f"Screenshot saved: {SsPath}")
    else:
        print("Screenshot failed — install scrot, maim, or gnome-screenshot")

    print()
    print("Current click sequence:")
    for I, Step in enumerate(Cfg["steps"]):
        if Step["action"] == "click":
            print(f"  [{I}] {Step['label']}: click({Step['x']}, {Step['y']})")
        elif Step["action"] == "key":
            print(f"  [{I}] {Step['label']}: key({Step['key']})")
        elif Step["action"] == "wait":
            print(f"  [{I}] {Step['label']}: wait({Step['seconds']}s)")

    print()
    print(f"Edit {ConfigPath} to adjust coordinates")
    print("Use xdotool getmouselocation to find coordinates while hovering over buttons")
    print()
    print("Tip: run 'xdotool getmouselocation' in another terminal")
    print("     while hovering over each button to get x,y coords")


def RunSequence(Cfg, Timeout):
    WindowTitle = Cfg["window_title"]
    Steps = Cfg["steps"]

    StartTime = time.time()

    print(f"Looking for window: {WindowTitle}")
    WindowId = None
    while time.time() - StartTime < Timeout:
        WindowId = FindWindow(WindowTitle)
        if WindowId:
            break
        print("Waiting for game window...")
        time.sleep(5)

    if not WindowId:
        print("Game window not found within timeout")
        return False

    print(f"Found window: {WindowId}")
    FocusWindow(WindowId)
    time.sleep(1)

    for I, Step in enumerate(Steps):
        if time.time() - StartTime > Timeout:
            print("Timeout reached during sequence")
            return False

        Action = Step["action"]
        Label = Step.get("label", f"step_{I}")

        if Action == "wait":
            Seconds = Step["seconds"]
            print(f"[{I}/{len(Steps)}] {Label}: waiting {Seconds}s")
            time.sleep(Seconds)

        elif Action == "click":
            X, Y = Step["x"], Step["y"]
            print(f"[{I}/{len(Steps)}] {Label}: click({X}, {Y})")
            WindowId = FindWindow(WindowTitle) or WindowId
            if not ClickAt(X, Y, WindowId):
                print(f"  Click failed at ({X}, {Y})")
            time.sleep(0.5)

        elif Action == "key":
            Key = Step["key"]
            print(f"[{I}/{len(Steps)}] {Label}: key({Key})")
            WindowId = FindWindow(WindowTitle) or WindowId
            if not PressKey(Key, WindowId):
                print(f"  Key press failed: {Key}")
            time.sleep(0.5)

        elif Action == "screenshot":
            OutPath = Step.get("path", f"/tmp/frost_step_{I}.png")
            print(f"[{I}/{len(Steps)}] {Label}: screenshot → {OutPath}")
            TakeScreenshot(OutPath)

    print("Sequence complete")
    return True


def main():
    Parser = argparse.ArgumentParser(description="Auto-join ARC Raiders match")
    Parser.add_argument("--calibrate", action="store_true",
                        help="Enter calibration mode to set click coordinates")
    Parser.add_argument("--timeout", type=int, default=180,
                        help="Max seconds for the join sequence")
    Parser.add_argument("--dry-run", action="store_true",
                        help="Print steps without executing")
    Args = Parser.parse_args()

    Cfg = LoadConfig()

    if Args.calibrate:
        RunCalibrate(Cfg)
        return

    if Args.dry_run:
        print("Dry run — steps that would execute:")
        for I, Step in enumerate(Cfg["steps"]):
            print(f"  [{I}] {Step}")
        return

    Success = RunSequence(Cfg, Args.timeout)
    sys.exit(0 if Success else 1)


if __name__ == "__main__":
    main()
