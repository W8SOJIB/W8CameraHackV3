#!/usr/bin/env python3
"""
Windows EXE Builder for W8CameraHackV3
Runs directly on Replit (Linux). Produces a real standalone Windows .exe
using Wine + Python embeddable + wheel injection (no pip inside Wine needed).

Usage:  python3 build_exe.py
"""

import os
import sys
import subprocess
import shutil
import zipfile
import json
import urllib.request
import time
from pathlib import Path

# ─────────────────────── CONFIG ──────────────────────────────
SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
MAIN_SCRIPT     = "W8CameraHackV3.py"
EXE_NAME        = "W8CameraHackV3"
PYTHON_VERSION  = "3.11.9"

EMBED_ZIP_URL   = (
    f"https://www.python.org/ftp/python/{PYTHON_VERSION}/"
    f"python-{PYTHON_VERSION}-embed-amd64.zip"
)

WINEPREFIX      = os.path.join(SCRIPT_DIR, ".wine_build")
PYDIR_LINUX     = os.path.join(WINEPREFIX, "drive_c", "Python311")
SITE_PACKAGES   = os.path.join(PYDIR_LINUX, "Lib", "site-packages")
OUTPUT_PACKAGE  = os.path.join(SCRIPT_DIR, "W8CameraHack_Windows")
OUTPUT_ZIP      = os.path.join(SCRIPT_DIR, "W8CameraHack_Windows.zip")
WORK_DIR        = os.path.join(SCRIPT_DIR, "_build_work")
WHEELS_DIR      = os.path.join(WORK_DIR, "wheels")

XDG_RUNTIME     = "/tmp/wine_xdg"

WINE_CANDIDATES = [
    "/nix/store/0c8fdvn8cx6car3yd95iv92f85890lpg-wine64-10.0/bin/wine64",
    "/nix/store/04ffr3616hr8vm0jb6fzpshnnbzra6mb-wine-staging-9.20/bin/wine",
    "wine64", "wine",
]

CONFIG_FILES = [
    "telegram_config.json",
    "credentials.txt",
    "credential_success_stats.json",
    "credential_daily_stats.json",
    "credential_success_stats_dated.json",
    "brute_progress.json",
    "scan_progress.json",
    "README.md",
    "replit.md",
    "credential_stats_export.csv",
    "requirements.txt",
]

PACKAGES = ["requests", "colorama", "urllib3", "pyfiglet", "pyinstaller", "pywin32-ctypes", "pefile"]

DEFAULT_TELEGRAM = {
    "enabled": False,
    "send_realtime": True,
    "send_summary": True,
    "destinations": [
        {"name": "Bot 1 - Main Chat",
         "bot_token": "YOUR_BOT_TOKEN_HERE",
         "chat_id": "YOUR_CHAT_ID_HERE",
         "enabled": True}
    ]
}

# ─────────────────────── HELPERS ─────────────────────────────
def log(msg, sym="*"):   print(f"[{sym}] {msg}", flush=True)
def ok(msg):             log(msg, "✓")
def fail(msg):           log(msg, "✗")
def info(msg):           log(msg, "→")

def wine_env():
    e = os.environ.copy()
    os.makedirs(XDG_RUNTIME, exist_ok=True)
    e.update({
        "WINEPREFIX":       WINEPREFIX,
        "WINEDEBUG":        "-all",
        "DISPLAY":          "",
        "XDG_RUNTIME_DIR":  XDG_RUNTIME,
    })
    return e

def run_wine(args_str, timeout=600, check=True):
    global WINE_BIN
    cmd = f'"{WINE_BIN}" {args_str}'
    info(f"wine: {args_str[:120]}")
    r = subprocess.run(cmd, shell=True, env=wine_env(), timeout=timeout)
    if check and r.returncode not in (0, 1):
        raise RuntimeError(f"Wine command failed ({r.returncode}): {args_str[:80]}")
    return r.returncode

def run_winpy(args_str, timeout=600, check=True):
    py = r'"C:\Python311\python.exe"'
    return run_wine(f"{py} {args_str}", timeout=timeout, check=check)

def download(url, dest, label=""):
    if os.path.exists(dest) and os.path.getsize(dest) > 500:
        ok(f"Already downloaded: {os.path.basename(dest)}")
        return
    name = label or os.path.basename(dest)
    info(f"Downloading {name} ...")
    def hook(count, block, total):
        done = count * block
        pct  = min(100, int(done * 100 / total)) if total > 0 else 0
        bar  = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r    [{bar}] {pct:3d}%  {done//1024} KB  ", end="", flush=True)
    urllib.request.urlretrieve(url, dest, reporthook=hook)
    print()
    ok(f"Downloaded: {os.path.basename(dest)}")

def lpath(win_path):
    r"""Convert Windows C:\... path to Linux path under WINEPREFIX."""
    p = win_path.replace("\\", "/")
    if p.startswith("C:/") or p.startswith("c:/"):
        return os.path.join(WINEPREFIX, "drive_c", p[3:])
    return p

def zpath(linux_path):
    """Convert Linux absolute path to Wine Z: drive path."""
    return "Z:" + linux_path.replace("/", "\\")

# ─────────────────────── STEPS ───────────────────────────────

WINE_BIN = WINE_CANDIDATES[0]

def step_find_wine():
    global WINE_BIN
    log("Locating Wine ...")
    for candidate in WINE_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            WINE_BIN = candidate
            break
        r = subprocess.run(f"which {candidate} 2>/dev/null",
                           shell=True, capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            WINE_BIN = r.stdout.strip()
            break
    else:
        r = subprocess.run(
            "find /nix/store -maxdepth 3 -name 'wine64' -o -name 'wine' 2>/dev/null | head -3",
            shell=True, capture_output=True, text=True)
        found = [p for p in r.stdout.strip().splitlines() if os.access(p, os.X_OK)]
        if found:
            WINE_BIN = found[0]
        else:
            fail("Wine not found. Cannot build Windows exe.")
            sys.exit(1)
    r = subprocess.run(f'"{WINE_BIN}" --version', shell=True,
                       capture_output=True, text=True, env=wine_env(), timeout=15)
    ver = (r.stdout + r.stderr).strip().split("\n")[0]
    ok(f"Wine: {ver}  ({WINE_BIN})")


def step_init_prefix():
    log("Initialising Wine prefix ...")
    os.makedirs(WINEPREFIX, exist_ok=True)
    subprocess.run(
        f'"{WINE_BIN}" wineboot --init',
        shell=True, env=wine_env(),
        capture_output=True, timeout=60
    )
    ok("Wine prefix ready.")


def step_setup_python():
    log("Setting up Windows Python 3.11 (embeddable) ...")
    py_exe = os.path.join(PYDIR_LINUX, "python.exe")
    if os.path.isfile(py_exe):
        ok("Python embeddable already set up.")
        return

    os.makedirs(PYDIR_LINUX, exist_ok=True)
    embed_zip = os.path.join(WORK_DIR, f"python-{PYTHON_VERSION}-embed-amd64.zip")
    download(EMBED_ZIP_URL, embed_zip, f"Python {PYTHON_VERSION} embeddable (Windows)")

    info("Extracting ...")
    with zipfile.ZipFile(embed_zip, "r") as zf:
        zf.extractall(PYDIR_LINUX)
    ok("Python embeddable extracted.")

    pth = os.path.join(PYDIR_LINUX, "python311._pth")
    if os.path.isfile(pth):
        txt = open(pth).read().replace("#import site", "import site")
        open(pth, "w").write(txt)
        ok("Enabled site-packages in python311._pth")

    os.makedirs(SITE_PACKAGES, exist_ok=True)
    ok("site-packages directory created.")


def step_inject_packages():
    log("Downloading Windows packages via pip (no Wine pip needed) ...")
    os.makedirs(WHEELS_DIR, exist_ok=True)

    r = subprocess.run(
        f'"{sys.executable}" -m pip download '
        f'--platform win_amd64 --python-version 311 '
        f'--only-binary :all: '
        f'{" ".join(PACKAGES)} '
        f'-d "{WHEELS_DIR}" -q',
        shell=True, capture_output=False, timeout=300
    )
    if r.returncode != 0:
        fail("pip download failed. Check your internet connection.")
        sys.exit(1)
    ok("All Windows wheels downloaded.")

    info("Injecting wheels into Wine Python site-packages ...")
    count = 0
    for wheel in os.listdir(WHEELS_DIR):
        if not wheel.endswith(".whl"):
            continue
        wpath = os.path.join(WHEELS_DIR, wheel)
        with zipfile.ZipFile(wpath, "r") as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                if member.startswith(("..","/")):
                    continue
                dest = os.path.join(SITE_PACKAGES, member)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
        count += 1
    ok(f"Injected {count} wheels into site-packages.")

    scripts_dir = os.path.join(PYDIR_LINUX, "Scripts")
    pyinstaller_script = os.path.join(SITE_PACKAGES, "PyInstaller", "__main__.py")
    if not os.path.isfile(pyinstaller_script):
        fail("PyInstaller __main__.py not found after injection.")
        sys.exit(1)
    ok("PyInstaller found in site-packages.")


def step_ensure_configs():
    log("Checking config files ...")
    defaults = {
        "telegram_config.json":          (DEFAULT_TELEGRAM, "json"),
        "credential_success_stats.json": ({}, "json"),
        "credential_daily_stats.json":   ({}, "json"),
        "credential_success_stats_dated.json": ({}, "json"),
        "brute_progress.json":           ({}, "json"),
        "scan_progress.json":            ({}, "json"),
        "credentials.txt": (
            "admin:admin123\nadmin:Admin123\nadmin:admin\n"
            "admin:\n888888:888888\nadmin:hik12345\n", "text"
        ),
        "credential_stats_export.csv": (
            "username,password,success_count,last_success\n", "text"
        ),
        "requirements.txt": (
            "requests>=2.31.0\ncolorama>=0.4.6\nurllib3>=2.0.0\n"
            "certifi>=2023.5.7\ncharset-normalizer>=3.0.0\nidna>=3.0\n", "text"
        ),
    }
    for fname, (default, kind) in defaults.items():
        path = os.path.join(SCRIPT_DIR, fname)
        if fname in ("README.md", "replit.md"):
            if os.path.exists(path):
                ok(f"{fname} — found")
            continue
        if not os.path.exists(path):
            with open(path, "w") as f:
                if kind == "json":
                    json.dump(default, f, indent=2)
                else:
                    f.write(default)
            ok(f"Created {fname}")
        else:
            ok(f"{fname} — found")


def step_build_exe():
    log("Building Windows .exe with PyInstaller ...")

    dist_dir  = os.path.join(WORK_DIR, "dist")
    build_dir = os.path.join(WORK_DIR, "build")
    os.makedirs(dist_dir,  exist_ok=True)
    os.makedirs(build_dir, exist_ok=True)

    datas = []
    for fname in CONFIG_FILES:
        src = os.path.join(SCRIPT_DIR, fname)
        if os.path.exists(src):
            datas.append(f"    (r'{zpath(src)}', '.'),")

    main_z    = zpath(os.path.join(SCRIPT_DIR, MAIN_SCRIPT))
    dist_z    = zpath(dist_dir)
    build_z   = zpath(build_dir)

    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-
block_cipher = None
a = Analysis(
    [r'{main_z}'],
    pathex=[r'Z:\\home\\runner\\workspace\\.wine_build\\drive_c\\Python311\\Lib\\site-packages'],
    binaries=[],
    datas=[
{chr(10).join(datas)}
    ],
    hiddenimports=[
        'requests','urllib3','colorama','pyfiglet','json',
        'threading','queue','socket','base64','html',
        'struct','ipaddress','concurrent.futures',
        'requests.auth','requests.adapters',
        'certifi','charset_normalizer','idna',
        'time','sys','os','re','signal','datetime','math',
        'csv','collections','glob','fnmatch','hashlib',
        'uuid','pathlib','shutil','traceback','io',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='{EXE_NAME}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
)
"""
    spec_path = os.path.join(WORK_DIR, f"{EXE_NAME}.spec")
    with open(spec_path, "w") as f:
        f.write(spec_content)

    pyinstaller_main = os.path.join(
        SITE_PACKAGES, "PyInstaller", "__main__.py"
    )
    spec_z = zpath(spec_path)
    pymain_z = zpath(pyinstaller_main)

    info("Running PyInstaller — 5–10 minutes, please wait ...")
    run_winpy(
        f'"{pymain_z}" --noconfirm --clean '
        f'--distpath "{dist_z}" --workpath "{build_z}" '
        f'"{spec_z}"',
        timeout=900
    )

    exe_path = os.path.join(dist_dir, f"{EXE_NAME}.exe")
    if not os.path.isfile(exe_path):
        fail(f"EXE not found at: {exe_path}")
        fail("Build failed — see output above for errors.")
        sys.exit(1)

    size = os.path.getsize(exe_path) / 1024 / 1024
    ok(f"EXE built: {EXE_NAME}.exe  ({size:.1f} MB)")
    return exe_path


def step_assemble_package(exe_path):
    log("Assembling Windows package ...")
    if os.path.exists(OUTPUT_PACKAGE):
        shutil.rmtree(OUTPUT_PACKAGE)
    os.makedirs(OUTPUT_PACKAGE)

    shutil.copy2(exe_path, OUTPUT_PACKAGE)
    ok(f"  {EXE_NAME}.exe")

    for fname in CONFIG_FILES:
        src = os.path.join(SCRIPT_DIR, fname)
        if os.path.exists(src):
            shutil.copy2(src, OUTPUT_PACKAGE)
            ok(f"  {fname}")

    readme = (
        "W8 Camera Hack V3 — Windows Portable Package\n"
        "=============================================\n\n"
        "KEEP ALL FILES IN THIS FOLDER TOGETHER.\n\n"
        "HOW TO USE:\n"
        "  1. Edit  telegram_config.json  — add your bot token + chat ID.\n"
        "  2. Edit  credentials.txt       — one  username:password  per line.\n"
        "  3. Double-click  W8CameraHackV3.exe  to launch.\n\n"
        "FILES:\n"
        "  W8CameraHackV3.exe            — standalone .exe  (no Python needed)\n"
        "  telegram_config.json          — Telegram bot settings\n"
        "  credentials.txt               — credential list\n"
        "  credential_success_stats.json — auto-updated stats\n"
        "  scan_progress.json            — resume data for interrupted scans\n\n"
        "NOTES:\n"
        "  Works on Windows 10 / 11 (64-bit).  Windows 7 / 8 also supported.\n"
        "  Result files (XX_CCTV_Found.txt) are saved next to the .exe.\n"
        "  If Windows Defender flags the file, add a folder exclusion.\n"
    )
    with open(os.path.join(OUTPUT_PACKAGE, "README.txt"), "w") as f:
        f.write(readme)
    ok("  README.txt")


def step_zip():
    log("Creating ZIP archive ...")
    if os.path.exists(OUTPUT_ZIP):
        os.remove(OUTPUT_ZIP)
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _, files in os.walk(OUTPUT_PACKAGE):
            for fname in files:
                full = os.path.join(root, fname)
                arc  = os.path.relpath(full, os.path.dirname(OUTPUT_PACKAGE))
                zf.write(full, arc)
    size = os.path.getsize(OUTPUT_ZIP) / 1024 / 1024
    ok(f"ZIP: {os.path.basename(OUTPUT_ZIP)}  ({size:.1f} MB)")


def step_cleanup():
    log("Cleaning up ...")
    for path in [WORK_DIR, WINEPREFIX]:
        if os.path.exists(path):
            shutil.rmtree(path)
    ok("Done.")


# ─────────────────────── MAIN ────────────────────────────────
def main():
    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(XDG_RUNTIME, exist_ok=True)

    print()
    print("=" * 64)
    print("  W8CameraHackV3  —  Windows .exe Builder  (Replit / Linux)")
    print("=" * 64)
    print()

    if not os.path.exists(os.path.join(SCRIPT_DIR, MAIN_SCRIPT)):
        fail(f"{MAIN_SCRIPT} not found.")
        sys.exit(1)

    t0 = time.time()

    step_find_wine()
    step_init_prefix()
    step_setup_python()
    step_inject_packages()
    step_ensure_configs()
    exe = step_build_exe()
    step_assemble_package(exe)
    step_zip()
    step_cleanup()

    elapsed = int(time.time() - t0)
    mins, secs = divmod(elapsed, 60)

    print()
    print("=" * 64)
    print("  BUILD COMPLETE!")
    print(f"  Total time : {mins}m {secs}s")
    print("=" * 64)
    print(f"  Package    : {OUTPUT_PACKAGE}/")
    print(f"  ZIP        : {OUTPUT_ZIP}")
    print()
    print("  → Download W8CameraHack_Windows.zip")
    print("  → Extract on any Windows 64-bit PC")
    print("  → Double-click W8CameraHackV3.exe  (no Python install needed)")
    print("=" * 64)
    print()


if __name__ == "__main__":
    main()
