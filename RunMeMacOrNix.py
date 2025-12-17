#!/usr/bin/env python3
import os
import sys
import shutil
import platform
import subprocess
import secrets
import re
import time
import zipfile
import tarfile
import urllib.request
import json
from pathlib import Path

# --- CONFIGURATION ---
# Since this script is at the project root, all directories are subfolders of the current path.
PROJECT_DIR_NAME = "my_app"
FIRMWARE_DIR_NAME = "firmware"
OUTPUT_DIR_NAME = "output"
TOOLS_DIR_NAME = "arduino-cli" 
DATA_DIR_NAME = "arduino-data"
SKETCHBOOK_DIR_NAME = "arduino-sketchbook"

# Arduino CLI Settings
ARDUINO_CLI_VERSION = "0.34.2"
FQBN = "esp32:esp32:esp32"
BAUD_RATE = "460800"

# Map OS to Arduino CLI download
OS_MAP = {
    "Windows": "Windows_64bit.zip",
    "Darwin": "macOS_64bit.tar.gz",
    "Linux": "Linux_64bit.tar.gz"
}

# Flash Addresses
ADDR_BOOTLOADER = "0x1000"
ADDR_PARTITIONS = "0x8000"
ADDR_APP = "0x10000"

# --- UTILITY FUNCTIONS ---

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def log(msg, type="INFO"):
    colors = {
        "INFO": "\033[96m",     # Cyan
        "SUCCESS": "\033[92m",  # Green
        "WARN": "\033[93m",     # Yellow
        "ERROR": "\033[91m",    # Red
        "RESET": "\033[0m"
    }
    prefix = f"[{type}]"
    if sys.platform == "win32":
        print(f"{prefix} {msg}")
    else:
        print(f"{colors.get(type, '')}{prefix} {msg}{colors['RESET']}")

def get_paths():
    """Defines pathing relative to the script's location at project root."""
    root = Path(__file__).resolve().parent
    exe_ext = ".exe" if platform.system() == "Windows" else ""
    return {
        "root": root,
        "firmware": root / FIRMWARE_DIR_NAME,
        "output": root / OUTPUT_DIR_NAME,
        "tools": root / TOOLS_DIR_NAME,
        "cli_bin": root / TOOLS_DIR_NAME / f"arduino-cli{exe_ext}",
        "data": root / DATA_DIR_NAME,
        "esp32_core": root / DATA_DIR_NAME / "packages" / "esp32" / "hardware" / "esp32",
        "sketchbook": root / SKETCHBOOK_DIR_NAME,
        "config": root / TOOLS_DIR_NAME / "arduino-cli.yaml",
        "sketch_dest": root / SKETCHBOOK_DIR_NAME / PROJECT_DIR_NAME
    }

def setup_arduino_cli(paths):
    """Ensures arduino-cli and the ESP32 core are installed locally."""
    if paths["cli_bin"].exists():
        log(f"Local arduino-cli found at {paths['cli_bin']}.", "SUCCESS")
    else:
        log("arduino-cli not found locally. Running setup...", "WARN")
        paths["tools"].mkdir(parents=True, exist_ok=True)
        
        system = platform.system()
        if system not in OS_MAP:
            log(f"Unsupported OS: {system}", "ERROR")
            sys.exit(1)

        url = f"https://github.com/arduino/arduino-cli/releases/download/v{ARDUINO_CLI_VERSION}/arduino-cli_{ARDUINO_CLI_VERSION}_{OS_MAP[system]}"
        archive_path = paths["tools"] / "cli_download"
        
        try:
            log(f"Downloading {url}...")
            urllib.request.urlretrieve(url, archive_path)
            
            log("Extracting...")
            if str(archive_path).endswith(".zip"):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(paths["tools"])
            else:
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(paths["tools"])
            
            if archive_path.exists():
                os.remove(archive_path)
            
            if system != "Windows":
                os.chmod(paths["cli_bin"], 0o755)
                
            log("arduino-cli installed.", "SUCCESS")
        except Exception as e:
            log(f"Failed to install tools: {e}", "ERROR")
            sys.exit(1)

    # Generate/Verify Config
    paths["data"].mkdir(exist_ok=True)
    paths["sketchbook"].mkdir(exist_ok=True)
    
    # Path strings MUST use forward slashes for the CLI yaml config to work across platforms
    data_dir_str = str(paths["data"]).replace("\\", "/")
    sketch_dir_str = str(paths["sketchbook"]).replace("\\", "/")
    
    config_content = f"""
board_manager:
  additional_urls:
    - https://espressif.github.io/arduino-esp32/package_esp32_index.json
directories:
  data: {data_dir_str}
  downloads: {data_dir_str}/staging
  user: {sketch_dir_str}
library:
  enable_unsafe_install: true
"""
    with open(paths["config"], "w") as f:
        f.write(config_content)

    # Check for local ESP32 Core
    log("Checking ESP32 core status...", "INFO")
    if paths["esp32_core"].exists():
        log("ESP32 core found.", "SUCCESS")
    else:
        log("ESP32 core not found. Running installation...", "WARN")
        cmd_base = [str(paths["cli_bin"]), "--config-file", str(paths["config"])]
        try:
            subprocess.run(cmd_base + ["core", "update-index"], check=True)
            subprocess.run(cmd_base + ["core", "install", "esp32:esp32"], check=True)
            log("ESP32 core installed.", "SUCCESS")
        except Exception as e:
            log(f"Failed to install core: {e}", "ERROR")
            sys.exit(1)

def find_esptool(paths):
    """Locates the esptool binary within the arduino-data directory."""
    search_root = paths["data"] / "packages" / "esp32" / "tools" / "esptool_py"
    if not search_root.exists():
        return None
        
    exe_name = "esptool.exe" if platform.system() == "Windows" else "esptool"
    matches = list(search_root.rglob(exe_name))
    if matches:
        return matches[0]
        
    matches = list(search_root.rglob("esptool.py"))
    if matches:
        return matches[0]
        
    return None

def generate_random_psk_block():
    """Generates a C++ formatted random key block."""
    random_bytes = secrets.token_bytes(24)
    hex_strings = [f"0x{b:02X}" for b in random_bytes]
    lines = []
    for i in range(0, 24, 8):
        block = ", ".join(hex_strings[i:i+8])
        lines.append(f"\t{block}, // 8-byte Random PSK Block {i//8 + 1}")
    return "\n".join(lines)

# --- ACTION: COMPILE ---

def action_compile(paths):
    clear_screen()
    print("--- COMPILATION MODE ---")
    print("[1] Secure Mode (Default): Generates a unique, random encryption key.")
    print("[2] Compatibility Mode: Uses the default/factory key.")
    
    choice = input("\nSelect Mode [1]: ").strip()
    secure_mode = False if choice == "2" else True
    
    setup_arduino_cli(paths)
    
    # 1. Prepare Sketch Directory
    if paths["sketch_dest"].exists():
        shutil.rmtree(paths["sketch_dest"])
    paths["sketch_dest"].mkdir(parents=True)
    
    # 2. Source File Processing
    possible_sources = ["originalcode.cpp", "sketch_primary.cpp", "sketch_primary (1).cpp"]
    source_file = None
    for s in possible_sources:
        test_path = paths["firmware"] / s
        if test_path.exists():
            source_file = test_path
            break
    
    if not source_file:
        log(f"Could not find source .cpp file in {paths['firmware']}", "ERROR")
        input("Press Enter to return...")
        return

    with open(source_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 3. Patching
    if secure_mode:
        log("Injecting secure random key...", "WARN")
        new_psk = generate_random_psk_block()
        magic_marker = "0xDE, 0xAD, 0xBE, 0xEF, // 4-byte Magic prefix for the flasher"
        if magic_marker in content:
            pre, post = content.split(magic_marker, 1)
            end_idx = post.find("};")
            if end_idx != -1:
                content = pre + magic_marker + "\n" + new_psk + "\n" + post[end_idx:]
            else:
                log("Could not find end of PSK array in source.", "ERROR")
    else:
        log("Using default factory key.", "WARN")

    if "#include <Arduino.h>" not in content:
        content = "#include <Arduino.h>\n" + content
    
    dest_ino = paths["sketch_dest"] / f"{PROJECT_DIR_NAME}.ino"
    with open(dest_ino, "w", encoding="utf-8") as f:
        f.write(content)

    # 4. Library Setup
    lib_src = paths["firmware"] / "tft_espi_library"
    lib_dest = paths["sketchbook"] / "libraries" / "TFT_eSPI"
    
    if lib_src.exists():
        if lib_dest.exists(): shutil.rmtree(lib_dest)
        shutil.copytree(lib_src, lib_dest)
        
        user_setup_src = paths["firmware"] / "User_Setup.h"
        if user_setup_src.exists():
            shutil.copy(user_setup_src, lib_dest / "User_Setup.h")
            log("Applied custom User_Setup.h", "SUCCESS")
    else:
        log("Warning: tft_espi_library not found in firmware folder.", "WARN")

    # 5. Compile - Note the explicit --output-dir to avoid artifact confusion
    log("Compiling firmware...", "INFO")
    build_dir = paths["sketch_dest"] / "build"
    build_dir.mkdir(exist_ok=True)
    
    cmd = [
        str(paths["cli_bin"]), "--config-file", str(paths["config"]),
        "compile", "--fqbn", FQBN,
        "--output-dir", str(build_dir),
        str(paths["sketch_dest"])
    ]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        log("Compilation failed.", "ERROR")
        return

    # 6. Export Binaries
    paths["output"].mkdir(exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H%M")
    mode_str = "secure" if secure_mode else "compat"
    
    # Artifact names as generated by arduino-cli in the build folder
    artifacts = {
        f"{PROJECT_DIR_NAME}.ino.bootloader.bin": f"bootloader_{timestamp}_{mode_str}.bin",
        f"{PROJECT_DIR_NAME}.ino.partitions.bin": f"partition-table_{timestamp}_{mode_str}.bin",
        f"{PROJECT_DIR_NAME}.ino.bin": f"{PROJECT_DIR_NAME}_{timestamp}_{mode_str}.bin"
    }

    success_count = 0
    for src, dest in artifacts.items():
        src_path = build_dir / src
        if src_path.exists():
            shutil.copy(src_path, paths["output"] / dest)
            success_count += 1
        else:
            log(f"Missing artifact: {src}", "ERROR")
    
    if success_count == 3:
        log(f"Build complete. Artifacts saved to '{OUTPUT_DIR_NAME}'", "SUCCESS")
        # Cleanup temporary sketch directory
        shutil.rmtree(paths["sketch_dest"])
    else:
        log("Build finished but some artifacts were missing.", "WARN")
    
    input("\nPress Enter to return to menu...")

# --- ACTION: FLASH ---

def action_flash(paths):
    clear_screen()
    print("--- FLASH MODE ---")
    
    setup_arduino_cli(paths) 
    esptool_path = find_esptool(paths)
    if not esptool_path:
        log("esptool not found. Please run Compile first to install dependencies.", "ERROR")
        input("Press Enter...")
        return

    log("Detecting Serial Ports...", "INFO")
    res = subprocess.run(
        [str(paths["cli_bin"]), "--config-file", str(paths["config"]), "board", "list"], 
        capture_output=True, text=True
    )
    
    ports = []
    lines = res.stdout.splitlines()
    print("\nAvailable Ports:")
    idx = 1
    for line in lines:
        if "USB" in line or "COM" in line or "tty" in line:
            parts = line.split()
            if len(parts) > 0:
                port_name = parts[0]
                if port_name == "Port" or port_name == "Address": continue
                print(f"[{idx}] {port_name}")
                ports.append(port_name)
                idx += 1
    
    if not ports:
        print("No ports detected automatically.")
        selected_port = input("Enter port name manually (e.g., COM3 or /dev/ttyUSB0): ").strip()
    else:
        sel = input("\nSelect Port Number [1] or enter manual: ").strip()
        if not sel: sel = "1"
        if sel.isdigit() and 1 <= int(sel) <= len(ports):
            selected_port = ports[int(sel)-1]
        else:
            selected_port = sel

    if not paths["output"].exists():
        log("No output directory found. Compile firmware first.", "ERROR")
        input("Press Enter...")
        return

    files = list(paths["output"].glob("*.bin"))
    groups = {}
    
    # Use regex to identify timestamped sets in the output folder
    for f in files:
        match = re.search(r'_(\d{4}-\d{2}-\d{2}_\d{4}_(?:secure|compat))\.bin$', f.name)
        if match:
            suffix = match.group(1)
            if suffix not in groups: groups[suffix] = {}
            if "bootloader" in f.name: groups[suffix]["boot"] = f
            elif "partition-table" in f.name: groups[suffix]["part"] = f
            elif PROJECT_DIR_NAME in f.name: groups[suffix]["app"] = f

    valid_suffixes = [s for s, files in groups.items() if len(files) == 3]
    valid_suffixes.sort(reverse=True)

    if not valid_suffixes:
        log("No valid firmware sets found in output.", "ERROR")
        input("Press Enter...")
        return

    print("\nAvailable Firmware Builds:")
    for i, suffix in enumerate(valid_suffixes):
        print(f"[{i+1}] {suffix}")
    
    sel = input("\nSelect Build [1]: ").strip()
    if not sel: sel = "1"
    
    try:
        chosen_suffix = valid_suffixes[int(sel)-1]
        group = groups[chosen_suffix]
    except (IndexError, ValueError):
        log("Invalid selection.", "ERROR")
        return

    print("\n" + "="*50)
    print("PREPARE YOUR BOARD")
    print("1. Press and HOLD the BOOT button.")
    print("2. Press and RELEASE the RESET (EN) button.")
    print("3. Release the BOOT button.")
    print("="*50 + "\n")
    input("Press Enter to ERASE and FLASH...")

    esptool_cmd = [str(esptool_path)] if str(esptool_path).endswith(".exe") else [sys.executable, str(esptool_path)]
    base_args = ["--chip", "esp32", "--port", selected_port, "--baud", BAUD_RATE]

    try:
        log("Erasing Flash...", "WARN")
        subprocess.run(esptool_cmd + base_args + ["erase_flash"], check=True)
        
        log("Writing Firmware...", "WARN")
        flash_args = [
            "--before", "default_reset", "--after", "hard_reset", "write_flash", "-z",
            ADDR_BOOTLOADER, str(group["boot"]),
            ADDR_PARTITIONS, str(group["part"]),
            ADDR_APP, str(group["app"])
        ]
        
        subprocess.run(esptool_cmd + base_args + flash_args, check=True)
        log("Flashing Complete! Press RESET on the board.", "SUCCESS")
        
    except subprocess.CalledProcessError as e:
        log(f"Flashing failed: {e}", "ERROR")
    
    input("\nPress Enter to return to menu...")

# --- MAIN MENU ---

def main():
    paths = get_paths()
    
    while True:
        clear_screen()
        print("========================================")
        print("   ESP32 TOOL (Project Root Version)")
        print("========================================")
        print(f"OS: {platform.system()} | Tools: {'Ready' if paths['cli_bin'].exists() else 'Missing'}")
        print("----------------------------------------")
        print("1. Compile Firmware (Builds binaries)")
        print("2. Flash Firmware   (Writes to device)")
        print("3. Exit")
        print("----------------------------------------")
        
        choice = input("Select Option: ").strip()
        
        if choice == "1":
            action_compile(paths)
        elif choice == "2":
            action_flash(paths)
        elif choice == "3":
            sys.exit(0)
        else:
            input("Invalid choice. Press Enter...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)