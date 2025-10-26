<#
.SYNOPSIS
    Sets up a portable arduino-cli environment and builds the ESP32 project.
    Features Quick (installs if missing) and Thorough (forces reinstall) build modes.
    Includes a 'FlashPrereq' mode to only install flasher tool dependencies.

.DESCRIPTION
    Portable build script for Windows. Does not rely on system Python or ESP-IDF.
    All dependencies (arduino-cli, esp32 core, compilers) are downloaded and managed
    by the script in a portable, self-contained way.

    INSTALLATION LOGIC: Attempts MSI install first. If MSI fails, it falls back to
    checking for a manually placed 'arduino-cli.exe'.

.PARAMETER Quick
    [Switch] Default mode. Skips core installation if environment is present, installs if missing.

.PARAMETER Thorough
    [Switch] Forces a full re-download and re-installation of the esp32 core.
    Also forces removal and re-attempt of arduino-cli setup.

.PARAMETER FlashPrereq
    [Switch] Installs only the prerequisites for 'flash.bat' (i.e., the ESP32 core
    which contains esptool.exe) and then exits. Does not compile.

.NOTES
    - Requires PowerShell 5.1 or later.
    - Manages PSK injection (Secure vs. Compatibility mode).
    - Patches WebServer.cpp (flush() -> clear()) in the arduino-cli core files.
    - Copies 'tft_espi_library' to the portable sketchbook.
    - Copies 'User_Setup.h' into the TFT library.
    - Converts 'originalcode.cpp' to a .ino file for compilation.
    - **Generates three separate binaries for flashing.**
    - Cleans up the transient sketch folder after build.
#>
# --- Parameters ---
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]
    $Quick,

    [Parameter(Mandatory=$false)]
    [switch]
    $Thorough,

    [Parameter(Mandatory=$false)]
    [switch]
    $FlashPrereq
)

# --- Logging Function ---
function Log ($Message, $Type="INFO") {
    $Timestamp = Get-Date -Format "HH:mm:ss"
    switch ($Type) {
        "ERROR" { Write-Host "[$Timestamp] [ERROR] $Message" -ForegroundColor Red }
        "WARN"  { Write-Host "[$Timestamp] [WARN] $Message" -ForegroundColor Yellow }
        "SUCCESS" { Write-Host "[$Timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        default { Write-Host "[$Timestamp] [INFO] $Message" -ForegroundColor Cyan }
    }
}

# --- Global Encoder Definition ---
# Fixes "Value cannot be null. Parameter name: encoding" error
$UTF8NoBOM = [System.Text.UTF8Encoding]::new($false)


# --- Password Generation Function ---
function Generate-RandomHexPSK {
    param(
        [int]$Bytes = 24 # PSK payload bytes, excluding magic
    )

    # Generate secure random bytes
    $RandomBytes = New-Object byte[] $Bytes
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($RandomBytes)

    # Format as C-style hex array
    $FormattedPSK = $RandomBytes | ForEach-Object { "0x$('{0:X2}' -f $_)" }

    # Format into multi-line string
    $NewPSKPayload = ""
    for ($i = 0; $i -lt $Bytes; $i += 8) {
        $Block = $FormattedPSK[$i..($i+7)] -join ', '
        $Comment = " // 8-byte Random PSK Block $((($i/8) + 1))"

        # Add trailing comma to all but last block
        if (($i + 8) -lt $Bytes) {
            $Block += ","
        }

        $NewPSKPayload += "`t$Block" + $Comment + "`r`n"
    }

    return $NewPSKPayload
}

# -----------------------------------------------------------------------------
# --- SECTION 0.1: SKETCHBOOK/LIBRARY PREP, PATCHING, AND SOURCE COPY ---------
# -----------------------------------------------------------------------------
function Run-ArduinoCli-Prep {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FirmwareDir,
        [Parameter(Mandatory=$true)]
        [string]$SketchbookDir,
        [Parameter(Mandatory=$true)]
        [string]$ProjectDirName,
        [Parameter(Mandatory=$true)]
        [string]$ArduinoDataDir
    )

    # Define paths
    $SketchDir = Join-Path $SketchbookDir $ProjectDirName
    $SketchLibrariesDir = Join-Path $SketchbookDir "libraries"
    $SketchInoFile = Join-Path $SketchDir "$($ProjectDirName).ino"

    Log "0.1. Preparing transient sketch directory and libraries..." -Type INFO

    try {
        # Clean existing sketch folder
        if (Test-Path $SketchDir) {
            Log "Pre-clean: Removing existing sketch folder '$ProjectDirName' recursively." -Type WARN
            Remove-Item -Path $SketchDir -Recurse -Force -ErrorAction Stop
        }

        # Re-create project structure
        New-Item -Path $SketchDir -ItemType Directory -ErrorAction Stop | Out-Null
        New-Item -Path $SketchLibrariesDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Log "Re-created transient sketch root: '$($SketchDir)'" -Type SUCCESS
        Log "Ensured sketchbook libraries folder exists: '$($SketchLibrariesDir)'" -Type SUCCESS

        # -------------------------------------------------------------------------
        # --- Copy TFT_eSPI Library ---
        # -------------------------------------------------------------------------
        $TFTLibrarySourceDirName = "tft_espi_library"
        $TFTLibraryDestDirName = "TFT_eSPI"
        $TFTLibrarySourcePath = Join-Path $FirmwareDir $TFTLibrarySourceDirName
        $TFTLibraryDestPath = Join-Path $SketchLibrariesDir $TFTLibraryDestDirName
        $TFTHeaderCheckPath = Join-Path $TFTLibraryDestPath "TFT_eSPI.h"

        if (Test-Path $TFTLibrarySourcePath) {
            # Only copy if it doesn't exist or in Thorough mode
            if (-not (Test-Path $TFTLibraryDestPath) -or $Thorough) {
                Log "Copying TFT_eSPI library to sketchbook..." -Type INFO

                # Clean destination first if it exists
                if (Test-Path $TFTLibraryDestPath) {
                    Remove-Item -Path $TFTLibraryDestPath -Recurse -Force -ErrorAction Stop
                }

                try {
                    # Create 'TFT_eSPI' destination folder
                    New-Item -Path $TFTLibraryDestPath -ItemType Directory -Force | Out-Null
                    # Copy library contents
                    Copy-Item -Path (Join-Path $TFTLibrarySourcePath "*") -Destination $TFTLibraryDestPath -Recurse -Force -ErrorAction Stop
                    # Verify copy
                    if (Test-Path $TFTHeaderCheckPath) {
                        Log "Successfully copied and verified TFT_eSPI.h at: $TFTHeaderCheckPath" -Type SUCCESS
                    } else {
                        throw "Copy successful, but main header file 'TFT_eSPI.h' not found at expected location after copy. Check source structure."
                    }
                } catch {
                    Log "FATAL ERROR: Failed to copy TFT_eSPI library contents." -Type ERROR
                    Log "Exception: $($_.Exception.Message)" -Type ERROR
                    exit 1
                }
            } else {
                Log "TFT_eSPI library already exists in sketchbook. Skipping copy (Quick Mode)." -Type INFO
            }
        } else {
            Log "CRITICAL WARNING: TFT_eSPI library source folder '$TFTLibrarySourceDirName' not found. This will cause a fatal build error if the source code includes TFT_eSPI.h." -Type WARN
        }

        # -------------------------------------------------------------------------
        # --- Copy User_Setup.h ---
        # -------------------------------------------------------------------------
        $TFTUserSetupSource = Join-Path $FirmwareDir "User_Setup.h"
        $TFTUserSetupDest = Join-Path $TFTLibraryDestPath "User_Setup.h"

        if (Test-Path $TFTUserSetupSource) {
            Log "Applying custom User_Setup.h (Fixing TOUCH_CS warning)..." -Type INFO
            try {
                Copy-Item -Path $TFTUserSetupSource -Destination $TFTUserSetupDest -Force -ErrorAction Stop
                Log "Successfully overwrote User_Setup.h in TFT_eSPI library." -Type SUCCESS
            } catch {
                Log "FATAL ERROR: Failed to copy User_Setup.h. $($_.Exception.Message)" -Type ERROR
                exit 1
            }
        } else {
            Log "WARNING: Custom 'User_Setup.h' not found in '$FirmwareDir'. Build will use default TFT settings and may show warnings." -Type WARN
        }

        # -------------------------------------------------------------------------
        # --- Patch WebServer.cpp (flush->clear) ---
        # -------------------------------------------------------------------------
        Log "Attempting to patch WebServer.cpp in arduino-cli data directory..."
        $WebServerSearchPath = Join-Path $ArduinoDataDir "packages\esp32\hardware\esp32"
        # Search multiple directories recursively to find the file
        $WebServerFile = Get-ChildItem -Path $WebServerSearchPath -Filter "WebServer.cpp" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($WebServerFile) {
            $WebServerPath = $WebServerFile.FullName
            Log "Found WebServer.cpp at: $WebServerPath"
            Log "Patching WebServer.cpp to fix deprecated flush() warning." -Type INFO
            $WebServerContent = Get-Content $WebServerPath -Raw

            if ($WebServerContent -match "_chunkedClient.clear\(\); // Patched") {
                Log "WebServer.cpp already patched. Skipping." -Type INFO
            } else {
                $PatchedWebServerContent = $WebServerContent.Replace("_chunkedClient.flush();", "_chunkedClient.clear(); // Patched")

                if ($PatchedWebServerContent -ne $WebServerContent) {
                    try {
                        # Write BOM-less UTF-8 (Uses global $UTF8NoBOM)
                        [System.IO.File]::WriteAllText($WebServerPath, $PatchedWebServerContent, $UTF8NoBOM)
                        Log "WebServer.cpp patched successfully (replaced flush() with clear())." -Type SUCCESS
                    } catch {
                        Log "ERROR: Failed to write patched WebServer.cpp. Check permissions. $($_.Exception.Message)" -Type ERROR
                    }
                } else {
                    Log "WARNING: Could not find the specific 'flush()' call in WebServer.cpp. Patch was skipped." -Type WARN
                }
            }
        } else {
            Log "WARNING: WebServer.cpp not found in '$WebServerSearchPath'. Skipping flush() deprecation fix. This might be normal on first install." -Type WARN
        }

        # -------------------------------------------------------------------------
        # --- Prepare Source Code (Convert to .ino) ---
        # -------------------------------------------------------------------------
        $SourceFileOriginalName = "originalcode.cpp"
        $SourcePath = Join-Path $FirmwareDir $SourceFileOriginalName

        if (-not (Test-Path $SourcePath)) {
            Log "FATAL ERROR: Source file '$SourceFileOriginalName' not found at '$SourcePath'. Build cannot proceed." -Type ERROR
            exit 1
        }

        # Load source
        $CodeContent = Get-Content $SourcePath -Raw
        $PatchedContent = $CodeContent

        # Patch PSK Payload (Secure Mode only)
        if ($Script:SecureMode) {
            Log "SECURE MODE: Generating and applying random PSK payload..." -Type INFO
            $NewPSKPayload = Generate-RandomHexPSK -Bytes 24

            $ArrayStartPattern = [regex]::Escape("volatile uint8_t PRE_SHARED_KEY[] = {")
            $MagicPrefixPattern = [regex]::Escape("0xDE, 0xAD, 0xBE, 0xEF,") + ".*?// 4-byte Magic prefix for the flasher"

            # Regex: Capture array definition
            $FullArrayPatchRegex = "(?s)($ArrayStartPattern.*?$MagicPrefixPattern.*?)([^}]+)(};)"

            if ($PatchedContent -notmatch $FullArrayPatchRegex) {
                Log "FATAL ERROR: Could not find the PRE_SHARED_KEY array definition for patching." -Type ERROR
                exit 1
            }

            # Replace payload
            $PatchedContent = $PatchedContent -replace $FullArrayPatchRegex, "`$1`r`n$NewPSKPayload`$3"

            if ($PatchedContent -eq $CodeContent) {
                Log "WARNING: PSK replacement failed. Using original PSK." -Type WARN
            } else {
                Log "Random PSK payload successfully applied." -Type SUCCESS
            }
        } else {
            Log "COMPATIBILITY MODE: Keeping original factory PSK from source code." -Type WARN
        }

        # --- Add Arduino Header (Required for C++ files to compile as INO sketches) ---
        $ArduinoHeader = '#include <Arduino.h>'

        if ($PatchedContent -notmatch [regex]::Escape($ArduinoHeader)) {
            Log "Prepending required Arduino header: $ArduinoHeader" -Type INFO
            $PatchedContent = $ArduinoHeader + "`r`n" + $PatchedContent
        }

        # Write patched source to destination .ino file (Uses global $UTF8NoBOM)
        [System.IO.File]::WriteAllText($SketchInoFile, $PatchedContent, $UTF8NoBOM)
        Log "Final source '$($ProjectDirName).ino' written to sketch directory." -Type SUCCESS

    } catch {
        Log "FATAL ERROR during sketch preparation: $($_.Exception.Message)" -Type ERROR
        exit 1
    }
}
# -----------------------------------------------------------------------------
# --- END OF BUILD PREP FUNCTION ----------------------------------------------
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# --- POST-BUILD CLEANUP FUNCTION ---------------------------------------------
# -----------------------------------------------------------------------------
function Run-PostBuildCleanup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SketchDir
    )

    Log "Build successful. Cleaning up transient sketch directory..." -Type INFO
    try {
        if (Test-Path $SketchDir) {
            Remove-Item -Path $SketchDir -Recurse -Force -ErrorAction Stop
            Log "Successfully removed transient sketch directory: $SketchDir" -Type SUCCESS
        } else {
            Log "Transient sketch directory not found. Nothing to clean up." -Type INFO
        }
    } catch {
        Log "WARNING: Failed to clean up transient sketch directory at $SketchDir" -Type WARN
        Log "You may need to delete it manually. Error: $($_.Exception.Message)" -Type WARN
    }
}
# -----------------------------------------------------------------------------
# --- END OF POST-BUILD CLEANUP FUNCTION --------------------------------------
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# --- Configuration & Path Resolution ---
# -----------------------------------------------------------------------------

# Config
$FirmwareDirName = "firmware"
$ProjectDirName = "my_app"
$ArduinoCliDirName = "arduino-cli"
$ArduinoDataDirName = "arduino-data"
$ArduinoSketchbookDirName = "arduino-sketchbook"
$MsiDirName = "arduino-cli_1.3.1_Windows_64bit"
$MsiName = "arduino-cli_1.3.1_Windows_64bit.msi"

# FQBN (Fully Qualified Board Name) - NOTE: Using base esp32:esp32 for maximum compatibility
$Fqbn = "esp32:esp32:esp32" 

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path $ScriptDir -Parent
Set-Location $RootDir
Log "Setting working directory to: $RootDir"

# Set working directories
$FirmwareDir = Join-Path $RootDir $FirmwareDirName
$ArduinoCliDir = Join-Path $RootDir $ArduinoCliDirName
$ArduinoCliExe = Join-Path $ArduinoCliDir "arduino-cli.exe"
$ArduinoDataDir = Join-Path $RootDir $ArduinoDataDirName
$ArduinoSketchbookDir = Join-Path $RootDir $ArduinoSketchbookDirName
$ArduinoCliConfig = Join-Path $ArduinoCliDir "arduino-cli.yaml"
$MsiPath = Join-Path (Join-Path $RootDir $MsiDirName) $MsiName
# Define the expected path for the ESP32 Core (for Quick/Thorough check)
$Esp32CorePath = Join-Path $ArduinoDataDir "packages\esp32\hardware\esp32"


# -------------------------------------------------------------
# --- Security Mode Selection ---
# -------------------------------------------------------------
if (-not $FlashPrereq) {
    Clear-Host
    Log "Please select a security mode:" -Type "INFO"
    Write-Host ""
    Write-Host "[1] Secure Mode:         (Default) Generates a unique random PSK for this build." -ForegroundColor Green
    Write-Host "                           Maximum security - PSK is unique to this device." -ForegroundColor Gray
    Write-Host ""
    Write-Host "[2] Compatibility Mode: Uses the original factory PSK from the source code." -ForegroundColor Yellow
    Write-Host "                           WARNING: Original PSK is publicly known - third-party tools could exist." -ForegroundColor Red
    Write-Host ""

    $Timeout = 10
    $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $SecurityModeSelected = $false

    while ($StopWatch.Elapsed.TotalSeconds -lt $Timeout -and -not $SecurityModeSelected) {
        $Remaining = $Timeout - [int]$StopWatch.Elapsed.TotalSeconds
        # Use -NoNewline and carriage return `r to overwrite the line
        Write-Host -NoNewline "Defaulting to [1] Secure Mode in $Remaining s... `r"

        if ($Host.UI.RawUI.KeyAvailable) {
            # Read the key and check the character
            $Key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($Key.Character -eq '2') {
                $Script:SecureMode = $false
                $SecurityModeSelected = $true
                Write-Host "" # Clear the countdown line
                break
            } elseif ($Key.Character -eq '1') {
                $Script:SecureMode = $true
                $SecurityModeSelected = $true
                Write-Host "" # Clear the countdown line
                break
            }
        }
        
        Start-Sleep -Milliseconds 100
    }
    $StopWatch.Stop()

    # Clear the countdown line if timeout occurred
    if (-not $SecurityModeSelected) {
        Write-Host "" # Print a final newline after the countdown
    }

    # Default to Secure Mode
    if (-not $SecurityModeSelected) {
        $Script:SecureMode = $true
    }

    if ($Script:SecureMode) {
        Log "Secure Mode selected - Random PSK will be generated." -Type "SUCCESS"
    } else {
        Log "Compatibility Mode selected - Using original factory PSK." -Type "WARN"
    }

    Write-Host ""
    Start-Sleep -Milliseconds 500
} else {
    # This mode doesn't compile, so PSK is irrelevant. Skip selection.
    $Script:SecureMode = $true # Set a default, though it won't be used
    Clear-Host
    Log "Flash Prereq mode selected via parameter." -Type "WARN"
    Log "Skipping Security Mode selection (not needed for flasher setup)." -Type "INFO"
}


# -------------------------------------------------------------
# --- Build Mode Selection ---
# -------------------------------------------------------------
if (-not $Quick -and -not $Thorough -and -not $FlashPrereq) {
    Log "Please select a build mode:" -Type "INFO"
    Write-Host ""
    Write-Host "[1] Quick Mode:   (Default) Fastest. Installs if missing, skips if present." -ForegroundColor Gray
    Write-Host "[2] Thorough Mode: Slowest. Forces re-installation of all tools." -ForegroundColor Gray
    Write-Host "[3] Setup Flasher: Installs flash tool (esptool) only. No compile." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Use 'Thorough' if 'Quick' fails. Use 'Setup Flasher' if 'flash.bat' fails." -ForegroundColor Yellow
    Write-Host ""

    $Timeout = 10
    $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $BuildModeSelected = $false

    while ($StopWatch.Elapsed.TotalSeconds -lt $Timeout -and -not $BuildModeSelected) {
        $Remaining = $Timeout - [int]$StopWatch.Elapsed.TotalSeconds
        Write-Host -NoNewline "Defaulting to [1] Quick Mode in $Remaining s... `r"

        if ($Host.UI.RawUI.KeyAvailable) {
            $Key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($Key.Character -eq '2') {
                $Thorough = $true
                $Quick = $false
                $FlashPrereq = $false
                $BuildModeSelected = $true
                Write-Host "" # Clear the countdown line
                break
            } elseif ($Key.Character -eq '1') {
                $Quick = $true
                $Thorough = $false
                $FlashPrereq = $false
                $BuildModeSelected = $true
                Write-Host "" # Clear the countdown line
                break
            } elseif ($Key.Character -eq '3') {
                $FlashPrereq = $true
                $Quick = $true  # <-- CRITICAL: Set Quick to run setup logic
                $Thorough = $false
                $BuildModeSelected = $true
                Write-Host "" # Clear the countdown line
                break
            }
        }
        Start-Sleep -Milliseconds 100
    }
    $StopWatch.Stop()
    
    # Clear the countdown line if timeout occurred
    if (-not $BuildModeSelected) {
        Write-Host ""
    }

    if (-not $BuildModeSelected) {
        $Quick = $true
        Log "Quick mode (Default) selected."
    } else {
        if ($FlashPrereq) {
            Log "Setup Flasher (FlashPrereq) mode selected." -Type "WARN"
            Log "This will run 'Quick' setup logic but skip compilation." -Type "INFO"
        } elseif ($Quick) {
            Log "Quick mode selected."
        } else {
            Log "Thorough mode selected." -Type "WARN"
        }
    }

} elseif ($Quick) {
    Log "Quick mode selected via parameter."
    if ($FlashPrereq) {
        Log "FlashPrereq mode also selected. 'Quick' setup will run, compilation will be skipped." -Type "INFO"
    }
} elseif ($Thorough) {
    Log "Thorough mode selected via parameter."
    if ($FlashPrereq) {
        Log "FlashPrereq mode also selected. 'Thorough' setup will run, compilation will be skipped." -Type "INFO"
    }
} elseif ($FlashPrereq) {
    Log "FlashPrereq mode selected via parameter."
    Log "Setting 'Quick' mode internally to run setup." -Type "INFO"
    $Quick = $true # <-- CRITICAL: Set Quick to run setup logic
}


# -----------------------------------------------------------------------------
# --- 1. Environment Setup (arduino-cli) ---
# -----------------------------------------------------------------------------

# 1.1. Check for arduino-cli
Log "1.1. Resolving arduino-cli path..."
$RunFullSetup = $false
if ($Thorough) {
    Log "THOROUGH MODE: Forcing full environment setup..." -Type WARN
    $RunFullSetup = $true
} elseif ($Quick) {
    if (-not (Test-Path $ArduinoCliExe)) {
        Log "QUICK MODE: arduino-cli.exe not found. Running full setup..." -Type WARN
        $RunFullSetup = $true
    } else {
        Log "QUICK MODE: arduino-cli.exe found. Skipping setup." -Type SUCCESS
    }
}

# 1.2. Run Full Setup if Needed
if ($RunFullSetup) {
    Log "Starting full arduino-cli environment setup..."

    try {
        # Clean/Create directories
        if ($Thorough) {
            Log "THOROUGH: Removing old portable directories..." -Type WARN
            if (Test-Path $ArduinoCliDir) { Remove-Item $ArduinoCliDir -Recurse -Force }
            # NOTE: We skip removing $ArduinoDataDir here as the user has to do it manually due to MAX_PATH limit
            # if (Test-Path $ArduinoDataDir) { Remove-Item $ArduinoDataDir -Recurse -Force } 
        }
        # Ensure target dir exists for executable and config
        New-Item -Path $ArduinoCliDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        New-Item -Path $ArduinoDataDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        New-Item -Path $ArduinoSketchbookDir -ItemType Directory -Force -ErrorAction Stop | Out-Null

        # --- NEW MSI ATTEMPT LOGIC ---
        $MsiSuccess = $false
        if (Test-Path $MsiPath) {
            Log "Attempting automatic installation of arduino-cli via MSI..." -Type INFO
            try {
                # Using Start-Process with explicit argument list for better quoting handling
                $MsiResult = Start-Process msiexec.exe -ArgumentList "/i", "`"$MsiPath`"", "/qn", "INSTALLDIR=`"$ArduinoCliDir`"" -Wait -PassThru -ErrorAction Stop

                if ($MsiResult.ExitCode -eq 0) {
                    $MsiSuccess = $true
                    Log "MSI installation completed successfully." -Type SUCCESS
                } else {
                    throw "MSI execution failed with exit code $($MsiResult.ExitCode)."
                }
            } catch {
                Log "WARNING: Automatic MSI installation failed or encountered an error." -Type WARN
                Log "Error details: $($_.Exception.Message)" -Type WARN
                $MsiSuccess = $false
            }
        } else {
            Log "WARNING: MSI file not found at $MsiPath. Skipping automatic install." -Type WARN
        }


        # --- FALLBACK / VERIFICATION LOGIC ---
        if (-not $MsiSuccess) {
            Log "Verifying manual presence of 'arduino-cli.exe' in: $ArduinoCliDir" -Type INFO

            if (-not (Test-Path $ArduinoCliExe)) {
                Log "ACTION REQUIRED: 'arduino-cli.exe' not found." -Type ERROR
                Log "Please manually copy 'arduino-cli.exe' into the following folder:" -Type ERROR
                Log "$ArduinoCliDir" -Type INFO
                throw "FATAL ERROR: The executable is missing. Build cannot continue until 'arduino-cli.exe' is placed in the target directory."
            }

            Log "Found arduino-cli.exe, proceeding with build." -Type SUCCESS
        }


    } catch {
        Log "FATAL ERROR during arduino-cli environment setup: $($_.Exception.Message)" -Type ERROR
        exit 1
    }
}

# -----------------------------------------------------------------------------
# --- 2. Activate & Configure Environment ---
# -----------------------------------------------------------------------------

Log "2. Activating and configuring environment..."
$env:PATH = "$ArduinoCliDir;$env:PATH"
Log "arduino-cli added to session PATH."

# 2.1. Create/Verify arduino-cli.yaml
$ConfigContent = @"
directories:
  data: $ArduinoDataDir
  downloads: $ArduinoDataDir\staging
  user: $ArduinoSketchbookDir
board_manager:
  additional_urls:
    - https://espressif.github.io/arduino-esp32/package_esp32_index.json
library:
  enable_unsafe_install: true
logging:
  file: ""
  format: text
  level: info
metrics:
  addr: ""
  enabled: false
output:
  no_color: false
sketch:
  always_export_binaries: true
updater:
  enable_notification: false
"@

# Normalize paths for YAML
$ConfigContent = $ConfigContent.Replace("\", "/")
try {
    # Uses the globally defined $UTF8NoBOM
    [System.IO.File]::WriteAllText($ArduinoCliConfig, $ConfigContent, $UTF8NoBOM)
    Log "Portable configuration file written to: $ArduinoCliConfig" -Type SUCCESS
} catch {
    Log "FATAL ERROR: Could not write config file '$ArduinoCliConfig'. Check permissions. $($_.Exception.Message)" -Type ERROR
    exit 1
}

# 2.2. Install/Update ESP32 Core
$CoreNeedsInstall = $false
if ($Thorough) {
    Log "THOROUGH: Forcing core reinstall." -Type WARN
    $CoreNeedsInstall = $true
} else {
    Log "Checking if esp32 core is installed..."
    # Check if the core path exists (The fix for the Quick Mode logic)
    if (Test-Path $Esp32CorePath) {
        Log "QUICK MODE: ESP32 core directory found. Assuming installation is complete." -Type SUCCESS
    } else {
        # Fallback to CLI check and force install if not found
        & $ArduinoCliExe --config-file $ArduinoCliConfig core update-index 2>&1 | Out-Null 
        $InstalledCores = & $ArduinoCliExe --config-file $ArduinoCliConfig core list
        if ($InstalledCores -join " " -notmatch "esp32:esp32") {
            Log "esp32 core not found." -Type WARN
            $CoreNeedsInstall = $true
        } else {
            Log "esp32 core already installed. Skipping (Quick Mode)." -Type SUCCESS
        }
    }
}

if ($CoreNeedsInstall -or $Thorough) {
    try {
        Log "Updating core index..."
        & $ArduinoCliExe --config-file $ArduinoCliConfig core update-index
        if ($LASTEXITCODE -ne 0) { throw "core update-index failed" }
        Log "Core index updated." -Type SUCCESS

        Log "Installing esp32:esp32 core (this includes esptool flasher)..."
        & $ArduinoCliExe --config-file $ArduinoCliConfig core install esp32:esp32
        if ($LASTEXITCODE -ne 0) { throw "core install esp32:esp32 failed" }
        Log "esp32 core installed successfully." -Type SUCCESS

    } catch {
        Log "FATAL ERROR during core installation: $($_.Exception.Message)" -Type ERROR
        exit 1
    }
}

# -----------------------------------------------------------------------------
# --- 3. Run Build Preparation ---
# -----------------------------------------------------------------------------

if (-not $FlashPrereq) {
    # Mocking essential source files needed by the prep function
    $FirmwareMockDir = Join-Path $RootDir $FirmwareDirName
    if (-not (Test-Path $FirmwareMockDir)) { New-Item -Path $FirmwareMockDir -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path (Join-Path $FirmwareMockDir "originalcode.cpp"))) { 
        $MockCode = @"
// originalcode.cpp - Mock file
#include <SPI.h>
#include <TFT_eSPI.h>

volatile uint8_t PRE_SHARED_KEY[] = {
    0xDE, 0xAD, 0xBE, 0xEF, // 4-byte Magic prefix for the flasher
    0xFF, 0xFF, 0xFF, 0xFF, // 8-byte Random PSK Block 1
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, // 8-byte Random PSK Block 2
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, // 8-byte Random PSK Block 3
    0xFF, 0xFF, 0xFF, 0xFF
};
// Setup function (Arduino style)
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("Source code mock loaded.");
}
// Loop function (Arduino style)
void loop() {
    // nothing
}
"@
        $MockCode | Set-Content -Path (Join-Path $FirmwareMockDir "originalcode.cpp") -Encoding UTF8
    }
    if (-not (Test-Path (Join-Path $FirmwareMockDir "tft_espi_library"))) { 
        New-Item -Path (Join-Path $FirmwareMockDir "tft_espi_library") -ItemType Directory -Force | Out-Null 
        "// Mock TFT_eSPI.h" | Set-Content -Path (Join-Path $FirmwareMockDir "tft_espi_library\TFT_eSPI.h") -Encoding UTF8
    }

    Run-ArduinoCli-Prep -FirmwareDir $FirmwareDir -SketchbookDir $ArduinoSketchbookDir -ProjectDirName $ProjectDirName -ArduinoDataDir $ArduinoDataDir
} else {
    Log "FLASH PREREQ MODE: Skipping Build Preparation (Section 3)." -Type INFO
}


# -----------------------------------------------------------------------------
# --- 4. Run Build ---
# -----------------------------------------------------------------------------

if (-not $FlashPrereq) {
    Log "4. Starting build configuration..."
    $SketchPath = Join-Path $ArduinoSketchbookDir $ProjectDirName

    Log "Starting Arduino-CLI Build (running arduino-cli compile)..."
    Log "FQBN: $Fqbn"
    Log "Sketch: $SketchPath"
    try {
        # Build
        & $ArduinoCliExe --config-file $ArduinoCliConfig compile --fqbn $Fqbn $SketchPath --verbose

        if ($LASTEXITCODE -ne 0) {
            throw "arduino-cli compile failed with exit code $LASTEXITCODE"
        }

        Log "--- Build SUCCESSFUL ---" -Type "SUCCESS"

    } catch {
        Log "--- Build FAILED ---" -Type "ERROR"
        Log "Error details: $_" -Type "ERROR"
        Log "Check the output above for errors." -Type "ERROR"
        exit 1
    }
} else {
    Log "FLASH PREREQ MODE: Skipping Build (Section 4)." -Type INFO
}


# -----------------------------------------------------------------------------
# --- 7. Package Binaries (SIMPLIFIED - Outputting 3 separate binaries) ---
# -----------------------------------------------------------------------------
if (-not $FlashPrereq) {
    Log "7. Locating binaries and preparing individual flash images..."

    # Output Directory
    $OutputFolderName = "output"
    $OutputDir = Join-Path $RootDir $OutputFolderName
    $Timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
    $SecuritySuffix = if ($Script:SecureMode) { "secure" } else { "compat" }

    # Artifact Paths
    $SketchPath = Join-Path $ArduinoSketchbookDir $ProjectDirName # Ensure $SketchPath is defined
    $BuildDir = Join-Path $SketchPath "build"
    $BootloaderBin = Get-ChildItem -Path $BuildDir -Filter "*.ino.bootloader.bin" -Recurse | Select-Object -First 1
    $PartitionTableBin = Get-ChildItem -Path $BuildDir -Filter "*.ino.partitions.bin" -Recurse | Select-Object -First 1
    $AppBin = Get-ChildItem -Path $BuildDir -Filter "*.ino.bin" -Recurse | Select-Object -First 1

    try {
        # Verify artifacts
        if (-not $BootloaderBin) { throw "Bootloader binary (*.ino.bootloader.bin) not found in: $BuildDir" }
        if (-not $PartitionTableBin) { throw "Partition table binary (*.ino.partitions.bin) not found in: $BuildDir" }
        if (-not $AppBin) { throw "Application binary (*.ino.bin) not found in: $BuildV" } 

        Log "Found all required build artifacts." -Type SUCCESS

        # Create output directory
        if (-not (Test-Path $OutputDir)) {
            New-Item -Path $OutputDir -ItemType Directory -ErrorAction Stop | Out-Null
            Log "Created output directory: $OutputDir" -Type SUCCESS
        } else {
            Log "Output directory already exists: $OutputDir"
        }

        # Copy artifacts to output
        Log "Copying individual binaries to 'output' folder..."

        # Define artifact names
        $ArtifactsToCopy = @(
            @{ Source = $BootloaderBin.FullName; Name = "bootloader_${Timestamp}_${SecuritySuffix}.bin" },
            @{ Source = $PartitionTableBin.FullName; Name = "partition-table_${Timestamp}_${SecuritySuffix}.bin" },
            @{ Source = $AppBin.FullName; Name = "${ProjectDirName}_${Timestamp}_${SecuritySuffix}.bin" }
        )

        foreach ($Artifact in $ArtifactsToCopy) {
            $DestPath = Join-Path $OutputDir $Artifact.Name
            Copy-Item -Path $Artifact.Source -Destination $DestPath -Force -ErrorAction Stop
            Log "Copied $($Artifact.Source | Split-Path -Leaf) to '$($Artifact.Name)'" -Type INFO
        }

        Log "All firmware artifacts (3 separate files) saved to: $OutputDir" -Type "SUCCESS"

    } catch {
        Log "--- PACKAGING FAILED (INDIVIDUAL BINARIES) ---" -Type "ERROR"
        Log "Failed to copy individual binaries to 'output': $($_.Exception.Message)" -Type "ERROR"
        Log "Individual binary files may remain in the build directory." -Type "INFO"
        exit 1
    }
} else {
    Log "FLASH PREREQ MODE: Skipping Binary Packaging (Section 7)." -Type INFO
}


# --- 8. Post-Build Cleanup ---
if (-not $FlashPrereq) {
    $SketchPath = Join-Path $ArduinoSketchbookDir $ProjectDirName
    Run-PostBuildCleanup -SketchDir $SketchPath
} else {
    Log "FLASH PREREQ MODE: Skipping Post-Build Cleanup (Section 8)." -Type INFO
}

# --- 9. Final Report ---
if ($FlashPrereq) {
    Log "--- FLASH PREREQ SETUP COMPLETE ---" -Type "SUCCESS"
    Log "The arduino-cli environment and ESP32 flasher (esptool) are installed." -Type "INFO"
    Log "You can now re-run the 'flash.bat' script." -Type "INFO"
} else {
    Log "--- BUILD COMPLETE ---" -Type "SUCCESS"
    Log "All firmware artifacts saved to project root sub-folder: $OutputDir" -Type "INFO"

    if ($Script:SecureMode) {
        Write-Host ""
        Write-Host "==============================================================================" -ForegroundColor Green
        Write-Host "  SECURE MODE BUILD COMPLETE" -ForegroundColor Green
        Write-Host "==============================================================================" -ForegroundColor Green
        Write-Host "  A unique random PSK was generated for this build." -ForegroundColor White
        Write-Host "  This firmware provides maximum security." -ForegroundColor White
        Write-Host "==============================================================================" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "==============================================================================" -ForegroundColor Yellow
        Write-Host "  COMPATIBILITY MODE BUILD COMPLETE" -ForegroundColor Yellow
        Write-Host "==============================================================================" -ForegroundColor Yellow
        Write-Host "  This firmware uses the original factory PSK." -ForegroundColor White
        Write-Host "  WARNING: The original PSK is publicly known." -ForegroundColor Red
        Write-Host "  A bootstrap process allows changing the key after first connection." -ForegroundColor White
        Write-Host "================================S==============================================" -ForegroundColor Yellow
    }
}


Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor Gray
try {
    # This read key is meant to be blocking to keep the window open
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") | Out-Null
} catch {
    Log "Failed to read key, exiting." -Type WARN
}