@echo off
setlocal enableextensions enabledelayedexpansion
cd /d "%~dp0"
:: ######################################################
:: #         ESP32 INTERACTIVE FIRMWARE FLASHER         #
:: #       REVISED FOR SMART VERSIONED MULTI-FILE FLASH
:: # (This script must be placed in a subdirectory, e.g., ./scripts/)\
:: # (Firmware files MUST be in the PARENT's 'output' subdirectory, e.g., ../output/)
:: ######################################################

:: --- 1. CONFIGURATION ---
set "BAUD_RATE=460800"
set "CHIP_TYPE=esp32"

:: Define the firmware file path: ..\output
set "FIRMWARE_PATH=..\output"
:: Using a separate temp file for the helper script
set "HELPER_SCRIPT_FILE=%TEMP%\esptool_run_helper.bat"

:: Define the required file prefixes
set "APP_PREFIX=my_app"
set "BOOTLOADER_PREFIX=bootloader"
set "PARTITIONS_PREFIX=partition-table"

echo.
echo Initializing ESP Flasher...
echo.

:: --- 2. LOCATE PORTABLE ESPTOOL (UNCHANGED) ---
echo Locating esptool.exe in portable arduino-data...

set "ESPTOOL_BASE_DIR=..\arduino-data\packages\esp32\tools\esptool_py"
set "ESPTOOL_EXE="

if not exist "%ESPTOOL_BASE_DIR%" (
    goto :TOOL_NOT_FOUND
)

pushd "%ESPTOOL_BASE_DIR%" 2>nul
if errorlevel 1 goto :TOOL_NOT_FOUND_PUSH

for /f "delims=" %%D in ('dir /b /a:d /od- 2^>nul') do (
    if exist "%%D\esptool.exe" (
        set "ESPTOOL_EXE=%ESPTOOL_BASE_DIR%\%%D\esptool.exe"
        goto :FOUND_AND_POPD
    )
)

goto :TOOL_NOT_FOUND_LOOP

:TOOL_NOT_FOUND_PUSH
    echo [CRITICAL ERROR] Failed to access ESP tool path: "%ESPTOOL_BASE_DIR%"
    pause
    goto :END_SCRIPT

:TOOL_NOT_FOUND_LOOP
    
popd
    goto :TOOL_NOT_FOUND

:FOUND_AND_POPD
popd 2>nul
goto :TOOL_CHECK

:TOOL_NOT_FOUND
:: This is where we land if the file was never found
:TOOL_CHECK
if not defined ESPTOOL_EXE (
    echo [CRITICAL ERROR] esptool.exe was not found!
    echo.
    echo Searched path pattern: "%ESPTOOL_BASE_DIR%\<version_folder>\esptool.exe"
    echo Please ensure the ESP32 core tools are installed correctly under arduino-data.
    echo.
    echo [ACTION REQUIRED] Run the 'compile.ps1' script to install the flasher tool.
    echo.
    echo.
    echo [FAILURE] Press any key to exit...
    pause
    goto :END_SCRIPT
)

echo Found esptool at: !ESPTOOL_EXE!
echo.


:: NEW CHECK: Ensure the output directory exists
if not exist "%FIRMWARE_PATH%" (
    echo [ERROR] Firmware directory not found: "%FIRMWARE_PATH%"
    echo Attempting to create it...
    mkdir "%FIRMWARE_PATH%"
    if errorlevel 1 (
         echo [CRITICAL ERROR] Failed to create firmware directory.
        echo.
        echo [FAILURE] Press any key to exit...
        pause
        goto :END_SCRIPT
   
    )
    echo Directory created.
)


:: --- 3. DETECT AND LIST COM PORTS (UNCHANGED) ---
echo --- 1^) SELECT COM PORT ---
echo.
echo Detecting available COM ports via Registry...
echo.

set port_count=0

for /L %%N in (1,1,100) do (
    if defined port_%%N (
        set "port_%%N="
    ) else (
        goto :CONTINUE_SCAN
    )
)
:CONTINUE_SCAN

for /f "tokens=3" %%A in ('reg query HKLM\HARDWARE\DEVICEMAP\SERIALCOMM 2^>nul') do (
    set "com_port_name=%%A"
  
    if defined com_port_name (
        set /a port_count+=1
        set "port_!port_count!=!com_port_name!"
        
        echo [!port_count!] !com_port_name!
    )
)
echo.
if %port_count% equ 0 (
    echo [WARNING] No COM ports detected automatically.
    echo.
    goto :MANUAL_PORT
)

:: --- 4. GET PORT SELECTION (CRASH-PROOF LOGIC - UNCHANGED) ---
:GET_PORT_SELECTION
set "port_selection="
echo Enter the number of the COM port to use (1 to %port_count%)
set /p "port_selection=Or press M for manual entry: "

if /i "%port_selection%"=="M" goto :MANUAL_PORT

if "%port_selection%"=="" (
    echo Input required.
    goto :GET_PORT_SELECTION
)

set /a port_test=%port_selection% 2>nul
if errorlevel 1 (
    goto :INVALID_SELECTION_NUMERIC
)

if %port_selection% equ 0 (
    goto :INVALID_SELECTION_NUMERIC
)

if %port_selection% LSS 1 goto :INVALID_SELECTION_NUMERIC
if %port_selection% GTR %port_count% goto :INVALID_SELECTION_NUMERIC

if not defined port_%port_selection% goto :INVALID_SELECTION_NUMERIC

set "com_port=!port_%port_selection%!"
goto :PORT_SELECTED

:INVALID_SELECTION_NUMERIC
    echo [ERROR] Invalid selection.
    echo Please enter a number between 1 and %port_count%, or M for manual.
    goto :GET_PORT_SELECTION

:: --- 5. MANUAL PORT ENTRY (UNCHANGED) ---
:MANUAL_PORT
set "com_port="
echo.
echo --- MANUAL COM PORT ENTRY ---
set /p "com_port=Enter the COM port (e.g., COM3): "

if "%com_port%"=="" (
    echo COM port is required.
    goto :MANUAL_PORT
)

for %%A in (%com_port%) do set "com_port=%%A"

:PORT_SELECTED
echo.
echo Selected Port: %com_port%
echo.

:: --- 6. SMART FILE LOCATOR (INTERACTIVE SELECTION FOR MAIN APP FILE) ---
echo --- 2^) SELECT MAIN APPLICATION FIRMWARE FILE ---
echo.
call :GATHER_FIRMWARE_GROUPS

:: Debug output
echo DEBUG: file_count = !file_count!
echo DEBUG: MOST_RECENT_SUFFIX = !MOST_RECENT_SUFFIX!
echo.
:: Check file count immediately after the subroutine returns
if !file_count! equ 0 (
    echo [CRITICAL ERROR] No complete firmware groups found in "%FIRMWARE_PATH%".
    echo ^(Looking for matching %APP_PREFIX%_*.bin, %BOOTLOADER_PREFIX%_*.bin, and %PARTITIONS_PREFIX%_*.bin^)
    echo.
    echo [ACTION REQUIRED] Run the 'compile.ps1' script to build the firmware files.
    echo.
    echo [FAILURE] Press any key to exit...
    pause
    goto :END_SCRIPT
)

echo Found !file_count! complete firmware group^(s^).
echo.

:: **FIXED:** The script now proceeds to the input prompt, which should execute correctly.
:GET_FILE_SELECTION
set "file_selection="
echo Enter the number of the firmware file to flash ^(1 to !file_count!^)
set /p "file_selection=Or press R for the Most Recent file ^(Default: R^): "

:: Set default to 'R' (Most Recent) if input is empty
if "%file_selection%"=="" (
    set "file_selection=R"
)

if /i "%file_selection%"=="R" (
    set "SELECTED_SUFFIX=!MOST_RECENT_SUFFIX!"
    echo.
    echo Selected: Most Recent File ^(Group: !MOST_RECENT_SUFFIX!^)
    goto :FILE_SUFFIX_SELECTED
)

set /a file_test=%file_selection% 2>nul
if errorlevel 1 (
    goto :INVALID_FILE_SELECTION
)

if %file_selection% LSS 1 goto :INVALID_FILE_SELECTION
if %file_selection% GTR !file_count! goto :INVALID_FILE_SELECTION

if not defined suffix_%file_selection% goto :INVALID_FILE_SELECTION

set "SELECTED_SUFFIX=!suffix_%file_selection%!"
echo.
echo Selected: Group !SELECTED_SUFFIX!
goto :FILE_SUFFIX_SELECTED

:INVALID_FILE_SELECTION
    echo [ERROR] Invalid selection.
    echo Please enter a number between 1 and !file_count!, or R for most recent.
    goto :GET_FILE_SELECTION

:FILE_SUFFIX_SELECTED
:: Re-assemble the full filenames using the selected suffix
set "LATEST_APP_FILE=%APP_PREFIX%_!SELECTED_SUFFIX!.bin"
set "BOOTLOADER_FILE=%BOOTLOADER_PREFIX%_!SELECTED_SUFFIX!.bin"
set "PARTITIONS_FILE=%PARTITIONS_PREFIX%_!SELECTED_SUFFIX!.bin"

echo.
echo Selected Firmware Group ^(Suffix: !SELECTED_SUFFIX!^):
echo - Main App: !LATEST_APP_FILE!
echo - Bootloader: !BOOTLOADER_FILE!
echo - Partitions: !PARTITIONS_FILE!
echo Confirmed flash mode: Multi-Binary ^(0x1000, 0x8000, 0x10000^)
echo.

:: --- 7. ERASE MODE (MANDATORY - UNCHANGED) ---
echo --- 3^) ERASE MODE ---
echo.
echo Erase mode set to: Thorough Flash ^(Erase entire flash first - **Mandatory**^)
echo.
:: --- 8. PHYSICAL FLASHING INSTRUCTIONS (UNCHANGED) ---
echo --- 4^) BOARD FLASHING INSTRUCTIONS ---
echo.
echo Connect your ESP board.
echo You must manually put it into bootloader mode.
echo.
echo **Recommended Method:**
echo 1. **Press and HOLD** the **BOOT** ^(or **FLASH**^) button.
echo 2. While still holding BOOT, **press and RELEASE** the **RESET** ^(or **EN**^) button.
echo 3. You can now **release** the BOOT button.
echo    ^(The board is now waiting in bootloader mode^).
echo.
echo **Alternative Method** ^(If you have no RESET button^):
echo 1. **Press and HOLD** the **BOOT** ^(or **FLASH**^) button.
echo 2. Press any key below to start the flashing attempt ^(while still holding BOOT^).
echo 3. **Release** the **BOOT** button *only* after you see the "Connecting..." message.
echo.
echo 5. Do not touch the board until flashing is complete.
echo.
echo Press any key to continue...
pause >nul


:: --- 9. EXECUTE ERASE AND FLASH COMMANDS ---
echo.
echo ==============================================================================

:: ERASING FLASH UNCONDITIONALLY (UNCHANGED)
echo ERASING FLASH FIRST...
echo ==============================================================================
echo.
echo Running Erase Command:
echo "!ESPTOOL_EXE!"
echo --chip %CHIP_TYPE% --port %com_port% --baud %BAUD_RATE% erase-flash
echo.

:: 1. Create the helper script for ERASE
(
    echo @echo off
    echo "!ESPTOOL_EXE!" --chip %CHIP_TYPE% --port %com_port% --baud %BAUD_RATE% erase-flash
    echo exit /b %%ERRORLEVEL%%
) > "%HELPER_SCRIPT_FILE%"

:: 2. Execute the helper script and save the exit code
call "%HELPER_SCRIPT_FILE%"
set ERASE_EXIT_CODE=%ERRORLEVEL%

:: 3. Delete the helper script
if exist "%HELPER_SCRIPT_FILE%" del "%HELPER_SCRIPT_FILE%"

:: Check the ERRORLEVEL of the erase command: 0 (perfect success) or 1 (common post-reset code) are accepted.
if %ERASE_EXIT_CODE% equ 0 goto :ERASE_SUCCESS
if %ERASE_EXIT_CODE% equ 1 goto :ERASE_SUCCESS

:: If the exit code is anything else, it's a real failure
echo.
echo [ERROR] Flash erase failed! ^(Error Code: %ERASE_EXIT_CODE%^)
echo Please ensure the port ^(%com_port%^) is correct and the board is in **bootloader mode**.
echo.
echo [FAILURE] Press any key to exit...
pause
goto :END_SCRIPT

:ERASE_SUCCESS
echo.
echo Flash erase command executed successfully.
echo.
echo ==============================================================================

ECHO.
ECHO Proceeding to write firmware...
ECHO.
echo FLASHING FIRMWARE...
echo ==============================================================================
echo.
:: REVISED FLASH COMMAND
:: Flashes Bootloader (0x1000), Partition Table (0x8000), and Application (0x10000)
set "FLASH_COMMAND=--chip %CHIP_TYPE% --port %com_port% --baud %BAUD_RATE% --before default-reset --after hard-reset write_flash -z ^"
set "FLASH_COMMAND=!FLASH_COMMAND! 0x1000 ^"%FIRMWARE_PATH%\!BOOTLOADER_FILE!^" ^"
set "FLASH_COMMAND=!FLASH_COMMAND! 0x8000 ^"%FIRMWARE_PATH%\!PARTITIONS_FILE!^" ^"
set "FLASH_COMMAND=!FLASH_COMMAND! 0x10000 ^"%FIRMWARE_PATH%\!LATEST_APP_FILE!^""

echo Running Flash Command:
echo "!ESPTOOL_EXE!"
echo !FLASH_COMMAND!
echo.
echo Starting flash attempt... 
echo.

:: 1. Create the helper script for FLASH
(
    echo @echo off
    :: Pass the command with proper escaping to the helper script
    echo "!ESPTOOL_EXE!" !FLASH_COMMAND!
    echo exit /b %%ERRORLEVEL%%
) > "%HELPER_SCRIPT_FILE%"

:: 2. Execute the helper script and save the exit code
call "%HELPER_SCRIPT_FILE%"
set FLASH_EXIT_CODE=%ERRORLEVEL%

:: 3. Delete the helper script
if exist "%HELPER_SCRIPT_FILE%" del "%HELPER_SCRIPT_FILE%"


:: --- 10. CHECK RESULT AND DISPLAY MESSAGE (UNCHANGED) ---
echo.
echo ######################################################

:: Accept 0 (perfect success) or 1 (common post-reset code) as success
if %FLASH_EXIT_CODE% equ 0 goto :FLASH_SUCCESS
if %FLASH_EXIT_CODE% equ 1 goto :FLASH_SUCCESS

:: Failure case
echo #           FLASHING FAILED - ERROR CODE: %FLASH_EXIT_CODE%
echo #         Please check error messages above           #
goto :FLASH_END

:FLASH_SUCCESS
echo #         FLASHING COMPLETED SUCCESSFULLY            #

:FLASH_END
echo ######################################################
echo.
echo [COMPLETE] Press any key to close this window...
pause 

:END_SCRIPT
endlocal
goto :EOF

:: ==============================================================================
:: == SUBROUTINES ===============================================================
:: ==============================================================================

:GATHER_FIRMWARE_GROUPS
:: PUSHD is used to change directory to the firmware path.
set "file_count=0"
set "MOST_RECENT_SUFFIX="
set "FIRST_MATCH=1"

:: Clear existing suffix variables
for /L %%N in (1,1,100) do (
    if defined suffix_%%N (
        set "suffix_%%N="
    ) else (
        goto :CONTINUE_CLEAR_AFTER_CLEAR
    )
)
:CONTINUE_CLEAR_AFTER_CLEAR

echo Searching for complete application firmware groups ^(%APP_PREFIX%_*.bin^)...
echo.
:: Change directory to the FIRMWARE_PATH to make existence checks robust.
pushd "%FIRMWARE_PATH%" 2>nul
if errorlevel 1 goto :DIR_ERROR_SUB

:: Find all APP files (my_app_*.bin), sorted by CREATION date/time (Most Recent First: /tc /o-d-)
:: /tc = sort by creation time, /od- = order by date descending (newest first)
for /f "delims=" %%I in ('dir /b /a-d /tc /o-d- "%APP_PREFIX%_*.bin" 2^>nul') do (
    set "APP_FILENAME=%%I"
    
    :: Extract the suffix from the APP file.
    set "TEMP_SUFFIX=!APP_FILENAME:%APP_PREFIX%_=!"
    set "CURRENT_SUFFIX=!TEMP_SUFFIX:.bin=!"

    :: Now check for component files by NAME ONLY, since we are in the directory.
    set "REQ_BOOT=%BOOTLOADER_PREFIX%_!CURRENT_SUFFIX!.bin"
    set "REQ_PART=%PARTITIONS_PREFIX%_!CURRENT_SUFFIX!.bin"

    if exist "!REQ_BOOT!" (
        if exist "!REQ_PART!" (
            :: Complete set found!
            set /a file_count+=1
            set "suffix_!file_count!=!CURRENT_SUFFIX!"
            
            :: Set the most recent file's suffix (the FIRST complete match found, which is newest by creation date)
            if !FIRST_MATCH! equ 1 (
                set "MOST_RECENT_SUFFIX=!CURRENT_SUFFIX!"
                set "FIRST_MATCH=0"
            )

            :: Display the application file and the full group suffix
            echo [!file_count!] !APP_FILENAME! ^(Group: !CURRENT_SUFFIX!^)
        )
    )
)

popd
goto :EOF

:DIR_ERROR_SUB
    echo [CRITICAL ERROR] Failed to access firmware directory: "%FIRMWARE_PATH%"
    echo Please ensure the directory exists and is accessible.
:: Note: file_count will be 0, which triggers the fail message upon return.
    goto :EOF