# ESP32 Protest Communication Mesh

* The python build/install script is not as well tested as the Windows one. Use Windows when you can until I can better test other platforms. The thinking is that most users that aren't developers will be on Windows, so I built that out first and foremost. The Python script does also work on Windows, but native tools are suggested, typically
* Before 12/16/2025 there was an issue where some cryptographic actions were reliant on a third party hosted JS file. This was an oversite that has been corrected. Devices flashes before 12/16/2025 could have issues hashing the organizer password and fail logon. I'm not aware of this deployed in the field prior, but if you did find this and flash, you should update

This is a decentralized, off-grid communication network designed for resilient public broadcasting during protests or events where centralized networks are unavailable or suppressed. It uses a mesh of low-cost ESP32 devices. Each node functions simultaneously as an ESP-NOW mesh relay and a Wi-Fi Access Point.

Users connect to the node's Wi-Fi with their phone (no app required) and are directed to a captive portal. This web interface allows them to read a real-time log of public messages and, if enabled, post their own.

The system is built with a focus on security and resilience, featuring authenticated encryption for all mesh traffic and a dashboard for monitoring network health and detecting potential attacks.

For a non-technical overview and the live web flashing tool, see **[mesh.fuckups.net](https://mesh.fuckups.net)**.

## 🚀 Core Features

* **ESP-NOW Mesh Network:** Uses ESP-NOW for a low-power, high-speed, connectionless mesh. Messages are relayed with a Time-To-Live (TTL) and deduplicated by each node.
* **App-Free Captive Portal:** Users simply connect to the `ProtestInfo_...` Wi-Fi. Any browser request is redirected to the node's web UI. If this fails, users can manually navigate to `http://192.168.4.1`.
* **Authenticated Encryption:** All mesh traffic is secured with AES-128-CTR and authenticated with HMAC-SHA256. An invalid HMAC or decryption failure causes the packet to be dropped and logged.
* **Dual Security Modes:**
    * **Secure Mode (Recommended):** The mesh encryption key is randomly generated and patched into the firmware at compile-time. This key never exists in the public source code.
    * **Compatibility Mode (Bootstrap):** Nodes use a default factory key only at first boot. An organizer is required to set a new password, which is then used to derive a new session key that propagates across the mesh. This mode is for development, testing, or low-threat situations.
* **Counter-Intel Dashboard:** The organizer web UI displays forensic data logged to NVS (Non-Volatile Storage):
    * **Jamming Detection:** Detects packet loss (no messages for 60 seconds), then briefly enables a 2-second promiscuous-mode scan to check the channel's noise floor (RSSI). If high noise is confirmed, it logs a jamming event.
    * **Infiltration Detection:** Detects and alerts when multiple, conflicting organizer passwords are broadcast in a short time window.
    * **HMAC/Auth Failures:** Logs all packets that fail authentication.
* **On-Device TFT Display:** An optional TFT touch-screen is supported. This is not required for nodes to function and is primarily for developer or organizer use as a handy status monitor.
    * **Note:** The only model tested is the `esp322432S028`, which uses `TFT_TOUCH_IRQ_PIN 36`.

## 🛠️ Build & Flash Instructions

### Hardware Requirements

* **ESP32 Module:** The project is tested on standard ESP32 development boards (like the ESP32-DevKitC). More advanced models (like S2, S3, C3) have not been tested.
* **(Optional) Display:** See the note in Core Features. The project is designed to run "headless" without a screen.

### Option 1: Secure Mode - Offline Build (Recommended)

This method uses the provided build scripts to create a single, secure, unique firmware file that you flash to all your nodes.

1.  Download the `mesh.zip` package from the project's website: **[mesh.fuckups.net](https://mesh.fuckups.net)** or **[mesh.fuckups.net/flash.html](https://mesh.fuckups.net/flash.html)**. (Note: This file is not on GitHub).
2.  Extract the package. It contains the firmware source and scripts like `RUNME.bat`, `compile.ps1`, and `flash.bat`.
3.  Run `RUNME.bat`.
    > **Note:** For the first run, it is highly recommended to "Run as administrator" to ensure all required tools (like `arduino-cli`) can be installed correctly.
4.  Choose **[1] Compile**. You will be prompted to select a mode:
5.  Choose **[1] Secure Mode**. This generates a new, cryptographically random 16-byte mesh key.
6.  The script will download a portable `arduino-cli` environment, install the `esp32` core, and patch `originalcode.cpp` by injecting this new key.
7.  It will then compile the patched source code.
8.  When finished, the `output` folder will contain your unique firmware binaries (e.g., `my_app_[...]_secure.bin`, `bootloader_[...]_secure.bin`, etc.).
9.  From the main menu, choose **[2] Flash**.
10. The `flash.bat` script will guide you to select the COM port and the firmware group you just compiled. It will then wait for you to put the ESP32 into bootloader mode.
11. Press and **HOLD** the **BOOT** (or **FLASH**) button on your ESP32.
12. While still holding **BOOT**, press and **RELEASE** the **RESET** (or **EN**) button.
13. You can now release the **BOOT** button. The board is in bootloader mode.
14. Press any key in the script window to begin flashing.
15. Flash this same set of secure binaries to all of your nodes.

### Option 2: Compatibility Mode (Web Flasher)

This method is for testing or lower-risk situations.

1.  Navigate to the project's web flasher: **[mesh.fuckups.net/flash.html](https://mesh.fuckups.net/flash.html)**
2.  Select **Compatibility Mode** on the webpage.
3.  Click **Flash Firmware** and follow the on-screen prompts to select your device's COM port from the browser window.
4.  After booting, connect to the node's Wi-Fi. You must go through the one-time "Set Initial Organizer Password" step.

> **Vulnerability Note:** This step helps secure the network, but it is not truly secure. The new password is broadcast over the air (encrypted with the default key). An attacker who knows the default key can intercept this broadcast, decrypt it, and learn your new password. Do not use this mode in a high-threat environment.

### Option 3: Developer Build (Arduino IDE)

This method is for users who want to modify the code (e.g., change website text) and flash it themselves. The `originalcode.cpp` file is intentionally monolithic (a single large file) to make this process easier for hobbyists using the Arduino IDE.

1.  **Add ESP32 Board Support:**
    * Go to `File > Preferences`.
    * In "Additional Boards Manager URLs," add: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
2.  **Install Libraries:**
    * Go to `Sketch > Include Library > Manage Libraries...`
    * Search for and install **TFT_eSPI** (only required if `USE_DISPLAY` is set to `true` in the code).
3.  **Flash:**
    * Open `originalcode.cpp` in the Arduino IDE (or paste the source code into a new sketch).
    * **CRITICAL SECURITY STEP:** To enter Secure Mode, you MUST manually edit the `PRE_SHARED_KEY` variable in the code. Change the 16 bytes after the `0xDE, 0xAD, 0xBE, 0xEF` magic prefix to new, random values.
        ```cpp
        // Change these 16 bytes to your own random values
        volatile uint8_t PRE_SHARED_KEY[] = {
          0xDE, 0xAD, 0xBE, 0xEF, // 4-byte Magic prefix
          0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // Your new 16-byte key
          0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
        };
        ```
    * Go to `Tools > Board` and select your ESP32 board (e.g., "ESP32 Dev Module").
    * Go to `Tools > Port` and select the serial port for your ESP32.
    * Click the **Upload** button.

## 📖 How to Use (User Guide)

After flashing and powering on a node, follow these steps to interact with its web interface:

1.  **Connect to Wi-Fi:** On your phone or computer, search for Wi-Fi networks. Connect to the network named `ProtestInfo_XXXX` (where `XXXX` is part of the node's unique hardware address).
2.  **Access the Web Interface:** Your device should automatically open a "captive portal" page. If not, open a web browser and manually navigate to `http://192.168.4.1`.
3.  **From the Web Interface:**
    * **View Messages:** The main page displays a real-time log of all messages received by this node. You can use filter buttons to show/hide public messages or view only urgent alerts.
    * **Access Organizer Mode:**
        * **Scenario 1: New Node/Mesh:** If this is the first node you've turned on, or it's isolated from an existing mesh, there is no login prompt. You will be required to use the "Set Initial Organizer Password" form. This sets the password for the first time.
        * **Scenario 2: Rebooting Node (Active Mesh):** If you reboot a node and it connects to an already-configured mesh, it will receive the mesh password from a nearby node via a `MSG_TYPE_PASSWORD_UPDATE` broadcast. This will lock the node and set its password. When you connect, you will see the standard "Enter Organizer Mode" login prompt.
    * **Send Public Messages:** This feature is off by default. An organizer must log in and enable it.
    * **Fail-Closed Security:** This feature can be abused. If an organizer sends a `CMD_PUBLIC_OFF` command, it not only disables public messaging but also locks it off (`publicMessagingLocked = true`). Once locked, it cannot be re-enabled from the web UI, even by an organizer, until the node is physically rebooted.

## 🔐 Security Model (Developer Deep-Dive)

This project's security relies on separating the **Mesh Encryption Key** from the **Web UI Login Password**.

### 1. Packet Structure & Encryption

* **Message Format:** `esp_now_message_t`.
* **Payload:** The `content[224]` buffer is split into two parts:
    * **HMAC:** 32 bytes (`HMAC_LEN`)
    * **Payload:** 192 bytes (`MAX_PAYLOAD_LEN`)
* **Authentication (HMAC-SHA256):** A 32-byte HMAC is calculated over the immutable message headers (`messageID`, `originalSenderMac`, `messageType`) AND the 192-byte `plaintext_payload`. This prevents tampering with message contents or metadata.
* **Encryption (AES-128-CTR):** The entire 224-byte `content` buffer (HMAC + Payload) is encrypted.

### 2. AES-CTR Nonce Reuse Mitigation

AES-CTR is vulnerable if a (key, nonce) pair is ever reused. This firmware mitigates this risk by constructing a highly unique 14-byte (112-bit) nonce for every message:

* `uint64_t messageID`: A 64-bit cryptographically random number generated for every single message.
* `uint8_t[6] originalSenderMac`: The 6-byte (48-bit) MAC address of the sender.

The 14-byte nonce is `[messageID (8 bytes) | originalSenderMac (6 bytes)]`. The statistical probability of two messages from the same sender randomly generating the same 64-bit `messageID` is negligible, preventing nonce reuse and protecting the encryption.

### 3. Key Management

#### Mode 1: Secure Mode (Recommended)

* **At Flash-Time:** The build script (`compile.ps1`) generates a random 16-byte key and patches the firmware, replacing the [16-byte default key].
* **At Boot-Time:** The C++ code sees that the key does not match the factory default. It immediately copies this unique, flashed key into the active `sessionKey` buffer.
* **Result:** The node only ever uses this strong, random, flashed key for mesh encryption. Changing the "Organizer Password" in the web UI **DOES NOT** change the mesh encryption key.

#### Mode 2: Compatibility Mode (Bootstrap)

* **At Flash-Time:** The node is flashed with the stock, un-patched binary.
* **At Boot-Time:** The C++ code sees that the key matches the factory default.
* **Post-Boot (First Use):** An organizer sets a new password. The node runs this password through a 1000-iteration KDF (PBKDF2-lite HMAC-SHA256) to derive a new `sessionKey`.
* **The Vulnerability:** The node then broadcasts this new password in a `MSG_TYPE_PASSWORD_UPDATE` message. This message is encrypted with the *original (known) factory key* so that other nodes can receive it.
* **Result:** An attacker who knows the default key can sniff this `MSG_TYPE_PASSWORD_UPDATE` message, decrypt it, and learn the new mesh-wide password.

## 📡 Mesh Protocol Details

### Message Types & Prioritization

The mesh uses several message types to function. All are encrypted and authenticated.

| Message Type | ID | Purpose |
| :--- | :---: | :--- |
| `MSG_TYPE_ORGANIZER` | 0 | General organizer communications. Can be marked as "Urgent". |
| `MSG_TYPE_PUBLIC` | 1 | Public messaging, sent by any user when enabled. |
| `MSG_TYPE_AUTO_INIT` | 2 | Sent automatically upon node startup to announce presence. |
| `MSG_TYPE_COMMAND` | 3 | Control network-wide settings (e.g., `CMD_PUBLIC_ON`, `CMD_PUBLIC_OFF`). |
| `MSG_TYPE_DISCOVERY` | 5 | Peer discovery and network topology maintenance. |
| `MSG_TYPE_PASSWORD_UPDATE` | 6 | Broadcasts the new organizer password in Compatibility Mode to update the mesh key. |
| `MSG_TYPE_STATUS_REQUEST` | 7 | Queries other nodes for their public messaging status. |
| `MSG_TYPE_STATUS_RESPONSE` | 8 | Responds with public messaging status information. |
| `MSG_TYPE_JAMMING_ALERT` | 9 | Broadcasts an alert when a node detects a confirmed jamming event. |

### Caching & Re-broadcasting

* **Cache Size:** Nodes maintain a cache of the last 100 messages.
* **Cache Duration:** Messages are stored for up to 30 minutes (`DEDUP_CACHE_DURATION_MS`).
* **Compatibility Mode Exception:** In Compatibility Mode, `MSG_TYPE_PASSWORD_UPDATE` messages are never pruned from the cache. This is necessary to allow new/rebooted nodes to get the new key, but it is also the source of the vulnerability, as an attacker can always find this message.
* **Re-broadcast:** Every 30 seconds (`AUTO_REBROADCAST_INTERVAL_MS`), each node re-broadcasts its entire valid message cache. This ensures high message persistence and eventual network-wide consistency.
* **TTL:** Messages have a Time-To-Live (TTL) of 40 hops (`MAX_TTL_HOPS`) to prevent infinite looping.

### Peer Management

* **ISR Queue:** A FreeRTOS queue of size 10 (`QUEUE_SIZE`) is used to pass messages from the ESP-NOW ISR (`onDataRecv`) to the main loop for processing, preventing ISR-related instability.
* **Discovery:** Nodes broadcast a `MSG_TYPE_DISCOVERY` message every 15 seconds (`PEER_DISCOVERY_INTERVAL_MS`) to find other peers.
* **Peer Timeout:** Peers are kept in the "Last Seen" list (for display) for 10 minutes (`PEER_LAST_SEEN_DURATION_MS`). They are removed from the active ESP-NOW sending list after 5 minutes (`ESP_NOW_PEER_TIMEOUT_MS`) of inactivity.

## 📂 Project File Structure

* `index.html`: The project's main landing page (hosted online).
* `flash.html`: The web-based flashing tool (hosted online).
* `directions.html`: A detailed flashing and usage guide (hosted online).
* `handout.html`: A printable handout to give to event participants with connection instructions.
* `mesh.zip`: The distributable offline package containing the items below.
* `RUNME.bat`: The main interactive menu for compiling and flashing.
* `compile.ps1`: The PowerShell build script for "Secure Mode."
* `flash.bat`: The Windows batch script for flashing compiled firmware.
* `originalcode.cpp`: The complete C++ firmware source for the ESP32 node.
