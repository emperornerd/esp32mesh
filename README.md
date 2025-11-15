# ESP32 Protest Communication Mesh

This is a decentralized, off-grid communication network designed for resilient public broadcasting during protests or events where centralized networks are unavailable or suppressed.

It uses a mesh of low-cost ESP32 devices. Each node functions simultaneously as an ESP-NOW mesh relay and a Wi-Fi Access Point.

Users connect to the node's Wi-Fi with their phone (no app required) and are directed to a captive portal. This web interface allows them to read a real-time log of public messages and, if enabled, post their own.

The system is built with a focus on security and resilience, featuring authenticated encryption for all mesh traffic and a dashboard for monitoring network health and detecting potential attacks.

For a non-technical overview and project philosophy, see [mesh.fuckups.net](http://mesh.fuckups.net).

---

## 🚀 Core Features

* ESP-NOW Mesh Network: Uses ESP-NOW for a low-power, high-speed, connectionless mesh. Messages are relayed with a Time-To-Live (TTL) and deduplicated by each node.
* App-Free Captive Portal: Users simply connect to the `ProtestInfo_...` Wi-Fi. Any browser request is redirected to the node's web UI for sending/receiving messages.
* Authenticated Encryption: All mesh traffic is secured with AES-128-CTR and authenticated with HMAC-SHA256. An invalid HMAC or decryption failure causes the packet to be dropped and logged.
* Dual Security Modes:
    1.  Secure Mode (Recommended): The mesh encryption key is randomly generated and patched into the firmware at compile-time. This key *never* exists in the public source code.
    2.  Compatibility Mode (Insecure): Nodes use a default factory key, allowing an organizer to set a mesh-wide password *after* deployment.
* Counter-Intel Dashboard: The organizer web UI displays forensic data logged to NVS:
    * Jamming Detection: Detects packet loss and actively scans the channel's noise floor (RSSI) using promiscuous mode to confirm high-energy jamming.
    * Infiltration Detection: Detects and alerts when multiple, conflicting organizer passwords are broadcast in a short time window.
    * HMAC/Auth Failures: Logs all packets that fail authentication.
* On-Device TFT Display: An optional (but recommended) TFT touch-screen shows a live message log, peer list, network stats, and security alerts.

---

## 🔐 Security Model (Developer Deep-Dive)

This project's security relies on separating the *Mesh Encryption Key* from the *Web UI Login Password*.

### 1. Packet Structure & Encryption

* Message Format: `esp_now_message_t`
* Payload: The `content[224]` buffer is split into two parts:
    * HMAC: 32 bytes (`HMAC_LEN`)
    * Payload: 192 bytes (`MAX_PAYLOAD_LEN`)
* Authentication (HMAC-SHA256): A 32-byte HMAC is calculated over the immutable message headers (`messageID`, `originalSenderMac`, `messageType`) AND the 192-byte `plaintext_payload`. This prevents tampering with message contents *or* metadata (like the sender's identity).
* Encryption (AES-128-CTR): The *entire* 224-byte `content` buffer (HMAC + Payload) is encrypted.
* Nonce: The 14-byte (112-bit) nonce is constructed from the unique `uint64_t messageID` and the `uint8_t[6] originalSenderMac`.

### 2. Key Management & The "Flasher Fix"

The firmware (`originalcode.cpp`) contains a "magic" byte sequence that the build/flash tools look for:
`volatile uint8_t PRE_SHARED_KEY[] = { 0xDE, 0xAD, 0xBE, 0xEF, ...[16-byte default key]... };`

The node's behavior is determined at boot by checking this key.

#### Mode 1: Secure Mode (Recommended)

This is the default and intended deployment method.

1.  At Flash-Time: The build script (`compile.ps1`) or web flasher (`flash.html`) generates a cryptographically random 16-byte key.
2.  It then *patches* the firmware binary, replacing the `[16-byte default key]` with this new random key.
3.  At Boot-Time: The C++ code in `setup()` compares the key at `(PRE_SHARED_KEY + 4)` against the hardcoded factory default.
4.  Since they do not match, it sets `isUsingDefaultPsk = false`.
5.  It *immediately* copies this patched-in key into the active `sessionKey` buffer.
6.  Result: The node *only* ever uses this strong, random, flashed key for mesh encryption.

In this mode, changing the "Organizer Password" in the web UI DOES NOT change the mesh encryption key. It only updates the `hashedOrganizerPassword` used for the web UI login. This allows organizers to change the *login* password without re-flashing the entire mesh.

#### Mode 2: Compatibility Mode (Insecure)

1.  At Flash-Time: The node is flashed with the *stock, un-patched* binary.
2.  At Boot-Time: The C++ code sees that the key at `(PRE_SHARED_KEY + 4)` *matches* the factory default.
3.  It sets `isUsingDefaultPsk = true` and uses the default (publicly known) factory key for initial communication.
4.  Post-Boot: An organizer must log in (using the default `WEB_PASSWORD`) and set a new password.
5.  This action broadcasts a `MSG_TYPE_PASSWORD_UPDATE` containing the new *human-readable* password.
6.  *All* nodes receive this, run the password through a 1000-iteration KDF (HMAC-SHA256), and derive a *new* `sessionKey`.
7.  Result: The mesh is now secured, but its strength is limited to the human-chosen password.

### 3. Web UI Authentication

The web UI login is protected separately. The client-side JavaScript hashes the plaintext password with a salt (`ProtestNodeSalt123XYZ`) before sending it to the server, which compares it against the `hashedOrganizerPassword`.

* Default Login Password: The initial password for the web UI in *both* modes is the value of `WEB_PASSWORD` from `originalcode.cpp`:
    `4kfu4ofkf0w020ijfkus9w98`

---

## 🛠️ Build & Flash Instructions

### Hardware Requirements

* ESP32 Module: Any ESP32-WROOM-32, ESP32-S, or similar module.
* (Optional) Display: A TFT display compatible with `TFT_eSPI`. The code is configured for a generic display with `TFT_TOUCH_IRQ_PIN 36`.

### Option 1: Secure Mode - Offline Build (Recommended)

This method uses the provided build script to create a single, secure, unique firmware file that you flash to all your nodes.

1.  Download the `mesh.zip` package from the project's `index.html` or `flash.html` page.
2.  Extract the package. It contains the `firmware` source and the `compile.ps1` script.
3.  Run `compile.ps1` (PowerShell).
4.  You will be prompted to select a mode. Choose [1] Secure Mode.
5.  The script will:
    * Download and set up a portable `arduino-cli` environment.
    * Install the `esp32` board core.
    * Generate a new, cryptographically random 16-byte mesh key.
    * *Patch* `originalcode.cpp` by injecting this new key.
    * Compile the *patched* source code.
6.  When finished, the `output` folder will contain your unique firmware binaries (e.g., `my_app_[...]_secure.bin`).
7.  Use a standard flash tool (like `esptool.py` or the `flash.bat` script provided in `mesh.zip`) to flash this new `.bin` file (along with the bootloader and partitions) to *all* of your nodes.

### Option 2: Secure Mode - Experimental Web Flasher

The `flash.html` page provides an *experimental* in-browser secure flash.

1.  Navigate to `flash.html` in a Web-Serial-compatible browser (Chrome, Edge).
2.  Go to Advanced Options (Experimental) and click Initialize Experimental Flasher.
3.  This will:
    * Generate a random key *in your browser session*.
    * Fetch the *stock* firmware `.bin`.
    * Find the `DE AD BE EF` magic bytes and *patch the key* live in the browser's memory.
4.  Click Flash Experimental Secure Firmware and select your ESP32.
5.  CRITICAL: You must flash all other nodes in your mesh with this *exact same patched firmware*. Use the Download Patched Secure Firmware button to save the unique `.bin` file and flash it to your other nodes manually.

### Option 3: Compatibility Mode (Testing Only)

1.  Navigate to `flash.html`.
2.  Select Compatibility Mode.
3.  Click Flash Firmware and flash the *stock* `.bin` file.
4.  After booting, connect to the node's Wi-Fi, log in with the default password (`4kfu4ofkf0w020ijfkus9w98`), and set a new mesh-wide password via the UI.

---

## 📂 File Structure

* `originalcode.cpp`: The complete C++ firmware for the ESP32 node. Contains all logic for mesh, web server, UI, and security.
* `index.html`: The project's main landing page.
* `flash.html`: The web-based flashing tool. Implements the "Experimental Secure" in-browser patching logic.
* `compile.ps1`: The offline (PowerShell) build script for "Secure Mode". Generates and injects the random key *before* compiling.
