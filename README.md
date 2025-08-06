# Protest Information Node

This project implements a decentralized, local communication network designed for sharing information in environments where traditional internet or cellular services might be unavailable or unreliable.
Each device acts as a node in a self-organizing mesh, enabling communication without a central server.

## Features

The Protest Information Node provides a robust way for people to share messages locally:

  - **Offline Communication**: Operates entirely without internet access, creating its own local Wi-Fi network.
  - **Public Message Viewing**: Anyone connected to a node's Wi-Fi can view received messages.
  - **Organizer Messaging**: Authorized organizers can send important, prioritized messages, including "Urgent" alerts.
  - **Public Message Sending**: Users can send public messages, but this feature is off by default and must be enabled by an organizer.
  - **Message Mesh Propagation**: Messages automatically spread from node to node, extending communication reach across the local area.
  - **Local Display**: If a TFT screen is attached, it can directly show messages (all or urgent only), device information, and network statistics.
  - **Web Interface (SoftAP)**: Each node hosts a local web interface accessible via its Wi-Fi network, providing message logs and control options.
  - **Organizer Mode Controls**: Authenticated organizers can manage network settings, including toggling public messaging, re-broadcasting message caches, and setting the initial organizer password.

## Getting Started (Flashing Firmware)

### Arduino IDE

#### Add ESP32 Board Support:

1. Go to File > Preferences.
2. In "Additional Boards Manager URLs," add: https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
3. Go to Tools > Board > Boards Manager...
4. Search for "esp32" and install the "esp32 by Espressif Systems" package.

#### Install Libraries:

1. Go to Sketch > Include Library > Manage Libraries...
2. Search for and install TFT_eSPI (only required if USE_DISPLAY is set to true in the code).
3. Open Project: Open the .ino file (this code) in Arduino IDE.
4. Select Board: Go to Tools > Board > ESP32 Arduino and select your specific ESP32 board (e.g., "ESP32 Dev Module").
5. Select Port: Go to Tools > Port and select the serial port connected to your ESP32.
6. Upload: Click the "Upload" button (right arrow icon) to compile and flash the code to your ESP32.
7. Once flashed, the ESP32 will reboot and automatically start its local Wi-Fi network and communication services.

### arduino-cli (via nix)

[flake.nix](./flake.nix) packages the `arduino-cli` command in a devshell.
Nix users can use it like so:

```bash
ls /dev > /tmp/devices                # while unplugged
                                      # then plug it in
diff <(cat /tmp/devices) <(ls /dev)   # this will print the new devices
ESP_PORT=/dev/tty.usbserial-1140      # the device may differ on your machine

# Enter dev shell
nix develop

# Verify device connection
arduino-cli board list

# Compile and upload firmware
arduino-cli compile --fqbn esp32:esp32:esp32 sketch_primary
arduino-cli upload --fqbn esp32:esp32:esp32 -p $ESP_PORT sketch_primary  --upload-property upload.speed=115200

# Monitor serial output
# (if you see nothing, try press the reset button on the board)
picocom -b 115200 $ESP_PORT
# you should also see a "protestinfo" wifi network at this point
```

## How to Use (Quick Start Guide)

After flashing and powering on a node, follow these steps to interact with its web interface:

1. **Connect to Wi-Fi**: On your phone or computer, search for Wi-Fi networks. Connect to the network named ProtestInfo_XXXX (where XXXX are the last four characters of the node's unique hardware address). No password is required for the Wi-Fi connection itself.
2. **Access the Web Interface**: Your device should automatically open a "captive portal" page. If not, open a web browser and try to navigate to any website (e.g., http://example.com). You will be redirected to the node's local web interface.

Things to do from there:

- **View Messages**: The main page displays a log of all messages received by this node. Use the filter buttons ("Show Public Messages" / "Hide Public Messages" and "Show Urgent Only" / "Show All Messages") to customize your view.
- **Access Organizer Mode**: To unlock advanced features, find the "Enter Organizer Mode" section.
- **Initial Setup**: If this is a new node, you'll first be prompted to "Set Initial Organizer Password." Choose a strong password and confirm it. This password will then spread to all other connected nodes in the mesh. You only need to set the organizer password once across your network.
- **Logging In**: After the password is set, use this section to log in as an organizer with your chosen password.
- **Send Public Messages**: Locate the "Send a Public Message" section. This feature is off by default. An organizer must enable it through "Organizer Mode." Once enabled, you can type and send messages that will be shared across all connected nodes.

### Understanding the Locking Mechanisms

The system incorporates two important locking mechanisms for security and control:

- **Organizer Password Lock**: The organizer password for a node is set at runtime. Once a non-default password is set (either locally or received from another node), it becomes permanently locked for that session. This means the password cannot be changed through the web interface without physically rebooting the ESP32 board. Upon reboot, the organizer password for that specific board will reset to its default value ('password'). To truly reset the organizer password across an entire mesh (i.e., change it from a previously set non-default value to a new non-default value), all boards in the mesh must be powered off before setting the new password on a single board and then powering others back on. This ensures that the new password propagates without interference from other nodes still holding the old password. This mechanism ensures that once a node is deployed with a specific organizer password, it maintains that security setting, preventing unauthorized password changes over the air.
- **Public Messaging Lock**: An organizer has the ability to "Disable Public Msgs," which also "locks" public messaging off. This means that once public messaging is locked off by an organizer, it cannot be re-enabled through the web interface until the board is rebooted. This provides a critical control mechanism for organizers to shut down public communication if necessary, preventing its re-activation without physical intervention.

## Technical Details (For Developers)

This section provides a deeper dive into the technical implementation for developers and those interested in the underlying mechanisms.

## ESP-NOW Mesh Network:

Each node establishes a peer-to-peer connection with other nearby nodes using ESP-NOW, a connectionless communication protocol.
There is no central server; messages are relayed between nodes in a mesh-like fashion.
Nodes dynamically discover each other and add new peers to their network.

## Message Types & Prioritization:

| Message Type | Sent By | Priority | Purpose |
|--------------|---------|----------|---------|
| MSG_TYPE_ORGANIZER | Authenticated organizers | Can be marked as "Urgent" | General organizer communications |
| MSG_TYPE_PUBLIC | Any connected user | Standard | Public messaging when enabled |
| MSG_TYPE_AUTO_INIT | Node | Standard | Sent automatically upon node startup |
| MSG_TYPE_COMMAND | Organizers | Standard | Control network-wide settings (e.g., enable/disable public messaging) |
| MSG_TYPE_DISCOVERY | Any node | Standard | Peer discovery and network topology maintenance |
| MSG_TYPE_PASSWORD_UPDATE | System/Organizers | Standard | Broadcast organizer password updates across mesh |
| MSG_TYPE_STATUS_REQUEST | Any node | Standard | Query other nodes for their public messaging status |
| MSG_TYPE_STATUS_RESPONSE | Any node | Standard | Respond with public messaging status information |

## Encryption:

All message content is encrypted using a simple XOR stream cipher with a pre-shared key (PSK) known to all nodes. This provides a basic layer of confidentiality.

#### Message Deduplication and Re-broadcasting:

- Each message is assigned a unique ID and original sender MAC.

- Nodes maintain a cache of recently seen messages to prevent redundant processing and re-broadcasting.

- Messages have a Time-To-Live (TTL) counter, which decrements with each hop. Messages are re-broadcast until their TTL reaches zero, ensuring propagation across the mesh.

### Web Interface (SoftAP):

Each node creates its own Wi-Fi Access Point (SoftAP) with a unique SSID (e.g., "ProtestInfo_EEFF").
Users connect to this Wi-Fi network.
A captive portal redirects all web requests to the node's local web interface.

- **Public Page**: Displays the message log. Public message sending is available if enabled by an organizer.

- **Organizer Page**: Accessible via password-based challenge-response authentication.

Organizers can:

- Send organizer messages (including "Urgent" messages).
- Toggle public messaging on/off.
- Set an initial organizer password for the node. Once set, the password cannot be changed without rebooting the board.
- Re-broadcast the message cache.

**Public Messaging Lock**: An organizer can permanently disable public messaging (until the board is rebooted) via a command.

### Local Display (TFT):

If a TFT display is connected, the node can cycle through different display modes:

- All messages (chat log).
- Urgent messages only.
- Device information (MAC, IP, nearby nodes).
- Network statistics (messages sent/received, cache size, uptime).

Display modes can be changed via touch input (if supported by the TFT).
