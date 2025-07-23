Protest Information Node
This project implements a decentralized, local communication network designed for sharing information in environments where traditional internet or cellular services might be unavailable or unreliable. Each device acts as a node in a self-organizing mesh, enabling communication without a central server.

Features
The Protest Information Node provides a robust way for people to share messages locally:

Offline Communication: Operates entirely without internet access, creating its own local Wi-Fi network.

Public Message Viewing: Anyone connected to a node's Wi-Fi can view received messages.

Organizer Messaging: Authorized organizers can send important, prioritized messages, including "Urgent" alerts.

Public Message Sending: Users can send public messages, but this feature is off by default and must be enabled by an organizer.

Message Mesh Propagation: Messages automatically spread from node to node, extending communication reach across the local area.

Local Display: If a TFT screen is attached, it can directly show messages (all or urgent only), device information, and network statistics.

Web Interface (SoftAP): Each node hosts a local web interface accessible via its Wi-Fi network, providing message logs and control options.

Organizer Mode Controls: Authenticated organizers can manage network settings, including toggling public messaging, re-broadcasting message caches, and setting the initial organizer password.

Getting Started (Flashing Firmware)
To upload the code to your ESP32 board using the Arduino IDE:

Install Arduino IDE: Download and install the Arduino IDE from the official website.

Add ESP32 Board Support:

Go to File > Preferences.

In "Additional Boards Manager URLs," add: https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

Go to Tools > Board > Boards Manager...

Search for "esp32" and install the "esp32 by Espressif Systems" package.

Install Libraries:

Go to Sketch > Include Library > Manage Libraries...

Search for and install TFT_eSPI (only required if USE_DISPLAY is set to true in the code).

Open Project: Open the .ino file (this code) in Arduino IDE.

Select Board: Go to Tools > Board > ESP32 Arduino and select your specific ESP32 board (e.g., "ESP32 Dev Module").

Select Port: Go to Tools > Port and select the serial port connected to your ESP32.

Upload: Click the "Upload" button (right arrow icon) to compile and flash the code to your ESP32.

Once flashed, the ESP32 will reboot and automatically start its local Wi-Fi network and communication services.

How to Use (Quick Start Guide)
After flashing and powering on a node, follow these steps to interact with its web interface:

Connect to Wi-Fi: On your phone or computer, search for Wi-Fi networks. Connect to the network named ProtestInfo_XXXX (where XXXX are the last four characters of the node's unique hardware address). No password is required for the Wi-Fi connection itself.

Access the Web Interface: Your device should automatically open a "captive portal" page. If not, open a web browser and try to navigate to any website (e.g., http://example.com). You will be redirected to the node's local web interface.

View Messages: The main page displays a log of all messages received by this node. Use the filter buttons ("Show Public Messages" / "Hide Public Messages" and "Show Urgent Only" / "Show All Messages") to customize your view.

Access Organizer Mode: To unlock advanced features, find the "Enter Organizer Mode" section.

Initial Setup: If this is a new node, you'll first be prompted to "Set Initial Organizer Password." Choose a strong password and confirm it. This password will then spread to all other connected nodes in the mesh. You only need to set the organizer password once across your network.

Logging In: After the password is set, use this section to log in as an organizer with your chosen password.

Send Public Messages: Locate the "Send a Public Message" section. This feature is off by default. An organizer must enable it through "Organizer Mode." Once enabled, you can type and send messages that will be shared across all connected nodes.

Understanding the Locking Mechanisms
The system incorporates two important locking mechanisms for security and control:

Organizer Password Lock: The organizer password for a node is set at runtime. Once a non-default password is set (either locally or received from another node), it becomes permanently locked for that session. This means the password cannot be changed through the web interface without physically rebooting the ESP32 board. Upon reboot, the organizer password for that specific board will reset to its default value ('password'). To truly reset the organizer password across an entire mesh (i.e., change it from a previously set non-default value to a new non-default value), all boards in the mesh must be powered off before setting the new password on a single board and then powering others back on. This ensures that the new password propagates without interference from other nodes still holding the old password. This mechanism ensures that once a node is deployed with a specific organizer password, it maintains that security setting, preventing unauthorized password changes over the air.

Public Messaging Lock: An organizer has the ability to "Disable Public Msgs," which also "locks" public messaging off. This means that once public messaging is locked off by an organizer, it cannot be re-enabled through the web interface until the board is rebooted. This provides a critical control mechanism for organizers to shut down public communication if necessary, preventing its re-activation without physical intervention.

Technical Details (For Developers)
This section provides a deeper dive into the technical implementation for developers and those interested in the underlying mechanisms.

ESP-NOW Mesh Network:

Each node establishes a peer-to-peer connection with other nearby nodes using ESP-NOW, a connectionless communication protocol.

There is no central server; messages are relayed between nodes in a mesh-like fashion.

Nodes dynamically discover each other and add new peers to their network.

Message Types & Prioritization:

Organizer Messages (MSG_TYPE_ORGANIZER): Sent by authenticated organizers, can be marked as "Urgent."

Public Messages (MSG_TYPE_PUBLIC): Sent by any connected user when public messaging is enabled.

Auto-Init Messages (MSG_TYPE_AUTO_INIT): Sent by a node upon startup.

Command Messages (MSG_TYPE_COMMAND): Used by organizers to control network-wide settings (e.g., enabling/disabling public messaging).

Discovery Messages (MSG_TYPE_DISCOVERY): Used for peer discovery and network topology maintenance.

Password Update Messages (MSG_TYPE_PASSWORD_UPDATE): Broadcast to update organizer passwords across the mesh.

Status Request/Response Messages (MSG_TYPE_STATUS_REQUEST, MSG_TYPE_STATUS_RESPONSE): Used for nodes to query and share their public messaging status.

Encryption:

All message content is encrypted using a simple XOR stream cipher with a pre-shared key (PSK) known to all nodes. This provides a basic layer of confidentiality.

Message Deduplication and Re-broadcasting:

Each message is assigned a unique ID and original sender MAC.

Nodes maintain a cache of recently seen messages to prevent redundant processing and re-broadcasting.

Messages have a Time-To-Live (TTL) counter, which decrements with each hop. Messages are re-broadcast until their TTL reaches zero, ensuring propagation across the mesh.

Web Interface (SoftAP):

Each node creates its own Wi-Fi Access Point (SoftAP) with a unique SSID (e.g., "ProtestInfo_EEFF").

Users connect to this Wi-Fi network. A captive portal redirects all web requests to the node's local web interface.

Public Page: Displays the message log. Public message sending is available if enabled by an organizer.

Organizer Page: Accessible via password-based challenge-response authentication. Organizers can:

Send organizer messages (including "Urgent" messages).

Toggle public messaging on/off.

Set an initial organizer password for the node. Once set, the password cannot be changed without rebooting the board.

Re-broadcast the message cache.

Public Messaging Lock: An organizer can permanently disable public messaging (until the board is rebooted) via a command.

Local Display (TFT):

If a TFT display is connected, the node can cycle through different display modes:

All messages (chat log).

Urgent messages only.

Device information (MAC, IP, nearby nodes).

Network statistics (messages sent/received, cache size, uptime).

Display modes can be changed via touch input (if supported by the TFT).
