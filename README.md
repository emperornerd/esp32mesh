Protest Information Node
This project implements a decentralized, local communication network designed for sharing information in environments where traditional internet or cellular services might be unavailable or unreliable. Each device acts as a node in a self-organizing mesh, enabling communication without a central server.

What It Does (For Everyone)
The Protest Information Node provides a robust way for people to share messages locally:

Offline Communication: It works completely without internet access, creating its own local network.

Public Messages: Anyone connected to a node's Wi-Fi can view messages. Public message sending is off by default and must be enabled by an organizer.

Organizer Messages: Authorized organizers can send important, prioritized messages, including "Urgent" alerts, and manage the network's settings.

Message Sharing: Messages automatically spread from node to node, extending the reach of communication across the local area.

Local Display: If a screen is attached, it can show messages directly, including urgent ones, and basic device information.

Flashing with Arduino IDE (For Setup)
To upload the code to your ESP32 board using the Arduino IDE:

Install Arduino IDE: Download and install the Arduino IDE from the official website.

Add ESP32 Board Support:

Go to File > Preferences.

In "Additional Boards Manager URLs," add: https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

Go to Tools > Board > Boards Manager...

Search for "esp32" and install the "esp32 by Espressif Systems" package.

Install Libraries:

Go to Sketch > Include Library > Manage Libraries...

Search for and install TFT_eSPI (if USE_DISPLAY is true in the code).

Open Project: Open the .ino file (this code) in Arduino IDE.

Select Board: Go to Tools > Board > ESP32 Arduino and select your specific ESP32 board (e.g., "ESP32 Dev Module").

Select Port: Go to Tools > Port and select the serial port connected to your ESP32.

Upload: Click the "Upload" button (right arrow icon) to compile and flash the code to your ESP32.

Once flashed, the ESP32 will reboot and start its local Wi-Fi network and communication services.

How to Use (Quick Start)
After flashing and powering on a node, follow these steps to interact with it:

Connect to Wi-Fi: On your phone or computer, search for Wi-Fi networks. You will see a network named ProtestInfo_XXXX (where XXXX are the last four characters of the node's unique hardware address). Connect to this network. No password is required for the Wi-Fi itself.

Access the Web Interface: Once connected, your device should automatically open a "captive portal" page. If not, open a web browser and try to navigate to any website (e.g., http://example.com). You will be redirected to the node's local web interface.

View Messages: The main page displays a log of all messages received by this node. You can use the filter buttons ("Show Public Messages" / "Hide Public Messages" and "Show Urgent Only" / "Show All Messages") to customize your view.

Organizer Mode (Core Function):

To access the core functions of the node, find the "Enter Organizer Mode" section.

Initial Setup: If this is a new node, you'll first be prompted to "Set Initial Organizer Password." Choose a strong password and confirm it. This password will then spread to all other connected nodes in the mesh. You only need to set the organizer password once across your network. Once set, this password cannot be changed through the web interface without physically rebooting the board for security reasons. This locking mechanism prevents unauthorized changes to the node's core settings after deployment.

Logging In: After the password is set, you'll use this section to log in as an organizer.

Organizer Actions: Once logged in, you can send prioritized organizer messages, manually re-broadcast messages, and control the "Public Messaging Lock."

Send Public Messages (Requires Organizer Enablement):

Look for the "Send a Public Message" section.

Public messaging is off by default. An organizer must enable it through "Organizer Mode" for this feature to become active. Once enabled, you can type your message and send it. These messages are shared with all connected nodes.

Understanding the Locking Mechanisms
The system includes two important locking mechanisms designed for security and control:

Organizer Password Lock: The organizer password for a node is set at runtime. Once a non-default password is set (either locally or received from another node), it becomes permanently locked for that session. This means the password cannot be changed through the web interface without physically rebooting the ESP32 board. Upon reboot, the organizer password for that specific board will reset to its default value ('password'). To truly reset the organizer password across an entire mesh (i.e., change it from a previously set non-default value to a new non-default value), all boards in the mesh must be powered off before setting the new password on a single board and then powering others back on. This ensures that the new password propagates without interference from other nodes still holding the old password. This mechanism ensures that once a node is deployed with a specific organizer password, it maintains that security setting, preventing unauthorized password changes over the air.

Public Messaging Lock: An organizer has the ability to "Disable Public Msgs," which also "locks" public messaging off. This means that once public messaging is locked off by an organizer, it cannot be re-enabled through the web interface until the board is rebooted. This provides a critical control mechanism for organizers to shut down public communication if necessary, preventing its re-activation without physical intervention.

Technical Details for Development
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
