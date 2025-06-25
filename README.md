ESP32 Mesh Information Node
This project transforms an ESP32 microcontroller into a self-contained, offline mesh communication node. It creates its own Wi-Fi Access Point (SoftAP) to allow users to connect via a web browser and exchange messages that are then propagated across a network of other trusted ESP32 nodes using ESP-NOW. This is designed for scenarios where traditional internet or cellular networks are unavailable, providing a resilient local communication channel.

Messages are deduplicated and periodically re-broadcast within the mesh to ensure maximum propagation and reliability, even if nodes temporarily go offline and reconnect. It includes optional support for a TFT display to show recent messages and node status.

Features
Offline Mesh Communication (ESP-NOW): Utilizes ESP-NOW for fast, connectionless message exchange between ESP32 boards, forming a local mesh network without a router.

Web Interface (SoftAP): Each node acts as a Wi-Fi Access Point (ProtestInfo_XXXX where XXXX is part of its MAC address), hosting a simple web page for users to view incoming messages and send new ones.

DNS Server: A built-in DNS server on the SoftAP redirects all DNS requests to the node's IP, ensuring the web interface loads consistently (e.g., you can type any domain into your browser, and it will resolve to the node's web page).

Message Deduplication: Prevents redundant processing and re-broadcasting of messages already seen, improving network efficiency.

Periodic Re-broadcasting: Automatically re-sends older, unique messages from its cache at random intervals. This ensures that messages propagate throughout the network, even if some nodes were temporarily offline when the message was originally sent.

Time-To-Live (TTL): Messages have a configurable hop limit to prevent infinite loops and manage network congestion.

Trusted Peers System: Only communicates with other ESP32 nodes whose MAC addresses are explicitly listed in its firmware, enhancing security in a closed network.

Configurable Password: The web interface for sending messages is protected by a simple password.

TFT Display Support (Optional): Can display incoming messages and node status on a connected TFT screen (requires TFT_eSPI library).

Hardware Requirements
ESP32 Development Board: Any ESP32 board (e.g., ESP32-DevKitC, ESP32 WROOM-32, NodeMCU-32S).

Micro-USB Cable: To connect the ESP32 to your computer for flashing.

Computer: Running Windows, macOS, or Linux.

TFT Display (Optional): If USE_DISPLAY is set to true in the code, a compatible TFT display (e.g., using an ILI9341 or ST7789 driver) connected via SPI.

Software Requirements
Arduino IDE: Download and install from https://www.arduino.cc/en/software.

ESP32 Boards Manager URL: Add the following URL in Arduino IDE File > Preferences > Additional Boards Manager URLs:

https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

ESP32 Board Definitions: Install "esp32 by Espressif Systems" via Tools > Board > Boards Manager... in Arduino IDE.

TFT_eSPI Library: Install "TFT_eSPI by Bodmer" via Sketch > Include Library > Manage Libraries... in Arduino IDE if you are using a display.

Setup Instructions
Follow these steps to prepare your ESP32 boards:

1. Install Arduino IDE and ESP32 Board Support
Refer to the "Software Requirements" section above and ensure the Arduino IDE is installed and the ESP32 board definitions are successfully added via the Boards Manager.

2. Install Required Libraries
TFT_eSPI: If you plan to use a TFT display (#define USE_DISPLAY true), open Arduino IDE, go to Sketch > Include Library > Manage Libraries..., search for TFT_eSPI, and install it.

DNSServer.h, WiFi.h, esp_now.h, esp_wifi.h, vector, algorithm, string.h, set, map: These are typically included with the ESP32 board package and do not require separate installation.

3. Obtain Your ESP32 MAC Addresses
This is a CRITICAL step. Each ESP32 node in your mesh must have the MAC addresses of all other trusted nodes hard-coded.

For each ESP32 board you intend to use:

Open a new sketch in the Arduino IDE.

Paste the following code:

#include <WiFi.h>
void setup() {
  Serial.begin(115200);
  Serial.print("ESP32 MAC Address: ");
  Serial.println(WiFi.macAddress());
}
void loop() {}

Select your ESP32 board (Tools > Board) and the correct serial port (Tools > Port).

Upload this small sketch to the ESP32.

Open the Serial Monitor (Tools > Serial Monitor) and set the baud rate to 115200.

Note down the full MAC address displayed (e.g., 14:33:5C:06:3A:99).

Repeat this for every ESP32 you plan to include in your mesh.

4. Configure trustedMACs in the Main Code
Copy the provided main sketch code (the content of code_canvas) into a new Arduino IDE sketch.

Find the section:

const uint8_t trustedMACs[][6] = {
  {0x08, 0xA6, 0xF7, 0x47, 0xFA, 0xAD},    // MAC of node A
  {0x14, 0x33, 0x5C, 0x6D, 0x74, 0x05},    // MAC of node B
  {0x14, 0x33, 0x5C, 0x6C, 0x3A, 0x99}     // MAC of node C
  // Add all other ESP32 MAC addresses here, ensuring they are exact!
};

Replace the example MAC addresses with the actual MAC addresses you collected in the previous step.

Convert each colon-separated hexadecimal pair to 0x format.

Example: 14:33:5C:06:3A:99 becomes {0x14, 0x33, 0x5C, 0x06, 0x3A, 0x99}.

Ensure numTrusted (calculated automatically) correctly reflects the number of MAC addresses you've entered.

Crucially, this trustedMACs array MUST BE IDENTICAL on ALL ESP32 boards in your mesh. If a node's MAC is not in another node's trustedMACs list, they will not communicate.

5. Flash the Code
Connect your ESP32 board to your computer.

In Arduino IDE, select your ESP32 board (Tools > Board) and the correct serial port (Tools > Port).

Click the Upload button (right arrow icon) in the Arduino IDE toolbar.

If the upload fails, you might need to manually put your ESP32 into "flashing mode":

Hold down the BOOT (or FLASH) button on your ESP32.

While holding BOOT, press the EN (or RESET) button once, then release EN.

Continue holding BOOT.

Click the Upload button in the Arduino IDE again.

Once you see "Connecting..." and upload progress, you can release the BOOT button.

Repeat this entire flashing process for each ESP32 board you want to be part of your mesh, ensuring they all have the identical and correct trustedMACs list.

Usage
Once flashed, each ESP32 node will operate as follows:

Connect to the Wi-Fi: On your phone or computer, look for a Wi-Fi network named ProtestInfo_XXXX (where XXXX is a unique identifier from the node's MAC address). Connect to this network. No password is required for the Wi-Fi itself.

Access the Web Interface: Open a web browser. Any URL you type (e.g., http://example.com, http://google.com, or directly http://192.168.4.1) should redirect you to the node's web interface.

View Messages: The main page will display a log of all messages received by this node, with the most recent at the top.

Send Messages: Below the message log, there's a collapsible "Send Message" section.

Enter your message in the text field.

Enter the WEB_PASSWORD (default: password).

Click "Send Message".

Your message will be sent via ESP-NOW to all other trusted nodes in the mesh.

Configuration
You can customize the node's behavior by modifying these #define and const values at the top of the .ino file:

#define USE_DISPLAY true/false:

Set to true if you have a TFT display connected and want messages to appear on it.

Set to false to disable display functionality and save resources if you don't have one.

const char* WEB_PASSWORD = "password";:

Highly Recommended: Change "password" to a strong, unique password for your web interface. This prevents unauthorized users from sending messages.

const uint8_t trustedMACs[][6]:

Essential: As described in Setup Step 4, this array MUST contain the MAC addresses of all ESP32 nodes you want to be part of your mesh. Each node must have the same complete list.

const int WIFI_CHANNEL = 1;:

Defines the Wi-Fi channel for both the SoftAP and ESP-NOW communication. All nodes in your mesh should ideally be on the same channel for optimal performance.

#define MAX_MESSAGE_CONTENT_LEN 239:

The maximum length (in bytes) of the message content. Adjust with caution, as ESP-NOW packets have a maximum payload of 250 bytes.

#define MAX_TTL_HOPS 40:

The maximum number of "hops" (re-broadcasts) a message can make before it's discarded. Increased for potentially larger mesh networks.

const unsigned long DEDUP_CACHE_DURATION_MS = 600000; (10 minutes):

How long a message stays in the cache to prevent it from being processed or re-broadcasted as a duplicate.

const size_t MAX_CACHE_SIZE = 50;:

The maximum number of unique messages to store in the cache to prevent memory exhaustion.

const unsigned long REBROADCAST_CENTER_MS = 240000; (4 minutes):

The central interval for periodic re-broadcasting of cached messages.

const unsigned long REBROADCAST_RANDOM_RANGE_MS = 60000; (+/- 1 minute):

A random range added to REBROADCAST_CENTER_MS to randomize re-broadcast times, helping to avoid "broadcast storms."

const unsigned long REBROADCAST_MIN_AGE_MS = 60000; (1 minute):

Minimum age a message must be in the cache before it is eligible for periodic re-broadcasting.

How it Works (Brief Technical Overview)
Initialization (setup()):

The ESP32 is configured in WIFI_AP_STA mode, acting as both an Access Point and a Wi-Fi station.

A SoftAP is created with a unique SSID (ProtestInfo_XXXX) and a static IP address (192.168.4.1).

A DNS server is started to redirect all DNS requests to the SoftAP's IP, simplifying web access.

ESP-NOW is initialized, and all trustedMACs are added as peers for sending and receiving.

A FreeRTOS queue (messageQueue) is created to safely pass incoming ESP-NOW messages from the interrupt service routine (onDataRecv) to the main loop() for processing.

The Wi-Fi channel is explicitly set for both SoftAP and ESP-NOW to ensure consistency.

Receiving Messages (onDataRecv ISR):

When an ESP-NOW packet arrives, the onDataRecv callback is triggered.

It immediately checks if the message (based on messageID and originalSenderMac) has already been seen using a critical section and a seenMessages cache.

If new and valid (TTL > 0), the message is added to the seenMessages cache and pushed onto the messageQueue for further processing in the main loop.

Processing & Re-broadcasting (loop()):

The loop() continuously checks the messageQueue for new incoming messages.

For each new message, it's prepended to the serialBuffer (for web display) and, if its ttl is still greater than 0, it's re-broadcasted to all other trusted peers using sendToAllPeers().

The sendToAllPeers() function decrements the ttl before sending and avoids sending back to the original sender or itself.

Periodic Re-broadcasting: At random intervals, the loop() iterates through the seenMessages cache. Any messages that are "old enough" (older than REBROADCAST_MIN_AGE_MS) and still have ttl > 0 are re-broadcasted. This helps messages reach all parts of the mesh over time.

Web Server: The loop() also handles incoming HTTP requests. GET requests serve the main web page, while POST requests process user-submitted messages (after password validation) and queue them for ESP-NOW transmission. A POST/Redirect/GET (PRG) pattern is used to prevent duplicate form submissions.

Auto Messages: An automated message is sent periodically to keep the network active if no user messages are sent.

Deduplication Cache (seenMessages):

The seenMessages vector acts as a cache, storing messageID, originalSenderMac, and timestamp of recently seen messages.

When adding new messages, the cache removes the oldest entries if it exceeds MAX_CACHE_SIZE or if entries are older than DEDUP_CACHE_DURATION_MS. This manages memory usage and ensures that messages are eventually forgotten, allowing them to be processed again if they persist in the network after a very long time.

Known Issues and Limitations
Security: This project uses hard-coded MAC addresses for trusted peers and a simple password for the web interface. This is suitable for closed, non-hostile environments. For truly secure applications, consider adding encryption to ESP-NOW and more robust authentication for the web server.

Range: ESP-NOW range depends on environmental factors, antenna quality, and ESP32 power output. Obstacles will reduce range.

Scalability: While ESP-NOW is efficient, very large meshes with many active nodes and high message rates might eventually encounter performance issues due to broadcast storms or cache management on resource-constrained ESP32s. The MAX_CACHE_SIZE, REBROADCAST_CENTER_MS, and MAX_TTL_HOPS can be adjusted.

No Message Persistence (Power Cycle): Messages are stored in RAM. If a node loses power, its serialBuffer and seenMessages cache will be cleared. Messages must be re-propagated by other active nodes.

Web Server Simplicity: The web server is very basic and does not support concurrent connections well, nor does it serve complex assets. It is designed for minimal resource usage.

TFT Display Specifics: The TFT_eSPI library requires configuration for your specific display in its User_Setup.h file. This is not handled by the sketch itself.

Contributing
Feel free to fork this repository, open issues, and submit pull requests.

License
This project is open-source and licensed under the MIT License. See the LICENSE file for more details.
