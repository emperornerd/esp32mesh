#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h> // Include for esp_wifi_set_channel
#include <vector>     // For dynamic array for the cache
#include <algorithm>  // For std::remove_if, std::min_element, std::sort
#include <string.h>   // For strncpy and memset
#include <set>        // For storing unique MACs for display (used for logic to pick 4 unique)
#include <map>        // For storing unique MACs with their last seen timestamp for sorting
#include <DNSServer.h> // REQUIRED: Include for DNS server functionality
#include <esp_system.h> // For esp_read_mac
#include <esp_mac.h>    // For ESP_MAC_WIFI_STA // Corrected from esp_mac.g

#define USE_DISPLAY true

#if USE_DISPLAY
#include <TFT_eSPI.h>
TFT_eSPI tft = TFT_eSPI();
bool displayActive = false;

// Define the T_IRQ pin explicitly here for direct digitalRead debugging
// IMPORTANT: This should match your User_Setup.h for your specific board (e.g., ESP32-CYD)
// Common T_IRQ for CYD: GPIO36 or GPIO39. Please verify your board's pinout.
#define TFT_TOUCH_IRQ_PIN 36 // Example: Change to 39 if your board uses GPIO39 for T_IRQ
#endif

// Hard-coded password for web input
const char* WEB_PASSWORD = "password"; // The password for accessing the message input

// Trusted MACs are now used for both receive and send authorization
// For simplicity, we are assuming all ESP32s in your network will be peers.
// Replace these with the actual MAC addresses of all your ESP32 nodes.
// Example: {0x14, 0x33, 0x5C, 0x06, 0x3A, 0x99} for 14:33:5C:06:3A:99
const uint8_t trustedMACs[][6] = {
  {0x08, 0xA6, 0xF7, 0x47, 0xFA, 0xAD},    // MAC of node A (example, keep if correct for your setup)
  {0x14, 0x33, 0x5C, 0x6D, 0x74, 0x05},    // MAC of node B
  {0x14, 0x33, 0x5C, 0x6C, 0x3A, 0x99}     // MAC of node C
  // Add all other ESP32 MAC addresses here, ensuring they are exact!
};
const int numTrusted = sizeof(trustedMACs) / sizeof(trustedMACs[0]);

// Define a consistent channel for both SoftAP and ESP-NOW
// Channel 1 is a common default and good starting point.
const int WIFI_CHANNEL = 1;

WiFiServer server(80);
IPAddress IP; // This will store the actual IP of the SoftAP (192.168.4.1)
String MAC_full_str; // Full MAC address of this ESP32 (e.g., "AA:BB:CC:DD:EE:FF")
String MAC_suffix_str; // Last 4 chars of our MAC (e.g., "EEFF")
String ssid; // Our unique SSID

// Global variable to store our own MAC address in byte array format for consistency
uint8_t ourMacBytes[6];

String serialBuffer = "";         // Stores messages, most recent on top
String userMessageBuffer = "";  // To hold the user-entered message from POST
String webFeedbackMessage = ""; // To send messages back to the web client (e.g., success/error)

// Global counters for statistics
unsigned long totalMessagesSent = 0;
unsigned long totalMessagesReceived = 0;
unsigned long totalUrgentMessages = 0;

unsigned long lastRebroadcast = 0; // Timestamp for last re-broadcast

int counter = 1; // Still used for the initial auto message

// REQUIRED: Define the static IP address for the SoftAP and DNS server
IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);

// REQUIRED: DNS server object
DNSServer dnsServer;

// --- Message Structure for ESP-NOW and Deduplication ---
// This struct will be used to send and receive messages,
// ensuring each message has a unique ID and original sender MAC.
// Message content size should be 240 bytes (max 250 bytes - 10 for ID/MAC/TTL).
// If you change content size, update MAX_MESSAGE_CONTENT_LEN
#define MAX_MESSAGE_CONTENT_LEN 239 // 250 (max ESP-NOW) - 4 (ID) - 6 (MAC) - 1 (TTL) = 239
#define MAX_TTL_HOPS 40 // Maximum Time-To-Live (hops) for a message (Increased for larger mesh)

typedef struct __attribute__((packed)) {
  uint32_t messageID;         // Unique ID for the message
  uint8_t originalSenderMac[6]; // MAC address of the *original* sender
  uint8_t ttl;                // Time-To-Live (hops remaining)
  char content[MAX_MESSAGE_CONTENT_LEN]; // Message content
} esp_now_message_t;

// --- Cache for Deduplication and Re-broadcasting ---
struct SeenMessage {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  unsigned long timestamp; // When this message was last seen/processed
  esp_now_message_t messageData; // Store the full message for re-broadcasting
};

// Global vector for seen messages and mutex for thread-safe access
// IMPORTANT: Using a mutex for `seenMessages` as it's accessed from ISR context (`onDataRecv`)
// and the main loop.
std::vector<SeenMessage> seenMessages;
portMUX_TYPE seenMessagesMutex = portMUX_INITIALIZER_UNLOCKED;

// Increased cache duration significantly
// This defines how long a message stays in the cache to prevent duplicates.
const unsigned long DEDUP_CACHE_DURATION_MS = 600000; // 10 minutes
// Max number of messages to keep in cache. Prevents memory exhaustion on the ESP32.
const size_t MAX_CACHE_SIZE = 50; 

// New: Fixed interval for periodic re-broadcasting of old messages from cache
// This is critical for synchronization. Shorter times mean faster catch-up for re-connected nodes.
const unsigned long AUTO_REBROADCAST_INTERVAL_MS = 30000; // 30 seconds

// --- FreeRTOS Queue for message processing ---
QueueHandle_t messageQueue;
#define QUEUE_SIZE 10 // Max messages to queue

// --- Display Mode Definitions ---
enum DisplayMode {
  MODE_CHAT_LOG,
  MODE_URGENT_ONLY, // New mode for urgent messages
  MODE_DEVICE_INFO,
  MODE_STATS_INFO // New mode for statistics
};
DisplayMode currentDisplayMode = MODE_CHAT_LOG; // Start with chat log mode

// --- Touch Debounce for Display Mode Switching ---
unsigned long lastTouchTime = 0;
const unsigned long TOUCH_DEBOUNCE_MS = 500; // 500ms debounce

// --- FORWARD DECLARATIONS for display functions ---
#if USE_DISPLAY
void displayChatLogMode(int numLines);
void displayUrgentOnlyMode(int numLines); // New forward declaration
void displayDeviceInfoMode();
void displayStatsInfoMode(); // New forward declaration
#endif
// --- END FORWARD DECLARATION ---

// Helper function to format a byte array MAC address into a String (full MAC)
String formatMac(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// Helper function to get the 4-char suffix from a byte array MAC
String getMacSuffix(const uint8_t *mac) {
  char buf[5]; // 4 chars + null terminator
  snprintf(buf, sizeof(buf), "%02X%02X", mac[4], mac[5]); // Last two bytes (4 hex chars)
  return String(buf);
}

// Corrected: Helper function to format MAC for display as xxxx.xxxx.xxxx.EEFF (last 2 bytes unmasked)
String formatMaskedMac(const uint8_t *mac) {
  char buf[20]; // Sufficient buffer for "xxxx.xxxx.xxxx.EEFF" + null terminator
  // Mask first three segments, then show the last two bytes (mac[4] and mac[5])
  snprintf(buf, sizeof(buf), "xxxx.xxxx.xxxx.%02X%02X",
           mac[4], mac[5]);
  return String(buf);
}

// Function to check if a message is already in the seenMessages cache
bool isMessageSeen(uint32_t id, const uint8_t* mac) {
  // Lock the mutex before accessing the shared resource
  portENTER_CRITICAL(&seenMessagesMutex);
  bool found = false;
  for (const auto& msg : seenMessages) {
    if (msg.messageID == id && memcmp(msg.originalSenderMac, mac, 6) == 0) {
      found = true;
      break;
    }
  }
  // Unlock the mutex
  portEXIT_CRITICAL(&seenMessagesMutex);
  return found;
}

// Function to add or update a message in the seenMessages cache
void addOrUpdateMessageToSeen(uint32_t id, const uint8_t* mac, const esp_now_message_t& msgData) {
  // Lock the mutex before accessing the shared resource
  portENTER_CRITICAL(&seenMessagesMutex);
  unsigned long currentTime = millis();
  bool updated = false;
  // Try to find and update the timestamp if message already exists
  for (auto& msg : seenMessages) {
    if (msg.messageID == id && memcmp(msg.originalSenderMac, mac, 6) == 0) {
      msg.timestamp = currentTime; // Update timestamp
      updated = true;
      break;
    }
  }
  if (!updated) {
    // Remove old entries if not updated
    seenMessages.erase(std::remove_if(seenMessages.begin(), seenMessages.end(),
                                     [currentTime](const SeenMessage& msg) {
                                         return (currentTime - msg.timestamp) > DEDUP_CACHE_DURATION_MS;
                                     }),
                      seenMessages.end());
    // If cache is full, remove the oldest one before adding new
    if (seenMessages.size() >= MAX_CACHE_SIZE) {
      // Find the oldest message (smallest timestamp)
      auto oldest = std::min_element(seenMessages.begin(), seenMessages.end(),
                                     [](const SeenMessage& a, const SeenMessage& b) {
                                         return a.timestamp < b.timestamp;
                                     });
      if (oldest != seenMessages.end()) {
          seenMessages.erase(oldest);
      }
    }
    SeenMessage newMessage = {id, {0}, currentTime, msgData}; // Store full message data
    memcpy(newMessage.originalSenderMac, mac, 6);
    seenMessages.push_back(newMessage);
  }
  // Unlock the mutex
  portEXIT_CRITICAL(&seenMessagesMutex);
}

// Callback function when ESP-NOW data is received
// IMPORTANT: Keep this function as lean as possible!
void onDataRecv(const esp_now_recv_info *recvInfo, const uint8_t *data, int len) {
  // Basic validation of message length
  if (len != sizeof(esp_now_message_t)) {
    // Serial.println("Received malformed ESP-NOW message (wrong size)"); // Cannot print from ISR directly
    return;
  }
  esp_now_message_t incomingMessage;
  // Use memset to clear the structure before copying to avoid junk data,
  // especially if the received 'len' is smaller than the struct (though we check 'len').
  memset(&incomingMessage, 0, sizeof(esp_now_message_t));
  memcpy(&incomingMessage, data, sizeof(esp_now_message_t));

  // Ensure null-termination of the content, as memcpy doesn't guarantee it if source isn't null-terminated
  // or if the source is exactly MAX_MESSAGE_CONTENT_LEN long.
  incomingMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0';

  // Check if already seen based on ID and original sender MAC
  if (isMessageSeen(incomingMessage.messageID, incomingMessage.originalSenderMac)) {
    // If seen, update its timestamp to keep it fresh in cache and prevent its re-broadcast too soon
    addOrUpdateMessageToSeen(incomingMessage.messageID, incomingMessage.originalSenderMac, incomingMessage);
    return; // Duplicate message, discard from immediate processing.
  }
  
  // Add to seen messages cache immediately (including its data for potential future re-broadcast)
  addOrUpdateMessageToSeen(incomingMessage.messageID, incomingMessage.originalSenderMac, incomingMessage);

  // Increment total messages received
  totalMessagesReceived++;
  if (String(incomingMessage.content).startsWith("Urgent: ")) {
      totalUrgentMessages++;
  }

  // --- TTL Check ---
  // Only process and potentially re-broadcast if TTL is greater than 0
  if (incomingMessage.ttl == 0) {
      // Message has reached its hop limit. Do not queue for processing or re-broadcasting.
      return; 
  }

  // If not a duplicate and TTL > 0, push to queue for processing in loop()
  // Use xQueueSendFromISR for ISR context
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  if (xQueueSendFromISR(messageQueue, &incomingMessage, &xHigherPriorityTaskWoken) != pdPASS) {
    // Message dropped due to queue full. Can't print from ISR.
  }
  if (xHigherPriorityTaskWoken == pdTRUE) {
    portYIELD_FROM_ISR(); // Yield to a higher priority task if one was unblocked
  }
}

// Sends a message to all trusted ESP-NOW peers
void sendToAllPeers(esp_now_message_t message) { // Pass by value so we can decrement TTL locally
  // Use the globally stored SoftAP MAC address for comparison
  uint8_t currentMacBytes[6];
  memcpy(currentMacBytes, ourMacBytes, 6);

  // --- Decrement TTL before sending ---
  // This is crucial for re-broadcasted messages.
  if (message.ttl > 0) { 
      message.ttl--; 
  } else {
      // This should ideally not happen if TTL check is done before calling sendToAllPeers
      // but as a safeguard, if TTL is already 0, don't send.
      Serial.println("Attempted to re-broadcast message with TTL 0. Skipping.");
      return;
  }

  for (int i = 0; i < numTrusted; i++) {
    // Prevent sending back to the original sender to avoid loops in the mesh.
    // Also, don't send to ourselves if we are the original sender (to avoid sending it back to us,
    // although our local addMessageToSeen already handles our own messages as "seen").
    if (memcmp(trustedMACs[i], message.originalSenderMac, 6) != 0 && memcmp(trustedMACs[i], currentMacBytes, 6) != 0) {
      esp_err_t result = esp_now_send(trustedMACs[i], (uint8_t*)&message, sizeof(esp_now_message_t));
      if (result != ESP_OK)
        Serial.printf("Send to %s failed (err %d)\n", formatMac(trustedMACs[i]).c_str(), result);
      // Removed TTL from this Serial.printf as well
      // else
      //    Serial.printf("Sent to %s: %s\n", formatMac(trustedMACs[i]).c_str(), message.content);
    } else {
        // Serial.printf("Skipping send to original sender or self: %s\n", formatMac(trustedMACs[i]).c_str());
    }
  }
}

void setup() {
  Serial.begin(115200);
  // Initialize random seed for esp_random() and random()
  // Ensure this is called once at startup
  randomSeed(analogRead(0)); // Standard Arduino way to seed the random number generator

  // Create the FreeRTOS message queue
  messageQueue = xQueueCreate(QUEUE_SIZE, sizeof(esp_now_message_t));
  if (messageQueue == NULL) {
    Serial.println("Failed to create message queue!");
    while(true) { delay(100); } // Halt if queue creation fails
  }

  // Set up WiFi as Access Point + Station (for ESP-NOW and serving web page)
  WiFi.mode(WIFI_AP_STA);
  // Disable WiFi sleep to ensure ESP-NOW can always receive packets
  WiFi.setSleep(false);

  // --- Explicitly configure SoftAP channel and ensure consistency ---
  // Step 1: Set a temporary AP to get the MAC address.
  // We use the WIFI_CHANNEL constant here from the start.
  WiFi.softAP("placeholder", nullptr, WIFI_CHANNEL);
  delay(100);
  MAC_full_str = WiFi.softAPmacAddress(); // Get our own full MAC address (SoftAP MAC)
  
  // Convert our MAC_full_str (SoftAP MAC) to bytes and store it globally
  sscanf(MAC_full_str.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
         (unsigned int*)&ourMacBytes[0], (unsigned int*)&ourMacBytes[1],
         (unsigned int*)&ourMacBytes[2], (unsigned int*)&ourMacBytes[3],
         (unsigned int*)&ourMacBytes[4], (unsigned int*)&ourMacBytes[5]);

  // Calculate our MAC suffix once at startup from the global ourMacBytes
  MAC_suffix_str = getMacSuffix(ourMacBytes);
  ssid = "ProtestInfo_" + MAC_suffix_str;

  // REQUIRED: Configure SoftAP with static IP, Gateway, and DNS (which is its own IP)
  WiFi.softAPConfig(apIP, apIP, netMsk); 
  // Step 2: Configure the actual SoftAP with the unique SSID and the chosen channel.
  // This is the definitive setting for the SoftAP channel.
  WiFi.softAP(ssid.c_str(), nullptr, WIFI_CHANNEL);
  IP = WiFi.softAPIP(); // Get the IP address of our AP (should be apIP)
  server.begin(); // Start the web server

  // REQUIRED: Start DNS server, redirecting all requests to apIP
  dnsServer.start(53, "*", apIP);
  Serial.println("DNS server started, redirecting all domains to: " + apIP.toString());


  // Step 3: Crucially, ensure the underlying Wi-Fi station interface (used by ESP-NOW)
  // is also locked to the same channel. This helps avoid internal channel conflicts.
  esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);

#if USE_DISPLAY
  tft.begin();
  tft.setRotation(1); // Adjust for your specific display orientation (1 for landscape)
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(0, 0);
  tft.println("Starting node...");
  displayActive = true;
  Serial.println("Display initialized");

  // Initialize the T_IRQ pin for touch detection
  pinMode(TFT_TOUCH_IRQ_PIN, INPUT_PULLUP); 
  Serial.printf("T_IRQ pin set to INPUT_PULLUP on GPIO%d\n", TFT_TOUCH_IRQ_PIN);

  // Initial display update
  displayChatLogMode(22); // Show chat log initially
#endif

  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    while(true) { delay(100); } // Halt if ESP-NOW init fails
  }

  // Add trusted peers for sending messages
  for (int i = 0; i < numTrusted; i++) {
    esp_now_del_peer(trustedMACs[i]); // Remove if already exists
    esp_now_peer_info_t peer{}; // Use aggregate initialization for clarity
    memcpy(peer.peer_addr, trustedMACs[i], 6);
    // Peer channel MUST match the SoftAP channel (WIFI_CHANNEL)
    peer.channel = WIFI_CHANNEL;
    peer.encrypt = false;    // No encryption for simplicity in this example
    esp_err_t result = esp_now_add_peer(&peer);
    if (result == ESP_OK)
      Serial.println("Peer added: " + formatMac(trustedMACs[i]));
    else
      Serial.printf("Failed to add peer %s (err %d)\n", formatMac(trustedMACs[i]).c_str(), result);
  }

  // Register the receive callback function
  esp_now_register_recv_cb(onDataRecv);

  // --- Send an auto-generated message once upon initialization ---
  esp_now_message_t autoMessage;
  // It's good practice to clear the struct before populating, especially char arrays
  memset(&autoMessage, 0, sizeof(esp_now_message_t)); 
  autoMessage.messageID = esp_random(); // Still generated for deduplication
  // Use the globally stored SoftAP MAC for the original sender
  memcpy(autoMessage.originalSenderMac, ourMacBytes, 6);
  autoMessage.ttl = MAX_TTL_HOPS; // Initialize TTL for a new message
  
  char msgContentBuf[MAX_MESSAGE_CONTENT_LEN]; // Use a temporary buffer for snprintf
  // Change text to 'Node [last four of mac] initializing'
  snprintf(msgContentBuf, sizeof(msgContentBuf), "Node %s initializing", MAC_suffix_str.c_str()); 
  
  // Copy content from temporary buffer to struct, ensuring null termination
  strncpy(autoMessage.content, msgContentBuf, sizeof(autoMessage.content));
  autoMessage.content[sizeof(autoMessage.content) - 1] = '\0'; // Explicitly ensure null termination

  // Formatted string WITHOUT messageID or TTL
  String formattedMessage = "Node " + MAC_suffix_str + " - " + String(autoMessage.content);
  // Add to seen messages cache immediately (so we don't process our own broadcast as an incoming message)
  // Store the full message data for potential re-broadcast later
  addOrUpdateMessageToSeen(autoMessage.messageID, autoMessage.originalSenderMac, autoMessage);

  // Prepend new messages to buffer (most recent on top)
  serialBuffer = formattedMessage + "\n" + serialBuffer; // Prepend here
  Serial.println("Sending (Auto): " + formattedMessage);
  totalMessagesSent++; // Increment total messages sent
  counter++; // Increment counter for future potential use, though only one auto message is sent
  if (serialBuffer.length() > 4000) // Keep buffer manageable
    serialBuffer = serialBuffer.substring(0, 4000); // Truncate from the end
  sendToAllPeers(autoMessage); // Send via ESP-NOW

  // Initialize the lastRebroadcast timestamp for the first check
  lastRebroadcast = millis();
}

void loop() {
  // REQUIRED: Process DNS requests
  dnsServer.processNextRequest();

  // --- Process Incoming Messages from Queue ---
  esp_now_message_t receivedMessage;
  bool messageProcessed = false; // Flag to indicate if a message was processed
  while (xQueueReceive(messageQueue, &receivedMessage, 0) == pdPASS) {
    // Ensure content is null-terminated before using with String, just in case
    receivedMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0';
    String incomingContent = String(receivedMessage.content);
    String originalSenderMacSuffix = getMacSuffix(receivedMessage.originalSenderMac); // Use new helper

    // Formatted string: Always include Node prefix, then the content (which might start with "Urgent: ")
    String formattedIncoming = "Node " + originalSenderMacSuffix + " - " + incomingContent;
    
    // Prepend new messages to buffer (most recent on top)
    serialBuffer = formattedIncoming + "\n" + serialBuffer;
    if (serialBuffer.length() > 4000) // Keep buffer from growing too large
      serialBuffer = serialBuffer.substring(0, 4000); // Take the most recent 4000 chars
    Serial.println("Message received from queue: " + formattedIncoming);
    messageProcessed = true; // Set flag
    
    // Re-broadcast the message to other peers (mesh behavior)
    // Only re-broadcast if TTL is still greater than 0 *before* this node decrements it.
    // The `sendToAllPeers` function will handle the decrement itself.
    if (receivedMessage.ttl > 0) {  
        sendToAllPeers(receivedMessage);
    } else {
        Serial.println("Message reached TTL limit, not re-broadcasting.");
    }
  }

  // --- Periodic Re-broadcast of Old Messages from Cache ---
  if (millis() - lastRebroadcast >= AUTO_REBROADCAST_INTERVAL_MS) {
    lastRebroadcast = millis(); // Reset the timer
    Serial.printf("Performing periodic re-broadcast of cache. Next check in %lu ms.\n", AUTO_REBROADCAST_INTERVAL_MS);
    
    portENTER_CRITICAL(&seenMessagesMutex); // Lock while iterating/modifying cache
    std::vector<esp_now_message_t> messagesToRebroadcast;
    // MODIFIED: Re-broadcast ALL messages in cache that still have TTL
    for (const auto& seenMsg : seenMessages) {
      if (seenMsg.messageData.ttl > 0) {
        messagesToRebroadcast.push_back(seenMsg.messageData);
      }
    }
    portEXIT_CRITICAL(&seenMessagesMutex); // Unlock after preparing list

    for (const auto& msg : messagesToRebroadcast) {
      Serial.printf("Re-broadcasting cached message from Node %s: %s (TTL: %d)\n",
                    getMacSuffix(msg.originalSenderMac).c_str(), msg.content, msg.ttl);
      sendToAllPeers(msg); // This will decrement TTL before sending
      // Update the timestamp in the cache for the re-broadcasted message
      // This ensures it stays in the cache for the full DEDUP_CACHE_DURATION_MS from *now*
      addOrUpdateMessageToSeen(msg.messageID, msg.originalSenderMac, msg);
    }
  }

  // Handle incoming HTTP client requests
  WiFiClient client = server.available();
  if (client) {
    String currentLine = "";
    String postBody = "";
    bool isPost = false;
    unsigned long clientTimeout = millis(); // Timeout for reading client data
    int contentLength = 0; // To store Content-Length for POST requests
    String requestedPath = "/"; // Default to root path

    // Read the client's request line by line
    while (client.connected() && (millis() - clientTimeout < 2000)) { // Timeout after 2 seconds of inactivity
      if (client.available()) {
        clientTimeout = millis(); // Reset timeout as long as data is coming in
        char c = client.read();
        if (c == '\n') {
          // If the current line is blank, we've reached the end of the HTTP headers
          if (currentLine.length() == 0) {
            // --- CAPTIVE PORTAL REDIRECTION LOGIC ---
            // If the requested path is not the root ("/") AND it's a GET request,
            // send a 302 redirect to our main page.
            if (!isPost && requestedPath != "/") { // Only apply to GET requests
                Serial.println("Intercepted non-root GET request for: " + requestedPath + ". Redirecting to captive portal.");
                client.println(F("HTTP/1.1 302 Found"));
                client.println(F("Location: http://192.168.4.1/")); // Redirect to the main page
                client.println(F("Connection: close"));
                client.println(); // End of headers
                client.stop(); // Close the connection
                return; // Crucially, exit function after redirecting
            }

            if (isPost) {
              // Read the POST body based on Content-Length (important for proper parsing)
              for (int i = 0; i < contentLength && client.available(); i++) {
                postBody += (char)client.read();
              }
              Serial.println("Received POST Body: " + postBody);
              // Parse the POST body for message and password parameters
              String messageParam = "";
              String passwordParam = "";
              String urgentParam = ""; // Added for urgent checkbox
              String actionParam = ""; // New: To identify which form was submitted

              int messageStart = postBody.indexOf("message=");
              if (messageStart != -1) {
                int messageEnd = postBody.indexOf('&', messageStart);
                if (messageEnd == -1) messageEnd = postBody.length(); // If '&' not found, it's the end
                messageParam = postBody.substring(messageStart + 8, messageEnd);
              }
              int passwordStart = postBody.indexOf("password=");
              if (passwordStart != -1) {
                int passwordEnd = postBody.indexOf('&', passwordStart);
                if (passwordEnd == -1) passwordEnd = postBody.length();
                passwordParam = postBody.substring(passwordStart + 9, passwordEnd);
              }
              // Check for urgent parameter
              int urgentStart = postBody.indexOf("urgent=");
              if (urgentStart != -1) {
                urgentParam = "on"; // Checkbox is typically "on" if checked, or absent if not
              }
              // Check for action parameter
              int actionStart = postBody.indexOf("action=");
              if (actionStart != -1) {
                int actionEnd = postBody.indexOf('&', actionStart);
                if (actionEnd == -1) actionEnd = postBody.length();
                actionParam = postBody.substring(actionStart + 7, actionEnd);
              }


              // --- Handle different form submissions ---
              if (actionParam == "sendMessage") {
                // --- URL DECODING FOR MESSAGE ---
                messageParam.replace('+', ' '); // Replace '+' with spaces from URL encoding
                String decodedMessage = "";
                for (int i = 0; i < messageParam.length(); i++) {
                  if (messageParam.charAt(i) == '%' && (i + 2) < messageParam.length()) {
                    // Convert hex to character
                    char decodedChar = (char)strtol((messageParam.substring(i + 1, i + 3)).c_str(), NULL, 16);
                    decodedMessage += decodedChar;
                    i += 2; // Skip the two hex characters
                  } else {
                    decodedMessage += messageParam.charAt(i);
                  }
                }
                
                // --- Password Validation and Message Processing ---
                if (passwordParam != WEB_PASSWORD) {
                  webFeedbackMessage = "<p class='feedback' style='color:red;'>Incorrect password. Message not sent.</p>";
                  Serial.println("Incorrect password entered.");
                } else if (decodedMessage.length() == 0) {
                  webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>";
                } else {
                  // Prepend "Urgent: " if checkbox was checked
                  if (urgentParam == "on") {
                    decodedMessage = "Urgent: " + decodedMessage;
                  }

                  // IMPORTANT: Ensure decodedMessage length doesn't exceed MAX_MESSAGE_CONTENT_LEN - 1
                  if (decodedMessage.length() >= MAX_MESSAGE_CONTENT_LEN) {
                      decodedMessage = decodedMessage.substring(0, MAX_MESSAGE_CONTENT_LEN - 1);
                      webFeedbackMessage = "<p class='feedback' style='color:orange;'>Message truncated due to length limit.</p>";
                  }
                  userMessageBuffer = decodedMessage; // Store message for ESP-NOW sending
                  webFeedbackMessage = "<p class='feedback' style='color:green;'>Message queued for sending!</p>" + webFeedbackMessage; // Append any previous feedback
                  Serial.println("User message received from web: " + userMessageBuffer);
                }
              } else if (actionParam == "rebroadcastCache") {
                // --- Password Validation for Re-broadcast Cache ---
                if (passwordParam != WEB_PASSWORD) {
                  webFeedbackMessage = "<p class='feedback' style='color:red;'>Incorrect password. Re-broadcast failed.</p>";
                  Serial.println("Incorrect password entered for re-broadcast.");
                } else {
                  int rebroadcastedCount = 0;
                  portENTER_CRITICAL(&seenMessagesMutex); // Lock while iterating/modifying cache
                  std::vector<esp_now_message_t> messagesToRebroadcast;
                  // MODIFIED: Re-broadcast ALL messages in cache that still have TTL
                  for (const auto& seenMsg : seenMessages) {
                    if (seenMsg.messageData.ttl > 0) {
                      messagesToRebroadcast.push_back(seenMsg.messageData);
                    }
                  }
                  portEXIT_CRITICAL(&seenMessagesMutex); // Unlock after preparing list

                  for (const auto& msg : messagesToRebroadcast) {
                    Serial.printf("Manually re-broadcasting cached message from Node %s: %s (TTL: %d)\n",
                                  getMacSuffix(msg.originalSenderMac).c_str(), msg.content, msg.ttl);
                    sendToAllPeers(msg); // This will decrement TTL before sending
                    // Update the timestamp in the cache for the re-broadcasted message
                    addOrUpdateMessageToSeen(msg.messageID, msg.originalSenderMac, msg);
                    rebroadcastedCount++;
                  }
                  webFeedbackMessage = "<p class='feedback' style='color:green;'>Re-broadcasted " + String(rebroadcastedCount) + " messages from cache!</p>";
                  Serial.printf("Manually re-broadcasted %d messages from cache.\n", rebroadcastedCount);
                }
              }


              // --- IMPLEMENT POST/REDIRECT/GET (PRG) PATTERN ---
              // Send a 303 See Other redirect to the same URL.
              // This prevents duplicate submissions if the user refreshes or uses back/forward.
              client.println(F("HTTP/1.1 303 See Other"));
              client.println(F("Location: /")); // Redirect to the root path
              client.println(F("Connection: close"));
              client.println(); // End of headers
              client.stop(); // Close the connection
              return; // Crucially, exit function after redirecting
            } // End if (isPost)

            // --- Gather unique seen MACs for display (most recent four) ---
            // This part is for GET requests only, as POST now redirects
            std::map<String, unsigned long> uniqueRecentMacsMap; 

            portENTER_CRITICAL(&seenMessagesMutex); // Lock while accessing seenMessages
            // Populate the map with the latest timestamp for each unique MAC
            for (const auto& seenMsg : seenMessages) {
                String fullMacStr = formatMac(seenMsg.originalSenderMac);
                // If MAC not in map, or new timestamp is more recent, update it
                if (uniqueRecentMacsMap.find(fullMacStr) == uniqueRecentMacsMap.end() || 
                    seenMsg.timestamp > uniqueRecentMacsMap[fullMacStr]) {
                    uniqueRecentMacsMap[fullMacStr] = seenMsg.timestamp;
                }
            }
            portEXIT_CRITICAL(&seenMessagesMutex); // Unlock

            // Now, transfer map contents to a vector of pairs for sorting
            std::vector<std::pair<String, unsigned long>> sortedUniqueMacs;
            for (auto const& [macStr, timestamp] : uniqueRecentMacsMap) {
                sortedUniqueMacs.push_back({macStr, timestamp});
            }

            // Sort by timestamp in descending order (most recent first)
            std::sort(sortedUniqueMacs.begin(), sortedUniqueMacs.end(),
                      [](const std::pair<String, unsigned long>& a, const std::pair<String, unsigned long>& b) {
                          return a.second > b.second; // Descending order of timestamp
                      });

            String detectedNodesHtmlContent = "";
            detectedNodesHtmlContent += "<div class='recent-senders-display-wrapper'>"; 
            detectedNodesHtmlContent += "<span class='detected-nodes-label'>Senders:</span>"; 
            detectedNodesHtmlContent += "<div class='detected-nodes-mac-list'>"; 
            // Take up to the most recent 4 unique MACs
            int count = 0;
            for (const auto& macPair : sortedUniqueMacs) {
                if (count >= 4) break; // Limit to 4 unique MACs
                
                // Convert the full MAC string (from macPair.first) back to bytes to mask for display
                uint8_t macBytes[6];
                sscanf(macPair.first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", 
                       (unsigned int*)&macBytes[0], (unsigned int*)&macBytes[1], 
                       (unsigned int*)&macBytes[2], (unsigned int*)&macBytes[3], 
                       (unsigned int*)&macBytes[4], (unsigned int*)&macBytes[5]);

                detectedNodesHtmlContent += "<span class='detected-node-item-compact'>" + formatMaskedMac(macBytes) + "</span>";
                count++;
            }
            // If empty, add a placeholder
            if (count == 0) {
                detectedNodesHtmlContent += "<span class='detected-node-item-compact'>None</span>";
            }
            detectedNodesHtmlContent += "</div>"; // Close detected-nodes-mac-list
            detectedNodesHtmlContent += "</div>"; // Close recent-senders-display-wrapper


            // --- Send HTTP Response for GET request ---
            client.println(F("HTTP/1.1 200 OK"));
            client.println(F("Content-type:text/html"));
            client.println(F("Connection: close")); // Close connection after response
            client.println(); // Blank line signals end of headers
            client.println(F("<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"));
            client.println(F("<title>Protest Info Node</title>")); // Added title for browser tab
            client.println(F("<style>"));
            client.println(F("body{font-family:Helvetica, Arial, sans-serif;margin:0;padding:0;background-color:#f8f8f8;color:#333;display:flex;flex-direction:column;min-height:100vh;}"));
            
            // Header: simple centered content
            client.println(F("header{background-color:#f0f0f0;padding:10px 15px;border-bottom:1px solid #ddd;width:100%;text-align:center;}"));
            
            client.println(F("h1, h2, h3 {margin:0;padding:5px 0;color:#333;text-align:center;}"));
            client.println(F("h1{font-size:1.4em;}"));
            client.println(F("h2{font-size:1.2em;}"));
            client.println(F("h3{font-size:1.1em;margin-bottom:10px;}"));
            client.println(F("p{margin:3px 0;font-size:0.9em;text-align:center;}"));
            client.println(F(".info-line{font-size:0.8em;color:#666;margin-bottom:10px;}")); // For IP/MAC info
            
            // Flexbox container for main content (always column, no sidebar)
            client.println(F(".content-wrapper {"));
            client.println(F("  display: flex;"));
            client.println(F("  flex-direction: column;"));
            client.println(F("  align-items: center;"));
            client.println(F("  width: 100%; /* Full width */"));
            client.println(F("  max-width: 900px; /* Overall max width for content */"));
            client.println(F("  margin: 15px auto; /* Center the wrapper and add vertical margin */"));
            client.println(F("  padding: 0 10px; /* Horizontal padding for wrapper */"));
            client.println(F("  flex-grow: 1; /* Allow content to grow and fill vertical space */"));
            client.println(F("}"));

            // Main message log area
            client.println(F(".chat-main-content {"));
            client.println(F("  flex: 1; /* Allows it to grow and shrink */"));
            client.println(F("  width: 100%; /* Full width */"));
            client.println(F("  max-width: 700px; /* Adjusted max width for chat content to be more central */"));
            client.println(F("  margin: 0 auto; /* Center the chat content block */"));
            client.println(F("  background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);border:1px solid #ddd;"));
            client.println(F("}"));

            client.println(F("pre{background:#eee;padding:10px;border-radius:5px;text-align:left;max-width:100%;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;font-size:0.85em;border:1px solid #ccc;min-height:200px;}"));
            
            // Form specific styles
            client.println(F("details{background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);max-width:450px;margin:15px auto;border:1px solid #ddd;}"));
            client.println(F("summary{font-size:1.1em;font-weight:bold;cursor:pointer;padding:5px 0;text-align:center;}"));
            client.println(F("form{display:flex;flex-direction:column;align-items:center;margin-top:10px;}"));
            client.println(F("label{font-size:0.9em;margin-bottom:5px;align-self:flex-start;width:80%;}"));
            client.println(F("input[type=text], input[type=password]{width:80%;max-width:350px;padding:8px;margin-bottom:10px;border-radius:4px;border:1px solid #ccc;font-size:0.9em;}"));
            client.println(F("input[type=submit]{background-color:#007bff;color:white;padding:8px 15px;border:none;border-radius:4px;cursor:pointer;font-size:1em;transition:background-color 0.3s ease;}"));
            client.println(F("input[type=submit]:hover{background-color:#0056b3;}"));
            
            // Feedback messages
            client.println(F("p.feedback {font-weight: bold; margin: 10px auto; padding: 8px; border-radius: 5px; border: 1px solid; max-width: 90%; text-align: center; font-size: 0.9em;}"));
            client.println(F("p.feedback[style*='color:green'] { background-color: #e6ffe6; border-color: #00cc00;}"));
            client.println(F("p.feedback[style*='color:red'] { background-color: #ffe6e6; border-color: #cc0000;}"));
            client.println(F("p.feedback[style*='color:orange'] { background-color: #fff8e6; border-color: #ff9900;}"));

            // --- Updated Styles for the compact detected nodes container (now below form) ---
            client.println(F(".recent-senders-display-wrapper {"));
            client.println(F("  display: flex;"));
            client.println(F("  flex-direction: column; /* Stack label and MAC list vertically */"));
            client.println(F("  align-items: center; /* Center contents */"));
            client.println(F("  width: 100%; /* Full width within its parent */"));
            client.println(F("  max-width: 450px; /* Max width to match the form */"));
            client.println(F("  background: #e6f7ff; /* Light blue background for the bubble */"));
            client.println(F("  border: 1px solid #cceeff;"));
            client.println(F("  border-radius: 12px; /* Rounded corners */"));
            client.println(F("  padding: 10px 15px;"));
            client.println(F("  font-size: 0.75em; /* Smaller font */"));
            client.println(F("  color: #0056b3; /* Darker blue text */"));
            client.println(F("  margin: 15px auto; /* Center this block horizontally */")); 
            client.println(F("}"));

            client.println(F(".detected-nodes-label {"));
            client.println(F("  font-weight: bold;"));
            client.println(F("  margin-bottom: 5px; /* Space below label */"));
            client.println(F("  color: #003366;"));
            client.println(F("}"));

            client.println(F(".detected-nodes-mac-list {"));
            client.println(F("  display: flex;"));
            client.println(F("  flex-wrap: wrap; /* Allow MACs to wrap */"));
            client.println(F("  justify-content: center; /* Center MACs if they wrap */"));
            client.println(F("  gap: 8px; /* Space between individual MAC addresses */"));
            client.println(F("  width: 100%; /* Ensure flex items fill width for centering */"));
            client.println(F("}"));

            client.println(F(".detected-node-item-compact {"));
            client.println(F("  /* No specific background or padding, just text style */"));
            client.println(F("}"));
            
            client.println(F("</style></head><body>"));
            client.println(F("<header>"));
            client.println(F("<h1>Protest Information Node</h1>"));
            client.printf("<p class='info-line'><strong>IP:</strong> %s | <strong>MAC:</strong> %s</p>", IP.toString().c_str(), MAC_suffix_str.c_str());
            client.println(F("</header>"));

            // Main content wrapper
            client.println(F("<div class='content-wrapper'>"));
            
            client.println(F("<div class='chat-main-content'>")); // Start of main content area
            // Display feedback message from server processing
            if (webFeedbackMessage.length() > 0) {
              client.println(webFeedbackMessage);
              webFeedbackMessage = ""; // Clear for next request
            }
            
            client.println(F("<h2>Serial Data Log:</h2><pre>"));
            client.print(serialBuffer); // This will naturally show most recent on top
            client.println(F("</pre>"));

            // --- Collapsible Text input form ---
            client.println(F("<details>"));
            client.println(F("<summary>Send Message</summary>")); // Clickable summary
            client.println(F("<h3>Send a New Message:</h3>")); // Adjusted heading size for form
            client.println(F("<form action=\"/\" method=\"POST\">"));
            client.println(F("<input type=\"hidden\" name=\"action\" value=\"sendMessage\">")); // Hidden field to identify form
            client.println(F("<label for=\"message_input\">Message:</label>"));
            client.println(F("<input type=\"text\" id=\"message_input\" name=\"message\" placeholder=\"Enter your message here\" required maxlength=\"226\">")); 
            client.println(F("<label for=\"password_input\">Password:</label>")); // Added password label
            client.println(F("<input type=\"password\" id=\"password_input\" name=\"password\" placeholder=\"Enter password\" required>")); // Added password input field
            // Added Urgent checkbox
            client.println(F("<div style=\"display:flex; align-items:center; justify-content:center; width:80%; max-width:350px; margin-bottom:10px;\">"));
            client.println(F("<input type=\"checkbox\" id=\"urgent_input\" name=\"urgent\" style=\"margin-right: 8px;\">"));
            client.println(F("<label for=\"urgent_input\" style=\"margin-bottom: 0; align-self: center;\">Urgent</label>"));
            client.println(F("</div>"));
            client.println(F("<input type=\"submit\" value=\"Send Message\">"));
            client.println(F("</form>"));
            client.println(F("</details>"));
            // --- End Collapsible Text input form ---

            // --- New: Re-broadcast Cache Button Form ---
            client.println(F("<details style='margin-top: 15px;'>")); // Add some top margin
            client.println(F("<summary>Re-broadcast Cache</summary>"));
            client.println(F("<h3>Force Re-broadcast:</h3>"));
            client.println(F("<form action=\"/\" method=\"POST\">"));
            client.println(F("<input type=\"hidden\" name=\"action\" value=\"rebroadcastCache\">")); // Hidden field to identify form
            client.println(F("<label for=\"rebroadcast_password_input\">Password:</label>")); // Added password label for re-broadcast
            client.println(F("<input type=\"password\" id=\"rebroadcast_password_input\" name=\"password\" placeholder=\"Enter password\" required>")); // Added password input field
            client.println(F("<input type=\"submit\" value=\"Re-broadcast Cached Messages\">"));
            client.println(F("</form>"));
            client.println(F("</details>"));
            // --- End Re-broadcast Cache Button Form ---

            // --- Recent Senders display, now under the form ---
            client.print(detectedNodesHtmlContent);
            
            client.println(F("</div>")); // End of chat-main-content
            
            client.println(F("</div>")); // End of content-wrapper
            client.println(F("</body></html>"));
            break; // Exit while loop after sending response
          } else { // Reading HTTP headers
            // Check for GET or POST request method
            if (currentLine.startsWith("GET")) {
              isPost = false;
              // Extract the path from the GET request line
              int pathStart = currentLine.indexOf(' ') + 1;
              int pathEnd = currentLine.indexOf(' ', pathStart);
              if (pathStart != -1 && pathEnd != -1 && pathEnd > pathStart) {
                requestedPath = currentLine.substring(pathStart, pathEnd);
              }
            } else if (currentLine.startsWith("POST")) {
              isPost = true;
            }
            // Look for Content-Length header for POST requests
            int contentLengthIndex = currentLine.indexOf("Content-Length: ");
            if (contentLengthIndex != -1) {
              contentLength = currentLine.substring(contentLengthIndex + 16).toInt();
            }
            currentLine = ""; // Clear currentLine for the next header
          }
        } else if (c != '\r') {
          currentLine += c; // Build up the current line
        }
      }
    }
    client.stop(); // Close the connection when done or timed out
  }

  // --- Process User Message (if successfully validated from the web interface) ---
  if (userMessageBuffer.length() > 0) {
    esp_now_message_t userEspNowMessage;
    // Clear the struct to ensure all bytes are zero, especially the content buffer
    memset(&userEspNowMessage, 0, sizeof(esp_now_message_t)); 
    userEspNowMessage.messageID = esp_random(); // Still generated for deduplication
    // Use the globally stored SoftAP MAC for the original sender
    memcpy(userEspNowMessage.originalSenderMac, ourMacBytes, 6);
    userEspNowMessage.ttl = MAX_TTL_HOPS; // Initialize TTL for a new message
    
    // Copy content from String to char array, ensuring null termination.
    strncpy(userEspNowMessage.content, userMessageBuffer.c_str(), MAX_MESSAGE_CONTENT_LEN);
    userEspNowMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0'; // Explicitly ensure null termination

    // Increment urgent message count for messages sent by this node if it's urgent
    if (userMessageBuffer.startsWith("Urgent: ")) { 
        totalUrgentMessages++; 
    }
    
    // Formatted string: Always include User via Node prefix, then the content (which might start with "Urgent: ")
    String messageToSendFormatted = "User via Node " + MAC_suffix_str + " - " + userMessageBuffer;
    
    // Add to seen messages cache immediately, storing the full message for potential re-broadcast
    addOrUpdateMessageToSeen(userEspNowMessage.messageID, userEspNowMessage.originalSenderMac, userEspNowMessage);

    // Prepend new messages to serialBuffer (most recent on top) and send via ESP-NOW
    serialBuffer = messageToSendFormatted + "\n" + serialBuffer; // Prepend here
    Serial.println("Broadcasting (User): " + messageToSendFormatted);
    totalMessagesSent++; // Increment total messages sent
    if (serialBuffer.length() > 4000) // Keep buffer manageable
      serialBuffer = serialBuffer.substring(0, 4000); // Truncate from the end
    sendToAllPeers(userEspNowMessage); // Broadcast the message
    messageProcessed = true; // Set flag
    userMessageBuffer = ""; // Clear the buffer after processing
  }

#if USE_DISPLAY
  // --- Touch Detection and Display Mode Switching ---
  if (digitalRead(TFT_TOUCH_IRQ_PIN) == LOW && (millis() - lastTouchTime > TOUCH_DEBOUNCE_MS)) {
    // Touch detected and debounced
    lastTouchTime = millis();
    Serial.println("Touch detected! Switching display mode.");

    // Cycle through the four display modes
    if (currentDisplayMode == MODE_CHAT_LOG) {
      currentDisplayMode = MODE_URGENT_ONLY;
      displayUrgentOnlyMode(22); // Display urgent messages
    } else if (currentDisplayMode == MODE_URGENT_ONLY) {
      currentDisplayMode = MODE_DEVICE_INFO;
      displayDeviceInfoMode(); // Display device info
    } else if (currentDisplayMode == MODE_DEVICE_INFO) {
      currentDisplayMode = MODE_STATS_INFO; // New stats mode
      displayStatsInfoMode(); // Display stats info
    }
    else { // currentDisplayMode == MODE_STATS_INFO
      currentDisplayMode = MODE_CHAT_LOG;
      displayChatLogMode(22); // Display all messages
    }
  }

  // Only refresh display if a message was processed or if we're in device info mode
  // and need to periodically update the seen devices.
  // For simplicity, we'll just refresh on message processing or mode switch.
  // A more advanced approach might have a separate timer for device info mode refresh.
  if (messageProcessed) {
    if (currentDisplayMode == MODE_CHAT_LOG) {
      displayChatLogMode(22);
    } else if (currentDisplayMode == MODE_URGENT_ONLY) {
      displayUrgentOnlyMode(22);
    } else if (currentDisplayMode == MODE_STATS_INFO) { // Refresh stats mode on new message
      displayStatsInfoMode();
    }
    // No need to refresh device info mode here, it refreshes on touch or if a message
    // was processed and it was the active mode (which is handled by the touch logic).
  }
#endif
}

// Displays the most recent N lines of the serialBuffer on the TFT display
#if USE_DISPLAY
void displayChatLogMode(int numLines) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str); // Set MAC to green (purple for user)
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString()); // Keep IP as green (purple for user)
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: All Messages"); // Updated mode name
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  // Since serialBuffer has most recent on top, we just print from the beginning
  int linesPrinted = 0;
  int lineStart = 0;
  while (linesPrinted < numLines && lineStart < serialBuffer.length()) {
    int lineEnd = serialBuffer.indexOf('\n', lineStart);
    if (lineEnd == -1) lineEnd = serialBuffer.length(); // Last line
    String line = serialBuffer.substring(lineStart, lineEnd);
    tft.println(line);
    lineStart = lineEnd + 1;
    linesPrinted++;
  }
}

// New function: Displays only urgent messages from the serialBuffer on the TFT display
void displayUrgentOnlyMode(int numLines) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString());
  tft.setTextColor(TFT_GREEN);        tft.println("Mode: Urgent Only"); // Changed to green
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  
  int linesPrinted = 0;
  int lineStart = 0;
  while (linesPrinted < numLines && lineStart < serialBuffer.length()) {
    int lineEnd = serialBuffer.indexOf('\n', lineStart);
    if (lineEnd == -1) lineEnd = serialBuffer.length(); // Last line
    String line = serialBuffer.substring(lineStart, lineEnd);
    
    // Only print the line if it contains "Urgent: " (now it's always preceded by "Node XXXX - ")
    if (line.indexOf("Urgent: ") != -1) { // Changed to indexOf to find "Urgent: " anywhere in the line
      tft.println(line);
      linesPrinted++;
    }
    lineStart = lineEnd + 1;
  }
}

// Displays device information and nearby detected nodes
void displayDeviceInfoMode() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str); // Set MAC to green (purple for user)
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString()); // Keep IP as green (purple for user)
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: Device Info"); // Set Mode to green (purple for user)
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  tft.println("Nearby Nodes (Last Seen):");

  std::map<String, unsigned long> uniqueRecentMacsMap; 
  // Use the globally stored SoftAP MAC for comparison
  uint8_t selfMacBytes[6]; 
  memcpy(selfMacBytes, ourMacBytes, 6);

  portENTER_CRITICAL(&seenMessagesMutex); // Lock while accessing seenMessages
  // Populate the map with the latest timestamp for each unique MAC
  for (const auto& seenMsg : seenMessages) {
      // Exclude our own MAC from the list of "nearby nodes"
      if (memcmp(seenMsg.originalSenderMac, selfMacBytes, 6) != 0) {
          String fullMacStr = formatMac(seenMsg.originalSenderMac);
          // If MAC not in map, or new timestamp is more recent, update it
          if (uniqueRecentMacsMap.find(fullMacStr) == uniqueRecentMacsMap.end() || 
              seenMsg.timestamp > uniqueRecentMacsMap[fullMacStr]) {
              uniqueRecentMacsMap[fullMacStr] = seenMsg.timestamp;
          }
      }
  }
  portEXIT_CRITICAL(&seenMessagesMutex); // Unlock

  std::vector<std::pair<String, unsigned long>> sortedUniqueMacs;
  for (auto const& [macStr, timestamp] : uniqueRecentMacsMap) {
      sortedUniqueMacs.push_back({macStr, timestamp});
  }

  // Sort by timestamp in descending order (most recent first)
  std::sort(sortedUniqueMacs.begin(), sortedUniqueMacs.end(),
            [](const std::pair<String, unsigned long>& a, const \
            std::pair<String, unsigned long>& b) {
                return a.second > b.second; // Descending order of timestamp
            });

  int linesPrinted = 0;
  // Display up to 15 nearby nodes (adjust as needed for screen size)
  const int MAX_NODES_TO_DISPLAY = 15; 
  if (sortedUniqueMacs.empty()) {
    tft.println("  No other nodes detected yet.");
  } else {
    for (const auto& macPair : sortedUniqueMacs) {
        if (linesPrinted >= MAX_NODES_TO_DISPLAY) break;
        uint8_t macBytes[6];
        sscanf(macPair.first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", 
               (unsigned int*)&macBytes[0], (unsigned int*)&macBytes[1], 
               (unsigned int*)&macBytes[2], (unsigned int*)&macBytes[3], 
               (unsigned int*)&macBytes[4], (unsigned int*)&macBytes[5]);
        
        tft.printf("  %s (seen %lu s ago)\n", 
                   formatMaskedMac(macBytes).c_str(), 
                   (millis() - macPair.second) / 1000);
        linesPrinted++;
    }
  }
}

// New function: Displays board information and communication statistics
void displayStatsInfoMode() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString());
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: Stats Info");
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");

  // Calculate uptime
  unsigned long uptimeMillis = millis();
  unsigned long seconds = uptimeMillis / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  unsigned long days = hours / 24;

  seconds %= 60;
  minutes %= 60;
  hours %= 24;

  tft.println("Uptime:");
  tft.printf("  Days: %lu\n", days);
  tft.printf("  Hours: %lu\n", hours);
  tft.printf("  Minutes: %lu\n", minutes);
  tft.printf("  Seconds: %lu\n", seconds);
  tft.println(""); // Blank line for spacing

  tft.println("Message Stats:");
  tft.printf("  Total Sent: %lu\n", totalMessagesSent);
  tft.printf("  Total Received: %lu\n", totalMessagesReceived);
  tft.printf("  Urgent Messages: %lu\n", totalUrgentMessages);
  tft.printf("  Cache Size: %u/%u\n", seenMessages.size(), MAX_CACHE_SIZE);
}
#endif
