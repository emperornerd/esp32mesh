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
#include <esp_mac.h>    // Corrected: Added .h for esp_mac
#include <freertos/FreeRTOS.h> // Explicitly include FreeRTOS for queue types
#include <freertos/queue.h>    // Explicitly include queue definitions

#define USE_DISPLAY true

#if USE_DISPLAY
#include <TFT_eSPI.h>
TFT_eSPI tft = TFT_eSPI();
bool displayActive = false;

// Define the T_IRQ pin explicitly here for direct digitalRead debugging
#define TFT_TOUCH_IRQ_PIN 36 // Example: Change to 39 if your board uses GPIO39 for T_IRQ
#endif

// --- Network Configuration Constants ---
const int WIFI_CHANNEL = 1;
const int WEB_SERVER_PORT = 80;
const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress NET_MASK(255, 255, 255, 0);

// --- Message & Protocol Constants ---
// Maximum content length for the message, allowing for null terminator after decryption.
// The total message size is 250 bytes. With the addition of a 2-byte checksum,
// the content length is reduced from 238 to 236 bytes.
// Total message size: 4 (ID) + 6 (MAC) + 1 (TTL) + 1 (Type) + 2 (Checksum) + 236 (content array) = 250 bytes.
#define MAX_MESSAGE_CONTENT_LEN 236 // Max actual content length (reduced for checksum)
#define MAX_TTL_HOPS 40 // Maximum Time-To-Live (hops) for a message

// Message types for display prioritization
#define MSG_TYPE_ORGANIZER 0
#define MSG_TYPE_PUBLIC 1
#define MSG_TYPE_AUTO_INIT 2
#define MSG_TYPE_COMMAND 3
#define MSG_TYPE_UNKNOWN 4 // Default for messages without explicit type
#define MSG_TYPE_DISCOVERY 5 // New message type for peer discovery
#define MSG_TYPE_PASSWORD_UPDATE 6 // New message type for password updates
#define MSG_TYPE_STATUS_REQUEST 7 // NEW: Request public enable/disable status
#define MSG_TYPE_STATUS_RESPONSE 8 // NEW: Respond with public enable/disable status

// Command prefixes
const char* CMD_PREFIX = "CMD::";
const char* CMD_PUBLIC_ON = "CMD::PUBLIC_ON";
const char* CMD_PUBLIC_OFF = "CMD::PUBLIC_OFF";


// Placing esp_now_message_t definition early to ensure it's recognized by the compiler.
// This uses the typedef struct syntax as provided in your original working code.
typedef struct __attribute__((packed)) {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  uint8_t ttl;
  uint8_t messageType; // Field to identify message type (organizer, public, etc.)
  uint16_t checksum;   // New field for integrity check
  char content[MAX_MESSAGE_CONTENT_LEN]; // Fixed size content buffer
} esp_now_message_t;


// The plaintext password for organizer access. This will be hashed at runtime.
// NOTE: This initial value is used only once at setup to generate the initial hashedOrganizerPassword.
// The actual password for login will be stored and updated in hashedOrganizerPassword.
const char* WEB_PASSWORD = "password"; 
// Stores the hash of WEB_PASSWORD, calculated at setup, and updated on password reset.
String hashedOrganizerPassword; 

WiFiServer server(WEB_SERVER_PORT);
IPAddress IP; // This will store the actual IP of the SoftAP (192.168.4.1)
String MAC_full_str; // Full MAC address of this ESP32 (e.g., "AA:BB:CC:DD:EE:FF")
String MAC_suffix_str; // Last 4 chars of our MAC (e.g., "EEFF")
String ssid; // Our unique SSID
uint8_t ourMacBytes[6];

String userMessageBuffer = "";  // To hold the user-entered message from POST
String webFeedbackMessage = ""; // To send messages back to the web client (e.g., success/error)

// --- Session & Authentication Constants ---
String organizerSessionToken = "";          // Stores the active organizer session token
unsigned long sessionTokenTimestamp = 0;    // Timestamp of when the token was created/last used
const unsigned long SESSION_TIMEOUT_MS = 900000; // Session timeout: 15 minutes
bool publicMessagingEnabled = false; // NOT PERSISTED
bool publicMessagingLocked = false; // NEW: True if public messaging has been explicitly disabled by an organizer
bool passwordChangeLocked = false; // NOT PERSISTED: True if organizer password has been set (node capable of sending)

// New flag: Controls if a user is logged into the web UI as an organizer.
bool isOrganizerSessionActive = false; 

int loginAttempts = 0;
unsigned long lockoutTime = 0;
const int MAX_LOGIN_ATTEMPTS = 20;
const unsigned long LOCKOUT_DURATION_MS = 300000; // 5 minutes

// Challenge-response authentication variables
String currentChallengeNonce = "";
unsigned long challengeNonceTimestamp = 0;
const unsigned long CHALLENGE_TIMEOUT_MS = 120000; // Increased to 120 seconds (2 minutes) for nonce validity

// --- Statistics Variables ---
unsigned long totalMessagesSent = 0;
unsigned long totalMessagesReceived = 0;
unsigned long totalUrgentMessages = 0;

// --- Timing & Interval Constants ---
unsigned long lastRebroadcast = 0; // Timestamp for last re-broadcast
const unsigned long DISPLAY_REFRESH_INTERVAL_MS = 10000; // Display refresh interval
unsigned long lastDisplayRefresh = 0;
const unsigned long LOCAL_DISPLAY_LOG_MANAGE_INTERVAL_MS = 5000; // 5 seconds
unsigned long lastLocalDisplayLogManage = 0;
const unsigned long LAST_SEEN_PEERS_MANAGE_INTERVAL_MS = 60000; // 60 seconds
unsigned long lastSeenPeersManage = 0;

// Discovery message interval
const unsigned long PEER_DISCOVERY_INTERVAL_MS = 15000; // Send discovery every 15 seconds
unsigned long lastDiscoveryBroadcast = 0;

// Auto-rebroadcast interval
const unsigned long AUTO_REBROADCAST_INTERVAL_MS = 30000; // 30 seconds

int counter = 1; // Still used for the initial auto message

DNSServer dnsServer;

// Define a Pre-Shared Key (PSK) for symmetric encryption
// This key must be identical on all participating nodes.
// For simplicity and to meet "fully embedded", it's hardcoded.
// In a real-world scenario, this would be provisioned securely.
const uint8_t PRE_SHARED_KEY[] = {
  0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
  0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09
};
const size_t PRE_SHARED_KEY_LEN = sizeof(PRE_SHARED_KEY);

// Simple PRNG state for the stream cipher
uint32_t prng_state;

// Function to seed the PRNG
void seedPrng(const uint8_t* key, size_t keyLen) {
    prng_state = 0;
    for (size_t i = 0; i < keyLen; ++i) {
        prng_state = (prng_state << 8) | key[i]; // Combine key bytes into seed
    }
    if (prng_state == 0) prng_state = 1; // Avoid zero seed
}

// Function to get next PRNG byte
uint8_t getPrngByte() {
    // Simple Linear Congruential Generator (LCG) parameters
    // These are NOT cryptographically secure, but provide a different stream.
    prng_state = (1103515245 * prng_state + 12345); 
    return (uint8_t)(prng_state >> 24); // Take higher bits for better distribution
}

// Stream cipher encryption/decryption using PRNG
// This function performs XOR operation with a PRNG-generated keystream in-place.
void prngStreamCipher(uint8_t* data, size_t dataLen, const uint8_t* key, size_t keyLen) {
    seedPrng(key, keyLen); // Seed PRNG for each operation to ensure determinism
    for (size_t i = 0; i < dataLen; i++) {
        data[i] = data[i] ^ getPrngByte();
    }
}

// Function to calculate a simple checksum (sum of bytes)
uint16_t calculateChecksum(const char* data, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += (uint8_t)data[i]; // Sum of byte values
    }
    return sum;
}


struct SeenMessage {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  unsigned long timestamp;
  esp_now_message_t messageData; // Store the full message data (encrypted) for re-broadcasting
};

std::vector<SeenMessage> seenMessages;
portMUX_TYPE seenMessagesMutex = portMUX_INITIALIZER_UNLOCKED;

// --- Cache & Peer Management Constants ---
const unsigned long DEDUP_CACHE_DURATION_MS = 1800000; // 30 minutes (was 10 minutes)
const size_t MAX_CACHE_SIZE = 100; // Increased from 50
const unsigned long PEER_LAST_SEEN_DURATION_MS = 600000; // 10 minutes for peer cleanup
const unsigned long ESP_NOW_PEER_TIMEOUT_MS = 300000; // 5 minutes for ESP-NOW peer cleanup

// Define a new struct for messages to be queued from ISR to loop()
// This struct should contain only raw C-style data to avoid dynamic allocation in ISR
typedef struct {
    esp_now_message_t messageData; // The raw incoming message (already decrypted by onDataRecv)
    uint8_t senderMac[6];          // MAC of the immediate sender (for peer management)
    unsigned long timestamp;       // Timestamp of reception
} IsrQueueMessage;

QueueHandle_t messageQueue;
const size_t QUEUE_SIZE = 10; // Size of the message queue

// Struct to hold messages for local display, including timestamp for sorting
struct LocalDisplayEntry {
    esp_now_message_t message; // This message will be stored in its decrypted form
    unsigned long timestamp; // Timestamp when this message was added to localDisplayLog
};
std::vector<LocalDisplayEntry> localDisplayLog;
portMUX_TYPE localDisplayLogMutex = portMUX_INITIALIZER_UNLOCKED; // Corrected initialization
const size_t MAX_LOCAL_DISPLAY_LOG_SIZE = 50; // Max number of messages to keep in local display log
const size_t NUM_ORGANIZER_MESSAGES_TO_RETAIN = 5; // Number of most recent organizer messages to always keep
const size_t MAX_WEB_MESSAGE_INPUT_LENGTH = 226; // Max length for message input in HTML
const size_t MAX_POST_BODY_LENGTH = 2048; // Max content length for POST requests

// Map to store MACs of all peers from which messages have been received (for display and peer management)
std::map<String, unsigned long> lastSeenPeers;
portMUX_TYPE lastSeenPeersMutex = portMUX_INITIALIZER_UNLOCKED;

// New map for peers added to ESP-NOW for sending (dynamic list)
std::map<String, unsigned long> espNowAddedPeers;
portMUX_TYPE espNowAddedPeersMutex = portMUX_INITIALIZER_UNLOCKED;


enum DisplayMode {
  MODE_CHAT_LOG,
  MODE_URGENT_ONLY,
  MODE_DEVICE_INFO,
  MODE_STATS_INFO
};
DisplayMode currentDisplayMode = MODE_CHAT_LOG;

unsigned long lastTouchTime = 0;
const unsigned long TOUCH_DEBOUNCE_MS = 500;
const int TFT_CHAT_LOG_LINES = 22; // Number of lines to display in chat log mode
const int TFT_URGENT_ONLY_LINES = 22; // Number of lines to display in urgent only mode
const int MAX_NODES_TO_DISPLAY_TFT = 15; // Max nodes to display on TFT

#if USE_DISPLAY
void displayChatLogMode(int numLines);
void displayUrgentOnlyMode(int numLines);
void displayDeviceInfoMode();
void displayStatsInfoMode();
#endif

// A simple non-cryptographic hash function (DJB2 variant) with a pseudo-salt
String simpleHash(const String& input) {
    // A hardcoded pseudo-salt. This is NOT a true cryptographic salt
    // as it's fixed and known. Its purpose is to make rainbow table attacks
    // against the *default* password slightly harder, as the hash will be
    // different from a standard DJB2 hash of "password".
    const String PSEUDO_SALT = "ProtestNodeSalt123XYZ"; 
    String saltedInput = input + PSEUDO_SALT; // Concatenate input with pseudo-salt

    unsigned long hash = 5381; // Initial value (DJB2 seed)
    for (int i = 0; i < saltedInput.length(); i++) {
        hash = ((hash << 5) + hash) + saltedInput.charAt(i); // hash * 33 + c
    }
    return String(hash, HEX); // Return as hex string
}


String formatMac(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

String getMacSuffix(const uint8_t *mac) {
  char buf[5];
  snprintf(buf, sizeof(buf), "%02X%02X", mac[4], mac[5]);
  return String(buf);
}

String formatMaskedMac(const uint8_t *mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "xxxx.xxxx.xxxx.%02X%02X",
           mac[4], mac[5]);
  return String(buf);
}

String escapeHtml(const String& html) {
  String escaped = html;
  escaped.replace("&", "&amp;");
  escaped.replace("<", "&lt;");
  escaped.replace(">", "&gt;");
  escaped.replace("\"", "&quot;");
  escaped.replace("'", "&#39;");
  return escaped;
}

// Function to add a message to the local display log
void addDisplayLog(const String& message) {
    portENTER_CRITICAL(&localDisplayLogMutex);
    // Create a dummy message structure for the log entry
    // This is a simplified approach for log messages not directly from ESP-NOW
    esp_now_message_t dummyMsg;
    memset(&dummyMsg, 0, sizeof(dummyMsg));
    dummyMsg.messageType = MSG_TYPE_UNKNOWN; // Mark as unknown type for simple log messages
    // Use our own MAC as sender for local log messages
    memcpy(dummyMsg.originalSenderMac, ourMacBytes, 6); 
    // Copy the message content
    message.toCharArray(dummyMsg.content, MAX_MESSAGE_CONTENT_LEN);
    dummyMsg.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0'; // Ensure null termination
    dummyMsg.checksum = calculateChecksum(dummyMsg.content, strlen(dummyMsg.content)); // Calculate checksum for consistency

    LocalDisplayEntry newEntry = {dummyMsg, millis()};
    localDisplayLog.push_back(newEntry);
    if (localDisplayLog.size() > MAX_LOCAL_DISPLAY_LOG_SIZE) {
        // Remove the oldest entry if the log exceeds max size
        localDisplayLog.erase(localDisplayLog.begin());
    }
    portEXIT_CRITICAL(&localDisplayLogMutex);
}


bool isOrganizerSessionValid(const String& token) {
  if (token.length() == 0 || organizerSessionToken.length() == 0) {
    return false;
  }
  if (millis() - sessionTokenTimestamp > SESSION_TIMEOUT_MS) {
    organizerSessionToken = "";
    return false;
  }
  return token == organizerSessionToken;
}

bool isMessageSeen(uint32_t id, const uint8_t* mac) {
  portENTER_CRITICAL(&seenMessagesMutex);
  bool found = false;
  for (const auto& msg : seenMessages) {
    if (msg.messageID == id && memcmp(msg.originalSenderMac, mac, 6) == 0) {
      found = true;
      break;
    }
  }
  portEXIT_CRITICAL(&seenMessagesMutex);
  return found;
}

void addOrUpdateMessageToSeen(uint32_t id, const uint8_t* mac, const esp_now_message_t& msgData) {
  portENTER_CRITICAL(&seenMessagesMutex);
  unsigned long currentTime = millis();
  bool updated = false;
  for (auto& msg : seenMessages) {
    if (msg.messageID == id && memcmp(msg.originalSenderMac, mac, 6) == 0) {
      msg.timestamp = currentTime;
      // The messageData (including its TTL) should remain as it was when first added to the cache,
      // which will be MAX_TTL_HOPS. This ensures re-broadcasts use full TTL potential.
      updated = true;
      break;
    }
  }
  if (!updated) {
    // Remove messages older than DEDUP_CACHE_DURATION_MS first
    seenMessages.erase(std::remove_if(seenMessages.begin(), seenMessages.end(),
                                     [currentTime](const SeenMessage& msg) {
                                         return (currentTime - msg.timestamp) > DEDUP_CACHE_DURATION_MS;
                                     }),
                      seenMessages.end());

    // If cache is still full after removing expired messages, remove the oldest one
    if (seenMessages.size() >= MAX_CACHE_SIZE) {
      auto oldest = std::min_element(seenMessages.begin(), seenMessages.end(),
                                     [](const SeenMessage& a, const SeenMessage& b) {
                                         return a.timestamp < b.timestamp;
                                     });
      if (oldest != seenMessages.end()) {
        seenMessages.erase(oldest);
      }
    }
    // When a message is *first* added to the cache, ensure its stored TTL is MAX_TTL_HOPS.
    // This makes the cache a reliable source for re-broadcasting with full TTL potential.
    esp_now_message_t storedMessage = msgData; // Copy the incoming message data
    storedMessage.ttl = MAX_TTL_HOPS; // Override TTL to its maximum for storage in cache
    SeenMessage newMessage = {id, {0}, currentTime, storedMessage};
    memcpy(newMessage.originalSenderMac, mac, 6);
    seenMessages.push_back(newMessage);
  }
  portEXIT_CRITICAL(&seenMessagesMutex);
}

void onDataRecv(const esp_now_recv_info *recvInfo, const uint8_t *data, int len) {
  if (len != sizeof(esp_now_message_t)) {
    return;
  }
  
  IsrQueueMessage qMsg;
  memset(&qMsg, 0, sizeof(IsrQueueMessage));
  memcpy(&qMsg.messageData, data, sizeof(esp_now_message_t));
  memcpy(qMsg.senderMac, recvInfo->src_addr, 6);
  qMsg.timestamp = millis(); // Timestamp when received by ISR

  // Decrypt the content in ISR before checksum and other checks
  // This is safe because it's an in-place XOR operation on a fixed-size buffer.
  prngStreamCipher((uint8_t*)qMsg.messageData.content, MAX_MESSAGE_CONTENT_LEN, PRE_SHARED_KEY, PRE_SHARED_KEY_LEN);
  qMsg.messageData.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0'; // Ensure null termination after decryption

  // Calculate checksum on the decrypted content in ISR
  uint16_t calculatedChecksum = calculateChecksum(qMsg.messageData.content, strlen(qMsg.messageData.content));

  // Check if the calculated checksum matches the received checksum
  if (calculatedChecksum != qMsg.messageData.checksum) {
      // Checksum mismatch! Dropping message.
      return; // Drop the message if checksum verification fails
  }

  // If message has no TTL left upon arrival, discard it.
  if (qMsg.messageData.ttl == 0) {
      return;
  }

  // Queue the message for further processing in the main loop
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  if (xQueueSendFromISR(messageQueue, &qMsg, 0) != pdPASS) {
    // Message dropped due to queue full
  }
  if (xHigherPriorityTaskWoken == pdTRUE) {
    portYIELD_FROM_ISR();
  }
}

// sendToAllPeers now takes a message by reference so its TTL can be decremented directly
void sendToAllPeers(esp_now_message_t& message) { // Changed to pass by reference
  uint8_t currentMacBytes[6];
  memcpy(currentMacBytes, ourMacBytes, 6);

  if (message.ttl > 0) {
      message.ttl--; // Decrement TTL here, as this is the point of sending (one hop)
  } else {
      Serial.println("Attempted to re-broadcast message with TTL 0. Skipping.");
      return;
  }

  portENTER_CRITICAL(&espNowAddedPeersMutex);
  for (auto const& [macStr, timestamp] : espNowAddedPeers) {
    uint8_t peerMacBytes[6];
    unsigned int tempMac[6];
    sscanf(macStr.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
           &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);
    for (int k = 0; k < 6; ++k) { peerMacBytes[k] = (uint8_t)tempMac[k]; }

    // Only send to peers that are NOT our own MAC and NOT the original sender of this message
    if (memcmp(peerMacBytes, currentMacBytes, 6) != 0 && memcmp(peerMacBytes, message.originalSenderMac, 6) != 0) {
      // The message content is already encrypted when it reaches here.
      esp_now_send(peerMacBytes, (uint8_t*)&message, sizeof(esp_now_message_t));
    }
  }
  portEXIT_CRITICAL(&espNowAddedPeersMutex);
}

// Helper function to create and send an ESP-NOW message (plaintext)
void createAndSendMessage(const char* plaintext_data, size_t plaintext_data_len, uint8_t type, const uint8_t* targetMac = nullptr) {
  // --- Start of capability check ---
  // Node can send Organizer/Public messages if a non-default password has been set (passwordChangeLocked is true)
  if ((type == MSG_TYPE_ORGANIZER || type == MSG_TYPE_PUBLIC) && !passwordChangeLocked) {
    Serial.println("Node not capable of sending this message type (password not set). Skipping send.");
    webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Node not configured to send this message. Set an organizer password first.</p>";
    return; 
  }
  // --- End of capability check ---

  esp_now_message_t newMessage;
  memset(&newMessage, 0, sizeof(newMessage));
  newMessage.messageID = esp_random(); // Use esp_random for message ID
  memcpy(newMessage.originalSenderMac, ourMacBytes, 6);
  newMessage.ttl = MAX_TTL_HOPS; // Set initial TTL
  newMessage.messageType = type; // Set the message type

  // Copy plaintext data, ensuring null termination and max length
  size_t len_to_copy = std::min(plaintext_data_len, (size_t)MAX_MESSAGE_CONTENT_LEN - 1);
  strncpy(newMessage.content, plaintext_data, len_to_copy);
  newMessage.content[len_to_copy] = '\0'; // Ensure null termination for plaintext

  // Calculate checksum on plaintext content BEFORE encryption
  newMessage.checksum = calculateChecksum(newMessage.content, strlen(newMessage.content));

  // Encrypt the message content before sending
  prngStreamCipher((uint8_t*)newMessage.content, MAX_MESSAGE_CONTENT_LEN, PRE_SHARED_KEY, PRE_SHARED_KEY_LEN);

  if (targetMac != nullptr) {
      // Unicast message
      esp_now_send(targetMac, (uint8_t*)&newMessage, sizeof(esp_now_message_t));
      Serial.printf("Sent unicast message (Type: %d, ID: %u) to %02X:%02X:%02X:%02X:%02X:%02X\n",
                    type, newMessage.messageID, MAC2STR(targetMac));
  } else {
      // Broadcast message (sendToAllPeers will decrement TTL on 'newMessage' directly)
      sendToAllPeers(newMessage);
  }
  totalMessagesSent++;

  // Special handling for discovery messages: DO NOT add to cache or local display log
  // Password updates (MSG_TYPE_PASSWORD_UPDATE) are now intended to be cached.
  // Status requests/responses should also not be added to display log
  if (type == MSG_TYPE_DISCOVERY || type == MSG_TYPE_STATUS_REQUEST || type == MSG_TYPE_STATUS_RESPONSE) { 
      return; // Do not proceed further for these message types
  }

  // Add to seen messages (newMessage now has its decremented TTL)
  // addOrUpdateMessageToSeen will store the message with MAX_TTL_HOPS
  // when it's first seen, regardless of its incoming TTL.
  addOrUpdateMessageToSeen(newMessage.messageID, newMessage.originalSenderMac, newMessage);

  // Add to local display log IMMEDIATELY for originating node
  portENTER_CRITICAL(&localDisplayLogMutex);
  // Decrypt for local display immediately after sending
  // Create a copy to decrypt for local display without altering the 'newMessage' that was sent.
  esp_now_message_t displayMessage = newMessage;
  // The checksum is already part of displayMessage, no need to recalculate for display.
  prngStreamCipher((uint8_t*)displayMessage.content, MAX_MESSAGE_CONTENT_LEN, PRE_SHARED_KEY, PRE_SHARED_KEY_LEN); // Decrypt for display
  displayMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0'; // Ensure null termination
  LocalDisplayEntry newEntry = {displayMessage, millis()}; // Store message and its creation timestamp
  localDisplayLog.push_back(newEntry);
  portEXIT_CRITICAL(&localDisplayLogMutex);

  Serial.println("Sending (Plaintext): " + String(plaintext_data));
}

// Function to manage the local display log, ensuring organizer message retention and newest-first order
void manageLocalDisplayLog() {
    portENTER_CRITICAL(&localDisplayLogMutex);

    // 1. Sort the entire log by timestamp, newest first
    std::sort(localDisplayLog.begin(), localDisplayLog.end(), [](const LocalDisplayEntry& a, const LocalDisplayEntry& b) {
        return a.timestamp > b.timestamp; // Newest first
    });

    std::vector<LocalDisplayEntry> newLocalDisplayLog;
    std::set<std::pair<uint32_t, String>> addedMessageKeys; // To track unique messages by ID and MAC suffix

    // 2. Add the most recent organizer messages first
    int organizerCount = 0;
    for (const auto& entry : localDisplayLog) {
        if (entry.message.messageType == MSG_TYPE_ORGANIZER) {
            if (organizerCount < NUM_ORGANIZER_MESSAGES_TO_RETAIN) {
                newLocalDisplayLog.push_back(entry);
                addedMessageKeys.insert({entry.message.messageID, getMacSuffix(entry.message.originalSenderMac)});
                organizerCount++;
            }
        }
    }

    // 3. Add other messages (and any remaining organizer messages not yet added)
    //    until MAX_LOCAL_DISPLAY_LOG_SIZE is reached.
    for (const auto& entry : localDisplayLog) {
        if (newLocalDisplayLog.size() >= MAX_LOCAL_DISPLAY_LOG_SIZE) {
            break; // Max size reached
        }

        // Check if this message has already been added (either as a retained organizer or previously)
        if (addedMessageKeys.find({entry.message.messageID, getMacSuffix(entry.message.originalSenderMac)}) == addedMessageKeys.end()) {
            newLocalDisplayLog.push_back(entry);
            addedMessageKeys.insert({entry.message.messageID, getMacSuffix(entry.message.originalSenderMac)});
        }
    }

    localDisplayLog = newLocalDisplayLog;
    portEXIT_CRITICAL(&localDisplayLogMutex);
}


void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(0));

  publicMessagingEnabled = false;
  publicMessagingLocked = false; // Initialize public messaging lock status as unlocked
  passwordChangeLocked = false; // Initialize password change lock status (node not capable)
  isOrganizerSessionActive = false; // Initialize web session as inactive

  messageQueue = xQueueCreate(QUEUE_SIZE, sizeof(IsrQueueMessage)); // Changed queue type to IsrQueueMessage
  if (messageQueue == NULL) {
    Serial.println("Failed to create message queue!");
    while(true) { delay(100); }
  }

  // Calculate the hash of the WEB_PASSWORD at startup using the simple hash
  hashedOrganizerPassword = simpleHash(WEB_PASSWORD);

  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);

  WiFi.softAP("placeholder", nullptr, WIFI_CHANNEL);
  delay(100);
  MAC_full_str = WiFi.softAPmacAddress();

  sscanf(MAC_full_str.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
         (unsigned int*)&ourMacBytes[0], (unsigned int*)&ourMacBytes[1],
         (unsigned int*)&ourMacBytes[2], (unsigned int*)&ourMacBytes[3],
         (unsigned int*)&ourMacBytes[4], (unsigned int*)&ourMacBytes[5]);

  MAC_suffix_str = getMacSuffix(ourMacBytes);
  ssid = "ProtestInfo_" + MAC_suffix_str;

  WiFi.softAPConfig(AP_IP, AP_IP, NET_MASK);
  WiFi.softAP(ssid.c_str(), nullptr, WIFI_CHANNEL);
  IP = WiFi.softAPIP();
  server.begin();

  dnsServer.start(53, "*", AP_IP);
  Serial.println("DNS server started, redirecting all domains to: " + AP_IP.toString());

  esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);

#if USE_DISPLAY
  tft.begin();
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(0, 0);
  tft.println("Starting node...");
  displayActive = true;
  Serial.println("Display initialized");
  pinMode(TFT_TOUCH_IRQ_PIN, INPUT_PULLUP);
  Serial.printf("T_IRQ pin set to INPUT_PULLUP on GPIO%d\n", TFT_TOUCH_IRQ_PIN);
  displayChatLogMode(TFT_CHAT_LOG_LINES);
#endif

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    while(true) { delay(100); }
  }

  // Add the broadcast MAC address as an initial peer for discovery messages
  uint8_t broadcastMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  esp_now_peer_info_t peer{};
  memcpy(peer.peer_addr, broadcastMac, 6);
  peer.channel = WIFI_CHANNEL;
  peer.encrypt = false; // Custom encryption
  esp_now_add_peer(&peer);
  
  portENTER_CRITICAL(&espNowAddedPeersMutex);
  espNowAddedPeers[formatMac(broadcastMac)] = millis(); // Add broadcast MAC to our dynamic peer list
  portEXIT_CRITICAL(&espNowAddedPeersMutex);

  esp_now_register_recv_cb(onDataRecv);

  // Initial auto-message
  char msgContentBuf[MAX_MESSAGE_CONTENT_LEN];
  snprintf(msgContentBuf, sizeof(msgContentBuf), "Node %s initializing", MAC_suffix_str.c_str());
  createAndSendMessage(msgContentBuf, strlen(msgContentBuf), MSG_TYPE_AUTO_INIT);

  // Initial discovery broadcast
  createAndSendMessage(MAC_full_str.c_str(), MAC_full_str.length(), MSG_TYPE_DISCOVERY);
  lastDiscoveryBroadcast = millis();

  lastRebroadcast = millis();
  lastLocalDisplayLogManage = millis(); // Initialize the timer for display log management
  lastSeenPeersManage = millis(); // Initialize the timer for last seen peers management
}

// Helper to build query string for redirects
String buildQueryString(const String& sessionToken, bool showPublic, bool showUrgent) {
    String query = "";
    if (sessionToken.length() > 0) {
        query += "session_token=" + sessionToken;
    }
    if (showPublic) {
        if (query.length() > 0) query += "&";
        query += "show_public=true";
    }
    if (showUrgent) {
        if (query.length() > 0) query += "&";
        query += "show_urgent=true";
    }
    return query;
}

void loop() {
  dnsServer.processNextRequest();

  IsrQueueMessage qMsg;
  bool messageProcessed = false;
  while (xQueueReceive(messageQueue, &qMsg, 0) == pdPASS) {
    // Process the message received from the ISR queue
    esp_now_message_t incomingMessage = qMsg.messageData; // Copy data from queue struct
    uint8_t* recvInfoSrcAddr = qMsg.senderMac; // Get sender MAC from queue struct
    unsigned long receptionTimestamp = qMsg.timestamp; // Get timestamp from queue struct

    String incomingContent = String(incomingMessage.content);
    String originalSenderMacSuffix = getMacSuffix(incomingMessage.originalSenderMac);

    // Update lastSeenPeers with the MAC of the immediate sender (for display on web/TFT)
    portENTER_CRITICAL(&lastSeenPeersMutex);
    lastSeenPeers[formatMac(recvInfoSrcAddr)] = receptionTimestamp; // Use the timestamp from ISR
    portEXIT_CRITICAL(&lastSeenPeersMutex);

    // Add/Update peer in espNowAddedPeers for sending (dynamic peer management)
    String senderMacStr = formatMac(recvInfoSrcAddr);
    portENTER_CRITICAL(&espNowAddedPeersMutex);
    bool peerExistsInMap = espNowAddedPeers.count(senderMacStr) > 0;
    portEXIT_CRITICAL(&espNowAddedPeersMutex);

    esp_now_peer_info_t peer{};
    memcpy(peer.peer_addr, recvInfoSrcAddr, 6);
    peer.channel = WIFI_CHANNEL;
    peer.encrypt = false; // Custom encryption

    esp_err_t addPeerResult = esp_now_add_peer(&peer);
    if (addPeerResult == ESP_OK || addPeerResult == ESP_ERR_ESPNOW_EXIST) {
      portENTER_CRITICAL(&espNowAddedPeersMutex);
      espNowAddedPeers[senderMacStr] = millis(); // Update timestamp (current millis for sending peers)
      portEXIT_CRITICAL(&espNowAddedPeersMutex);
    } else {
      Serial.printf("Failed to add peer %s: %d\n", senderMacStr.c_str(), addPeerResult);
    }

    // Handle MSG_TYPE_DISCOVERY differently: Do not display, cache, or re-broadcast
    if (incomingMessage.messageType == MSG_TYPE_DISCOVERY) {
        continue; // Stop processing this message further (silently handled)
    }

    // Check if the message has been seen before by THIS node (for display deduplication).
    bool wasAlreadySeen = isMessageSeen(incomingMessage.messageID, incomingMessage.originalSenderMac);

    bool skipDisplayLog = false; // Flag to control display logging

    // Handle MSG_TYPE_STATUS_REQUEST
    if (incomingMessage.messageType == MSG_TYPE_STATUS_REQUEST) {
        Serial.printf("Received STATUS_REQUEST from %02X:%02X:%02X:%02X:%02X:%02X. Replying with status.\n", MAC2STR(incomingMessage.originalSenderMac));
        
        esp_now_message_t outgoingStatusResponse;
        memset(&outgoingStatusResponse, 0, sizeof(outgoingStatusResponse));
        outgoingStatusResponse.messageType = MSG_TYPE_STATUS_RESPONSE;
        memcpy(outgoingStatusResponse.originalSenderMac, ourMacBytes, 6); // Our MAC as sender
        outgoingStatusResponse.messageID = esp_random();
        outgoingStatusResponse.ttl = MAX_TTL_HOPS;
        // Content now includes both publicMessagingEnabled and publicMessagingLocked status
        outgoingStatusResponse.content[0] = publicMessagingEnabled ? '1' : '0'; // '1' for enabled, '0' for disabled
        outgoingStatusResponse.content[1] = publicMessagingLocked ? '1' : '0'; // '1' for locked, '0' for unlocked
        outgoingStatusResponse.content[2] = '\0';
        outgoingStatusResponse.checksum = calculateChecksum(outgoingStatusResponse.content, strlen(outgoingStatusResponse.content));
        
        // Encrypt content before sending
        prngStreamCipher((uint8_t*)outgoingStatusResponse.content, MAX_MESSAGE_CONTENT_LEN, PRE_SHARED_KEY, PRE_SHARED_KEY_LEN);
        
        createAndSendMessage("", 0, MSG_TYPE_STATUS_RESPONSE, incomingMessage.originalSenderMac); // Send unicast back to sender
        Serial.printf("Sent STATUS_RESPONSE (publicEnabled=%s, publicLocked=%s) to %02X:%02X:%02X:%02X:%02X:%02X\n",
                      publicMessagingEnabled ? "true" : "false", publicMessagingLocked ? "true" : "false", MAC2STR(incomingMessage.originalSenderMac));
        continue; // Do not process this message further (no display, no re-broadcast)
    }

    // Handle MSG_TYPE_STATUS_RESPONSE
    if (incomingMessage.messageType == MSG_TYPE_STATUS_RESPONSE) {
        bool peerPublicStatus = (incomingMessage.content[0] == '1'); // Content is '1' or '0'
        bool peerPublicLockedStatus = (incomingMessage.content[1] == '1'); // Content is '1' or '0'
        Serial.printf("Received STATUS_RESPONSE from %02X:%02X:%02X:%02X:%02X:%02X. Peer Public Enabled: %s, Peer Public Locked: %s\n",
                      MAC2STR(incomingMessage.originalSenderMac), peerPublicStatus ? "true" : "false", peerPublicLockedStatus ? "true" : "false");
        addDisplayLog(String("Peer ") + getMacSuffix(incomingMessage.originalSenderMac) + " Public Status: " + (peerPublicStatus ? "ENABLED" : "DISABLED") + ", Locked: " + (peerPublicLockedStatus ? "YES" : "NO"));
        // Match the public messaging status to the sender's status
        // Only update if our current status is different and not locked
        if (!publicMessagingLocked) { // Only update if we are not locally locked
            publicMessagingEnabled = peerPublicStatus; 
            Serial.printf("Local publicMessagingEnabled set to: %s (from peer status)\n", publicMessagingEnabled ? "true" : "false");
        }
        // If the peer is locked, and we are not, we should also lock
        if (peerPublicLockedStatus && !publicMessagingLocked) {
            publicMessagingLocked = true;
            publicMessagingEnabled = false; // If locked, it must be disabled
            Serial.println("Local publicMessagingLocked set to TRUE (from peer status). Public messaging DISABLED.");
        }
        continue; // Do not process this message further (no re-broadcast)
    }

    // Handle MSG_TYPE_PASSWORD_UPDATE
    if (incomingMessage.messageType == MSG_TYPE_PASSWORD_UPDATE) {
        // If password is already set on this node, ignore the incoming update completely.
        // This prevents processing AND caching of redundant/unwanted password updates.
        if (passwordChangeLocked) {
            Serial.println("Received password update but local password change is locked. Ignoring and not caching.");
            continue; // Stop processing this message, including not adding to cache or display log.
        }
        // ONLY process password updates if new to this node (passwordChangeLocked is already false here)
        if (!wasAlreadySeen) { 
            Serial.println("Received password update command via mesh.");
            // The content is the plaintext new password (decrypted by onDataRecv already)
            hashedOrganizerPassword = simpleHash(String(incomingMessage.content));
            passwordChangeLocked = true; // Lock change on this board (node is now capable)
            Serial.println("Organizer password updated via mesh. Local change locked. Node is now capable of sending messages.");

            // NEW: If a node receives an OTA password update and accepts it,
            // it immediately requests the sender's public status.
            Serial.printf("Password updated via OTA. Requesting public status from sender %02X:%02X:%02X:%02X:%02X:%02X\n", MAC2STR(incomingMessage.originalSenderMac));
            createAndSendMessage("", 0, MSG_TYPE_STATUS_REQUEST, incomingMessage.originalSenderMac); // Send unicast status request
        }
        skipDisplayLog = true; // Always skip display for password updates
    }

    // Always update the seen message cache first. This ensures the message's timestamp
    // is refreshed and its "full TTL potential" version is stored if new.
    // To do this, we re-encrypt the incomingMessage before passing it to the cache.
    // NOTE: incomingMessage.content is currently DECRYPTED here.
    esp_now_message_t encryptedForCache = incomingMessage; // Create a copy
    prngStreamCipher((uint8_t*)encryptedForCache.content, MAX_MESSAGE_CONTENT_LEN, PRE_SHARED_KEY, PRE_SHARED_KEY_LEN); // Re-encrypt for cache
    addOrUpdateMessageToSeen(encryptedForCache.messageID, encryptedForCache.originalSenderMac, encryptedForCache);


    // ONLY queue the message for local processing/display if it's truly new to this node.
    // If `wasAlreadySeen` is true, it means this node has already processed it for display
    // or originated it. The re-broadcast logic is handled separately by the cache.
    if (!wasAlreadySeen) {
        totalMessagesReceived++;
        // The urgent message count is now based on the content prefix, not message type directly
        if (String(incomingMessage.content).indexOf("Urgent: ") != -1) {
            totalUrgentMessages++;
        }

        // Add to local display log (decrypted version) - ONLY if not a password update
        if (!skipDisplayLog) { // Check the flag here
            portENTER_CRITICAL(&localDisplayLogMutex);
            LocalDisplayEntry newEntry = {incomingMessage, millis()}; // Store message and its reception timestamp
            localDisplayLog.push_back(newEntry);
            portEXIT_CRITICAL(&localDisplayLogMutex);
        }

        // IMPORTANT: When re-broadcasting from the queue, we need to send the *encrypted* version.
        // The message in `incomingMessage` is currently decrypted.
        // We also need to respect its current TTL.
        if (incomingMessage.ttl > 0) {
            esp_now_message_t encryptedForRebroadcast = incomingMessage; // Create a copy
            prngStreamCipher((uint8_t*)encryptedForRebroadcast.content, MAX_MESSAGE_CONTENT_LEN, PRE_SHARED_KEY, PRE_SHARED_KEY_LEN); // Encrypt for re-broadcast
            sendToAllPeers(encryptedForRebroadcast);
        } else {
            Serial.println("Message reached TTL limit, not re-broadcasting.");
        }
    }
    
    // Command processing (now safe in loop after decryption)
    if (incomingMessage.messageType == MSG_TYPE_COMMAND) {
        if (incomingContent.equals(CMD_PUBLIC_ON)) {
            // Only enable public messaging if it's not locked
            if (!publicMessagingLocked) {
                if (!publicMessagingEnabled) {
                    publicMessagingEnabled = true;
                    Serial.println("Received command: ENABLE public messaging.");
                    webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging was ENABLED by an organizer.</p>";
                }
            } else {
                Serial.println("Received command: ENABLE public messaging, but it is locked OFF. Ignoring.");
                webFeedbackMessage = "<p class='feedback' style='color:orange;'>Public messaging is locked OFF by a previous organizer command. Cannot re-enable.</p>";
            }
        } else if (incomingContent.equals(CMD_PUBLIC_OFF)) {
            if (publicMessagingEnabled || !publicMessagingLocked) { // If it's currently enabled, or not yet locked
                publicMessagingEnabled = false; // Disable it
                publicMessagingLocked = true;   // Lock it permanently (until reboot)
                Serial.println("Received command: DISABLE public messaging. Status is now LOCKED OFF.");
                webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging was DISABLED and LOCKED OFF by an organizer.</p>";
            } else {
                Serial.println("Received command: DISABLE public messaging, but it was already locked OFF. No change.");
            }
        }
    }

    Serial.println("Message processed from queue: Node " + originalSenderMacSuffix + " - " + incomingContent);
    messageProcessed = true;
  }

  if (millis() - lastRebroadcast >= AUTO_REBROADCAST_INTERVAL_MS) {
    lastRebroadcast = millis();
    portENTER_CRITICAL(&seenMessagesMutex);
    std::vector<esp_now_message_t> messagesToRebroadcast;
    for (const auto& seenMsg : seenMessages) {
      // When pulling from cache for auto-rebroadcast, the TTL in seenMsg.messageData
      // should already be MAX_TTL_HOPS due to the change in addOrUpdateMessageToSeen.
      // We still check > 0, though it should always be.
      if (seenMsg.messageData.ttl > 0) {
        messagesToRebroadcast.push_back(seenMsg.messageData); // These are already encrypted in cache
      }
    }
    portEXIT_CRITICAL(&seenMessagesMutex);

    for (auto& msg : messagesToRebroadcast) { // Use auto& to allow modification of msg
      // sendToAllPeers will decrement msg's TTL.
      // This 'msg' here is a copy from the cache, which had its TTL reset to MAX_TTL_HOPS.
      sendToAllPeers(msg);
    }
  }

  // Periodic discovery broadcast
  if (millis() - lastDiscoveryBroadcast >= PEER_DISCOVERY_INTERVAL_MS) {
      lastDiscoveryBroadcast = millis();
      // Send a discovery message. The content doesn't matter much, as it's silently handled.
      // Using our own MAC as content for identification if needed for debugging.
      createAndSendMessage(MAC_full_str.c_str(), MAC_full_str.length(), MSG_TYPE_DISCOVERY);
  }

  // Periodically manage the local display log
  if (millis() - lastLocalDisplayLogManage >= LOCAL_DISPLAY_LOG_MANAGE_INTERVAL_MS) {
      lastLocalDisplayLogManage = millis();
      manageLocalDisplayLog();
  }

  // Periodically manage the lastSeenPeers map and espNowAddedPeers
  if (millis() - lastSeenPeersManage >= LAST_SEEN_PEERS_MANAGE_INTERVAL_MS) {
      lastSeenPeersManage = millis();
      unsigned long currentTime = millis();

      // Cleanup lastSeenPeers (for display)
      portENTER_CRITICAL(&lastSeenPeersMutex);
      for (auto it = lastSeenPeers.begin(); it != lastSeenPeers.end(); ) {
          if ((currentTime - it->second) > PEER_LAST_SEEN_DURATION_MS) {
              it = lastSeenPeers.erase(it);
          } else {
              ++it;
          }
      }
      portEXIT_CRITICAL(&lastSeenPeersMutex);

      // Cleanup espNowAddedPeers (for sending)
      portENTER_CRITICAL(&espNowAddedPeersMutex);
      for (auto it = espNowAddedPeers.begin(); it != espNowAddedPeers.end(); ) {
          // Do not remove the broadcast MAC address
          if (it->first == "FF:FF:FF:FF:FF:FF") {
              ++it;
              continue;
          }
          if ((currentTime - it->second) > ESP_NOW_PEER_TIMEOUT_MS) {
              uint8_t peerMacBytes[6];
              unsigned int tempMac[6];
              sscanf(it->first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                     &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);
              for (int k = 0; k < 6; ++k) { peerMacBytes[k] = (uint8_t)tempMac[k]; }
              esp_now_del_peer(peerMacBytes); // Remove from ESP-NOW internal peer list
              it = espNowAddedPeers.erase(it); // Remove from our map
          } else {
              ++it;
          }
      }
      portEXIT_CRITICAL(&espNowAddedPeersMutex);
  }


  WiFiClient client = server.available();
  if (client) {
    String currentLine = "";
    String postBody = "";
    bool isPost = false;
    unsigned long clientTimeout = millis();
    int contentLength = 0;
    String requestedPath = "/";
    String currentQueryParams = ""; // To store query parameters for redirects

    while (client.connected() && (millis() - clientTimeout < 2000)) {
      if (client.available()) {
        clientTimeout = millis();
        char c = client.read();
        if (c == '\n') {
          if (currentLine.length() == 0) {
            String sessionTokenParam = "";
            
            // Extract query parameters from the original requestedPath for both GET and POST
            int queryStart = requestedPath.indexOf('?');
            if (queryStart != -1) {
                currentQueryParams = requestedPath.substring(queryStart + 1);
                requestedPath = requestedPath.substring(0, queryStart); // Clean path
            }

            // Parse session_token from queryParams for GET or postBody for POST
            if (isPost) {
                for (int i = 0; i < contentLength && client.available(); i++) {
                    postBody += (char)client.read();
                }
                Serial.println("Received POST Body: " + postBody);

                int tokenStart = postBody.indexOf("session_token=");
                if (tokenStart != -1) {
                    int tokenEnd = postBody.indexOf('&', tokenStart);
                    if (tokenEnd == -1) tokenEnd = postBody.length();
                    sessionTokenParam = postBody.substring(tokenStart + 14, tokenEnd);
                }
            } else { // It's a GET request
                int tokenStart = currentQueryParams.indexOf("session_token=");
                if (tokenStart != -1) {
                    int tokenEnd = currentQueryParams.indexOf('&', tokenStart);
                    if (tokenEnd == -1) tokenEnd = currentQueryParams.length();
                    sessionTokenParam = currentQueryParams.substring(tokenStart + 14, tokenEnd);
                }
            }
            
            isOrganizerSessionActive = isOrganizerSessionValid(sessionTokenParam); // Update session status
            if (isOrganizerSessionActive) { // Refresh session timestamp if session is active
                sessionTokenTimestamp = millis();
            }

            // Handle /challenge endpoint for key exchange
            if (requestedPath == "/challenge") {
                currentChallengeNonce = String(esp_random()); // Generate a random nonce
                challengeNonceTimestamp = millis();
                client.println(F("HTTP/1.1 200 OK"));
                client.println(F("Content-type:text/plain"));
                client.println(F("Connection: close"));
                // Added Cache-Control headers for challenge endpoint
                client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                client.println(F("Pragma: no-cache"));
                client.println(F("Expires: 0"));
                client.println();
                client.print(currentChallengeNonce);
                client.stop();
                return;
            }

            // --- CAPTIVE PORTAL REDIRECT PATCH ---
            // --- BEGIN: Connectivity Check Response Patch ---
            if (!isPost) {
              bool isConnectivityCheck = false;
              String lowerPath = requestedPath;
              lowerPath.toLowerCase();
              if (
                  lowerPath == "/generate_204" ||
                  lowerPath == "/hotspot-detect.html" ||
                  lowerPath == "/ncsi.txt" ||
                  lowerPath == "/connecttest.txt" ||
                  lowerPath == "/captive-portal" ||
                  lowerPath == "/success.txt" ||
                  lowerPath == "/library/test/success.html" ||
                  lowerPath.startsWith("/redirect") ||
                  lowerPath.indexOf("connectivitycheck.gstatic.com") != -1 ||
                  lowerPath.indexOf("msftconnecttest.com") != -1 ||
                  lowerPath.indexOf("apple.com") != -1 ||
                  lowerPath.indexOf("hotspot-detect.html") != -1
                 ) {
                isConnectivityCheck = true;
              }

              if (isConnectivityCheck) {
                if (lowerPath == "/generate_204") {
                  client.println(F("HTTP/1.1 204 No Content"));
                  client.println(F("Connection: close"));
                  // Added Cache-Control headers for 204 responses
                  client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                  client.println(F("Pragma: no-cache"));
                  client.println(F("Expires: 0"));
                  client.println();
                  client.stop();
                  return;
                } else if (lowerPath == "/hotspot-detect.html" || lowerPath == "/ncsi.txt" || lowerPath == "/connecttest.txt" || lowerPath == "/success.txt") {
                  client.println(F("HTTP/1.1 200 OK"));
                  client.println(F("Content-Type: text/plain"));
                  client.println(F("Connection: close"));
                  // Added Cache-Control headers for text/plain responses
                  client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                  client.println(F("Pragma: no-cache"));
                  client.println(F("Expires: 0"));
                  client.println();
                  client.println("Success");
                  client.stop();
                  return;
                } else {
                  client.println(F("HTTP/1.1 200 OK"));
                  client.println(F("Content-Type: text/html"));
                  client.println(F("Connection: close"));
                  // Added Cache-Control headers for generic HTML success responses
                  client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                  client.println(F("Pragma: no-cache"));
                  client.println(F("Expires: 0"));
                  client.println();
                  client.println(F("<html><head><title>Success</title></head><body>Success</body></html>"));
                  client.stop();
                  return;
                }
              }
            }
            // --- END: Connectivity Check Response Patch ---
            // Handle captive portal redirect for non-root GETs unless it's a filter or session token request
            if (requestedPath != "/" && currentQueryParams.indexOf("show_public") == -1 && currentQueryParams.indexOf("show_urgent") == -1 && currentQueryParams.indexOf("session_token") == -1) {
                Serial.println("Intercepted non-root GET request for: " + requestedPath + ". Redirecting to captive portal.");
                client.println(F("HTTP/1.1 302 Found"));
                client.println(F("Location: http://192.168.4.1/"));
                client.println(F("Connection: close"));
                // Added Cache-Control headers for 302 redirects
                client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                client.println(F("Pragma: no-cache"));
                client.println(F("Expires: 0"));
                client.println();
                client.stop();
                return;
            }

            if (isPost) {
              String messageParam = "", passwordParam = "", urgentParam = "", actionParam = "", newPasswordParam = "", confirmNewPasswordParam = "";
              // For challenge-response
              String challengeNonceReceived = "", passwordResponseHash = "";

              int messageStart = postBody.indexOf("message=");
              if (messageStart != -1) {
                int messageEnd = postBody.indexOf('&', messageStart);
                if (messageEnd == -1) messageEnd = postBody.length();
                messageParam = postBody.substring(messageStart + 8, messageEnd);
              }
              // This is the plaintext password from the client (will be cleared after hashing)
              int passwordStart = postBody.indexOf("password_plaintext_client=");
              if (passwordStart != -1) {
                int passwordEnd = postBody.indexOf('&', passwordStart);
                if (passwordEnd == -1) passwordEnd = postBody.length();
                passwordParam = postBody.substring(passwordStart + 26, passwordEnd);
              }
              if (postBody.indexOf("urgent=on") != -1) { urgentParam = "on"; }
              int actionStart = postBody.indexOf("action=");
              if (actionStart != -1) {
                int actionEnd = postBody.indexOf('&', actionStart);
                if (actionEnd == -1) actionEnd = postBody.length();
                actionParam = postBody.substring(actionStart + 7, actionEnd);
              }
              int newPasswordStart = postBody.indexOf("new_password=");
              if (newPasswordStart != -1) {
                  int newPasswordEnd = postBody.indexOf('&', newPasswordStart);
                  if (newPasswordEnd == -1) newPasswordEnd = postBody.length();
                  newPasswordParam = postBody.substring(newPasswordStart + 13, newPasswordEnd);
              }
              int confirmNewPasswordStart = postBody.indexOf("confirm_new_password=");
              if (confirmNewPasswordStart != -1) {
                  int confirmNewPasswordEnd = postBody.indexOf('&', confirmNewPasswordStart);
                  if (confirmNewPasswordEnd == -1) confirmNewPasswordEnd = postBody.length();
                  confirmNewPasswordParam = postBody.substring(confirmNewPasswordStart + 21, confirmNewPasswordEnd);
              }


              // Parse challenge-response parameters
              int nonceStart = postBody.indexOf("challenge_nonce=");
              if (nonceStart != -1) {
                  int nonceEnd = postBody.indexOf('&', nonceStart);
                  if (nonceEnd == -1) nonceEnd = postBody.length();
                  challengeNonceReceived = postBody.substring(nonceStart + 16, nonceEnd);
              }
              // This is the client-side hashed response
              int responseHashStart = postBody.indexOf("password_response_hash=");
              if (responseHashStart != -1) {
                  int responseHashEnd = postBody.indexOf('&', responseHashStart);
                  if (responseHashEnd == -1) responseHashEnd = postBody.length();
                  passwordResponseHash = postBody.substring(responseHashStart + 23, responseHashEnd);
              }


              messageParam.replace('+', ' ');
              String decodedMessage = "";
              for (int i = 0; i < messageParam.length(); i++) {
                if (messageParam.charAt(i) == '%' && (i + 2) < messageParam.length()) {
                  char decodedChar = (char)strtol((messageParam.substring(i + 1, i + 3)).c_str(), NULL, 16);
                  decodedMessage += decodedChar;
                  i += 2;
                } else {
                  decodedMessage += messageParam.charAt(i);
                }
              }

              newPasswordParam.replace('+', ' ');
              String decodedNewPassword = "";
              for (int i = 0; i < newPasswordParam.length(); i++) {
                if (newPasswordParam.charAt(i) == '%' && (i + 2) < newPasswordParam.length()) {
                  char decodedChar = (char)strtol((newPasswordParam.substring(i + 1, i + 3)).c_str(), NULL, 16);
                  decodedNewPassword += decodedChar;
                  i += 2;
                } else {
                  decodedNewPassword += newPasswordParam.charAt(i);
                }
              }
              
              confirmNewPasswordParam.replace('+', ' ');
              String decodedConfirmNewPassword = "";
              for (int i = 0; i < confirmNewPasswordParam.length(); i++) {
                if (confirmNewPasswordParam.charAt(i) == '%' && (i + 2) < confirmNewPasswordParam.length()) {
                  char decodedChar = (char)strtol((confirmNewPasswordParam.substring(i + 1, i + 3)).c_str(), NULL, 16);
                  decodedConfirmNewPassword += decodedChar;
                  i += 2;
                } else {
                  decodedConfirmNewPassword += confirmNewPasswordParam.charAt(i);
                }
              }


              if (actionParam == "enterOrganizer") {
                  if (lockoutTime > 0 && millis() < lockoutTime) {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Too many failed attempts. Try again later.</p>";
                  } else {
                      if (lockoutTime > 0 && millis() >= lockoutTime) {
                          lockoutTime = 0;
                          loginAttempts = 0;
                      }

                      // Challenge-response verification (client-side hashed response)
                      // Validate nonce *before* processing the password hash
                      if (challengeNonceReceived != currentChallengeNonce ||
                          millis() - challengeNonceTimestamp > CHALLENGE_TIMEOUT_MS ||
                          currentChallengeNonce.length() == 0) {
                          webFeedbackMessage = "<p class='feedback' style='color:red;'>Login failed: Invalid or expired challenge.</p>";
                          // Clear nonce to force a new challenge for the next attempt
                          currentChallengeNonce = "";
                          challengeNonceTimestamp = 0;
                      } else {
                          // Use the simpleHash function with the *current* hashedOrganizerPassword
                          // The server computes: hash(stored_hashed_password + nonce)
                          Serial.print("Current hashedOrganizerPassword (for login): '"); Serial.print(hashedOrganizerPassword); Serial.println("'");
                          String expectedResponse = simpleHash(hashedOrganizerPassword + challengeNonceReceived);
                          Serial.print("Expected Response Hash: '"); Serial.print(expectedResponse); Serial.println("'");
                          Serial.print("Received Password Response Hash: '"); Serial.print(passwordResponseHash); Serial.println("'");

                          if (expectedResponse.equalsIgnoreCase(passwordResponseHash)) { // Compare with client-provided hash
                              loginAttempts = 0;
                              organizerSessionToken = String(esp_random()) + String(esp_random());
                              sessionTokenTimestamp = millis();
                              isOrganizerSessionActive = true; // User is logged into the web session
                              webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer Mode activated.</p>";
                              if (!passwordChangeLocked) {
                                  webFeedbackMessage += "<p class='feedback' style='color:orange;'>Note: Node's organizer password is still default. Set a new password to enable sending messages.</p>";
                              }
                              // Clear nonce on successful login (or successful password check)
                              currentChallengeNonce = "";
                              challengeNonceTimestamp = 0;
                              
                              // Preserve existing query parameters for redirect
                              String redirectQuery = currentQueryParams;
                              if (redirectQuery.length() > 0) redirectQuery += "&";
                              redirectQuery += "session_token=" + organizerSessionToken;

                              client.println(F("HTTP/1.1 303 See Other"));
                              client.println("Location: /?" + redirectQuery); // Preserve query params
                              client.println(F("Connection: close"));
                              // Added Cache-Control headers for 303 redirect after POST
                              client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                              client.println(F("Pragma: no-cache"));
                              client.println(F("Expires: 0"));
                              client.println();
                              client.stop();
                              return;
                          } else {
                              loginAttempts++;
                              if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                                  lockoutTime = millis() + LOCKOUT_DURATION_MS;
                                  loginAttempts = 0;
                                  webFeedbackMessage = "<p class='feedback' style='color:red;'>Login locked for 5 minutes due to too many failures.</p>";
                              } else {
                                  webFeedbackMessage = "<p class='feedback' style='color:red;'>Incorrect password. " + String(MAX_LOGIN_ATTEMPTS - loginAttempts) + " attempts remaining.</p>";
                              }
                              // Clear nonce on failed login to force a new challenge
                              currentChallengeNonce = "";
                              challengeNonceTimestamp = 0;
                          }
                      }
                  }
              } else if (actionParam == "exitOrganizer") {
                  // Clear any previous feedback message before setting a new one for exit
                  webFeedbackMessage = ""; 
                  if (isOrganizerSessionActive) { // Check if there's an active session to exit
                      organizerSessionToken = "";
                      isOrganizerSessionActive = false; // User exited web session
                      webFeedbackMessage = "<p class='feedback' style='color:blue;'>Exited Organizer Mode.</p>";
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:orange;'>Not currently in Organizer Mode.</p>"; // Provide feedback even if not active
                  }
              } else if (actionParam == "togglePublic") {
                  // Only allow if organizer session is active AND node is capable (password set)
                  if (isOrganizerSessionActive && passwordChangeLocked) { 
                      sessionTokenTimestamp = millis();
                      // Check if public messaging is locked OFF
                      if (publicMessagingLocked) {
                          webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Public messaging is locked OFF. Cannot re-enable.</p>";
                      } else {
                          publicMessagingEnabled = !publicMessagingEnabled;
                          webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging has been " + String(publicMessagingEnabled ? "ENABLED" : "DISABLED") + ".</p>";
                          createAndSendMessage(publicMessagingEnabled ? CMD_PUBLIC_ON : CMD_PUBLIC_OFF, strlen(publicMessagingEnabled ? CMD_PUBLIC_ON : CMD_PUBLIC_OFF), MSG_TYPE_COMMAND);
                      }
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Not logged in as organizer or node's password not set.</p>";
                  }
              } else if (actionParam == "sendMessage") {
                  // Only allow if organizer session is active AND node is capable (password set)
                  if (isOrganizerSessionActive && passwordChangeLocked) { 
                      sessionTokenTimestamp = millis();
                      if (decodedMessage.length() == 0) {
                          webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>";
                      } else {
                          uint8_t messageType = MSG_TYPE_ORGANIZER; // Default to organizer for this form
                          if (urgentParam == "on") {
                              decodedMessage = "Urgent: " + decodedMessage; // Prepend "Urgent: "
                          }
                          if (decodedMessage.length() >= MAX_MESSAGE_CONTENT_LEN) {
                              decodedMessage = decodedMessage.substring(0, MAX_MESSAGE_CONTENT_LEN - 1);
                          }
                          createAndSendMessage(decodedMessage.c_str(), decodedMessage.length(), messageType);
                          // createAndSendMessage will set webFeedbackMessage if not capable
                          if (webFeedbackMessage.length() == 0) { // Only set if createAndSendMessage didn't set an error
                              webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer message queued!</p>";
                          }
                      }
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Not logged in as organizer or node's password not set.</p>";
                  }
              } else if (actionParam == "sendPublicMessage") {
                  // Only allow if public messaging is enabled AND node is capable (password set)
                  if (publicMessagingEnabled && passwordChangeLocked) { 
                      if (decodedMessage.length() == 0) {
                          webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>";
                      } else {
                          if (decodedMessage.length() >= MAX_MESSAGE_CONTENT_LEN) {
                              decodedMessage = decodedMessage.substring(0, MAX_MESSAGE_CONTENT_LEN - 1);
                          }
                          createAndSendMessage(decodedMessage.c_str(), decodedMessage.length(), MSG_TYPE_PUBLIC);
                          // createAndSendMessage will set webFeedbackMessage if not capable
                          if (webFeedbackMessage.length() == 0) { // Only set if createAndSendMessage didn't set an error
                              webFeedbackMessage = "<p class='feedback' style='color:green;'>Public message queued!</p>";
                          }
                      }
                  } else {
                      // This message should only appear on the organizer page if an organizer tries to send a public message
                      // when public messaging is disabled or the node is not capable.
                      // For public users, the public message form is simply hidden if publicMessagingEnabled is false.
                      if (isOrganizerSessionActive) { // Only show this feedback if an organizer is logged in
                          webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Public messaging is disabled or node's password not set.</p>";
                      }
                  }
              } else if (actionParam == "rebroadcastCache") {
                  // Only allow if organizer session is active AND node is capable (password set)
                  if (isOrganizerSessionActive && passwordChangeLocked) { 
                      sessionTokenTimestamp = millis();
                      int rebroadcastedCount = 0;
                      portENTER_CRITICAL(&seenMessagesMutex);
                      std::vector<esp_now_message_t> messagesToRebroadcast;
                      for (const auto& seenMsg : seenMessages) {
                          // When pulling from cache for auto-rebroadcast, the TTL in seenMsg.messageData
                          // should already be MAX_TTL_HOPS due to the change in addOrUpdateMessageToSeen.
                          // We still check > 0, though it should always be.
                          if (seenMsg.messageData.ttl > 0) {
                            // Create a copy to send, decrementing its TTL for this hop
                            esp_now_message_t msgCopy = seenMsg.messageData;
                            sendToAllPeers(msgCopy); // msgCopy's TTL will be decremented here
                            rebroadcastedCount++;
                          }
                      }
                      portEXIT_CRITICAL(&seenMessagesMutex);
                      webFeedbackMessage = "<p class='feedback' style='color:green;'>Re-broadcasted " + String(rebroadcastedCount) + " messages!</p>";
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Not logged in as organizer or node's password not set.</p>";
                  }
              } else if (actionParam == "setOrganizerPassword") {
                  // If passwordChangeLocked is true, we prevent changing it and show a message.
                  if (passwordChangeLocked) {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>The organizer password for this node cannot be changed after it has been set. To reset the password, you must reboot the board.</p>";
                  } else if (isOrganizerSessionActive || !passwordChangeLocked) { // Proceed only if not locked
                      sessionTokenTimestamp = millis();
                      Serial.println("Attempting to set new password.");
                      Serial.print("Decoded New Password: '"); Serial.print(decodedNewPassword); Serial.println("'");
                      Serial.print("Decoded Confirm Password: '"); Serial.print(decodedConfirmNewPassword); Serial.println("'");

                      if (decodedNewPassword.length() == 0) {
                          webFeedbackMessage = "<p class='feedback' style='color:orange;'>New password cannot be empty.</p>";
                      } else if (decodedNewPassword != decodedConfirmNewPassword) { // Check if passwords match
                          webFeedbackMessage = "<p class='feedback' style='color:red;'>New passwords do not match. Please try again.</p>";
                      }
                      else {
                          // Update local hashed password
                          hashedOrganizerPassword = simpleHash(decodedNewPassword);
                          passwordChangeLocked = true; // Lock future password changes on this board immediately (node is now capable)
                          Serial.print("New hashedOrganizerPassword (after update): '"); Serial.print(hashedOrganizerPassword); Serial.println("'");
                          webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer password updated successfully!</p>";
                          loginAttempts = 0; // Reset login attempts on successful password change
                          lockoutTime = 0;

                          // Broadcast the new password (plaintext) to the mesh
                          // It will be hashed and encrypted by createAndSendMessage
                          createAndSendMessage(decodedNewPassword.c_str(), decodedNewPassword.length(), MSG_TYPE_PASSWORD_UPDATE);
                          
                          // After setting the password, if we are in an organizer session,
                          // this node is now capable of sending messages.
                      }
                  } else {
                      // This else block handles cases where it's not locked but also not an active session
                      // (e.g., trying to set initial password without a valid session, which shouldn't happen with the current UI flow)
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Invalid or expired session to change password.</p>";
                  }
              }

              client.println(F("HTTP/1.1 303 See Other"));
              // Preserve current query parameters for redirect
              String redirectQuery = currentQueryParams;
              if (isOrganizerSessionActive && sessionTokenParam.length() > 0) { // Ensure session token is preserved if active
                  if (redirectQuery.length() > 0) redirectQuery += "&";
                  redirectQuery += "session_token=" + sessionTokenParam;
              }
              client.println("Location: /?" + redirectQuery);
              client.println(F("Connection: close"));
              // Added Cache-Control headers for 303 redirect after POST
              client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
              client.println(F("Pragma: no-cache"));
              client.println(F("Expires: 0"));
              client.println();
              client.stop();
              return;
            }

            // --- HTML Generation for Web Interface ---
            String detectedNodesHtmlContent = "<div class='recent-senders-display-wrapper'><span class='detected-nodes-label'>Senders:</span><div class='detected-nodes-mac-list'>";
            int count = 0;
            portENTER_CRITICAL(&lastSeenPeersMutex); // Use the lastSeenPeers for display
            std::vector<std::pair<String, unsigned long>> sortedSeenPeers;
            for (auto const& [macStr, timestamp] : lastSeenPeers) { sortedSeenPeers.push_back({macStr, timestamp}); }
            std::sort(sortedSeenPeers.begin(), sortedSeenPeers.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

            const int MAX_NODES_TO_DISPLAY_WEB = 4; // Max nodes to display on web interface
            for (const auto& macPair : sortedSeenPeers) { // Corrected typo here
                if (count >= MAX_NODES_TO_DISPLAY_WEB) break;
                uint8_t macBytes[6];
                unsigned int tempMac[6]; // Temporary array for sscanf
                sscanf(macPair.first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                       &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);
                // Copy values from temporary unsigned int array to uint8_t array
                for (int k = 0; k < 6; ++k) {
                    macBytes[k] = (uint8_t)tempMac[k];
                }

                detectedNodesHtmlContent += "<span class='detected-node-item-compact'>" + formatMaskedMac(macBytes) + "</span>";
                count++;
            }
            portEXIT_CRITICAL(&lastSeenPeersMutex);
            if (count == 0) { detectedNodesHtmlContent += "<span class='detected-node-item-compact'>None</span>"; }
            detectedNodesHtmlContent += "</div></div>";

            client.println(F("HTTP/1.1 200 OK"));
            client.println(F("Content-type:text/html"));
            client.println(F("Connection: close"));
            // --- START: Added Cache-Control Headers for main HTML page ---
            client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
            client.println(F("Pragma: no-cache"));
            client.println(F("Expires: 0"));
            // --- END: Added Cache-Control Headers for main HTML page ---
            client.println();
            client.println(F("<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Protest Info Node</title><style>"));
            client.println(F("body{font-family:Helvetica,Arial,sans-serif;margin:0;padding:0;background-color:#f8f8f8;color:#333;display:flex;flex-direction:column;min-height:100vh;}"));
            client.println(F("header{background-color:#f0f0f0;padding:10px 15px;border-bottom:1px solid #ddd;text-align:center; display: flex; flex-direction: column; align-items: center; justify-content: center;}")); // Added flexbox for centering
            client.println(F("h1,h2,h3{margin:0;padding:5px 0;color:#333;text-align:center;} h1{font-size:1.4em;} h2{font-size:1.2em;} h3{font-size:1.1em;margin-bottom:10px;}"));
            client.println(F("p{margin:3px 0;font-size:0.9em;text-align:center;} .info-line{font-size:0.8em;color:#666;margin-bottom:10px;}"));
            client.println(F(".content-wrapper{display:flex;flex-direction:column;align-items:center;width:100%;max-width:900px;margin:15px auto;padding:0 10px;flex-grow:1;}"));
            client.println(F(".chat-main-content{flex:1;width:100%;max-width:700px;margin:0 auto;background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);border:1px solid #ddd;}"));
            client.println(F("pre{background:#eee;padding:10px;border-radius:5px;text-align:left;max-width:100%;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;font-size:0.85em;border:1px solid #ccc;min-height:200px;}"));
            client.println(F("details, .form-container{background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);max-width:450px;margin:15px auto;border:1px solid #ddd;}"));
            client.println(F("summary{font-size:1.1em;font-weight:bold;cursor:pointer;padding:5px 0;text-align:center; outline: none; border: none;} /* Added outline and border none */"));
            client.println(F("form{display:flex;flex-direction:column;align-items:center;margin-top:10px;}"));
            client.println(F("label{font-size:0.9em;margin-bottom:5px;align-self:flex-start;width:80%;}"));
            client.println(F("input[type=text],input[type=password]{width:80%;max-width:350px;padding:8px;margin-bottom:10px;border-radius:4px;border:1px solid #ccc;font-size:0.9em;}"));
            client.println(F("input[type=submit], .button-link{background-color:#007bff;color:white!important;padding:8px 15px;border:none;border-radius:4px;cursor:pointer;font-size:1em;transition:background-color 0.3s ease;text-decoration:none;display:block; margin: 0 auto;}"));
            client.println(F(".button-link.secondary{background-color:#6c757d;} .button-link.secondary:hover{background-color:#5a6268;}"));
            client.println(F(".button-link.disabled{background-color:#cccccc; cursor: not-allowed;}")); // NEW: Style for disabled buttons
            client.println(F(".recent-senders-display-wrapper{display:flex;flex-direction:column;align-items:center;width:100%;max-width:450px;background:#e6f7ff;border:1px solid #cceeff;border-radius:12px;padding:10px 15px;font-size:0.75em;color:#0056b3;margin:15px auto; box-sizing: border-box;}")); // Added box-sizing
            client.println(F(".detected-nodes-label{font-weight:bold;margin-bottom:5px;color:#003366;}"));
            client.println(F(".detected-nodes-mac-list{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;width:100%;}")); // Added flex-wrap
            client.println(F("</style></head><body><script>"));
            // Re-added simpleHash function to client-side JS
            client.println(F("function simpleHash(input) {"));
            client.println(F("    // Must match the C++ pseudo-salt for consistency"));
            client.println(F("    const PSEUDO_SALT = 'ProtestNodeSalt123XYZ';"));
            client.println(F("    const saltedInput = input + PSEUDO_SALT;"));
            client.println(F("    let hash = 5381;"));
            client.println(F("    for (let i = 0; i < saltedInput.length; i++) {"));
            client.println(F("        hash = ((hash << 5) + hash) + saltedInput.charCodeAt(i);"));
            client.println(F("    }"));
            client.println(F("    return (hash >>> 0).toString(16); // Ensure positive and convert to hex"));
            client.println(F("}"));
            client.println(F("async function fetchChallengeAndSubmit() {"));
            client.println(F("    const loginForm = document.getElementById('organizerLoginForm');"));
            client.println(F("    const passwordInput = document.getElementById('pass_input');"));
            client.println(F("    const challengeNonceInput = document.getElementById('challenge_nonce_input');"));
            client.println(F("    const passwordResponseHashInput = document.getElementById('password_response_hash_input');"));
            client.println(F("    if (!loginForm || !passwordInput || !challengeNonceInput || !passwordResponseHashInput) {"));
            client.println(F("        console.error('Login form elements not found.');"));
            client.println(F("        const feedbackDiv = document.createElement('p');"));
            client.println(F("        feedbackDiv.className = 'feedback';"));
            client.println(F("        feedbackDiv.style.color = 'red';"));
            client.println(F("        feedbackDiv.textContent = 'Login failed: Missing form elements. Please refresh the page.';"));
            client.println(F("        loginForm.parentNode.insertBefore(feedbackDiv, loginForm);"));
            client.println(F("        return;"));
            client.println(F("    }"));
            client.println(F("    console.log('Attempting to fetch challenge and submit form...');"));
            client.println(F("    try {"));
            client.println(F("        console.log('Fetching challenge nonce from /challenge...');"));
            client.println(F("        const response = await fetch('/challenge');"));
            client.println(F("        if (!response.ok) {"));
            client.println(F("            throw new Error(`HTTP error! status: ${response.status}`);"));
            client.println(F("        }"));
            client.println(F("        const nonce = await response.text();"));
            client.println(F("        challengeNonceInput.value = nonce;"));
            client.println(F("        console.log('Received nonce:', nonce);"));
            client.println(F("        const plaintextPassword = passwordInput.value;"));
            client.println(F("        // Corrected client-side hashing: hash the plaintext password, then hash with nonce"));
            client.println(F("        const hashedClientPassword = simpleHash(plaintextPassword);"));
            client.println(F("        const combinedString = hashedClientPassword + nonce;"));
            client.println(F("        const responseHash = simpleHash(combinedString);"));
            client.println(F("        passwordResponseHashInput.value = responseHash;"));
            client.println(F("        console.log('Generated hash:', responseHash);"));
            client.println(F("        passwordInput.value = ''; // Clear plaintext password from input for security"));
            client.println(F("        console.log('Submitting form...');"));
            client.println(F("        loginForm.submit();"));
            client.println(F("    } catch (error) {"));
            client.println(F("        console.error('Authentication process failed:', error);"));
            client.println(F("        const feedbackDiv = document.createElement('p');"));
            client.println(F("        feedbackDiv.className = 'feedback';"));
            client.println(F("        feedbackDiv.style.color = 'red';"));
            client.println(F("        feedbackDiv.textContent = 'Login failed: ' + error.message + '. Please try again.';"));
            client.println(F("    }"));
            client.println(F("}"));
            client.println(F("document.addEventListener('DOMContentLoaded', () => {"));
            client.println(F("    const loginForm = document.getElementById('organizerLoginForm');"));
            client.println(F("    if (loginForm) {"));
            client.println(F("        loginForm.addEventListener('submit', (event) => {"));
            client.println(F("            event.preventDefault(); // Prevent default form submission"));
            client.println(F("            fetchChallengeAndSubmit(); // Initiate challenge-response and submit"));
            client.println(F("        });"));
            client.println(F("    }"));
            client.println(F("    // Scroll to the top of the pre element on load for newest messages visibility"));
            client.println(F("    const preElement = document.querySelector('pre');"));
            client.println(F("    if (preElement) {"));
            client.println(F("        preElement.scrollTop = 0;"));
            client.println(F("    }"));
            client.println(F("});"));
            client.println(F("</script>"));
            client.println(F("<body><header><h1>Protest Information Node</h1>"));
            client.printf("<p class='info-line'><strong>IP:</strong> %s | <strong>MAC:</strong> %s</p>", IP.toString().c_str(), MAC_suffix_str.c_str());
            client.println(F("<p style='font-weight:bold; color:#007bff; margin-top:10px;'>All protest activities are non-violent. Please remain calm, even if others are not.</p>"));
            if (publicMessagingEnabled) {
                client.println(F("<p class='feedback' style='color:orange;'>Warning: Public messages are unmoderated.</p>"));
            }
            client.println(F("</header>"));
            client.println(F("<div class='content-wrapper'><div class='chat-main-content'>"));

            if (webFeedbackMessage.length() > 0) { client.println(webFeedbackMessage); webFeedbackMessage = ""; }

            bool showPublicView = (currentQueryParams.indexOf("show_public=true") != -1);
            bool showUrgentView = (currentQueryParams.indexOf("show_urgent=true") != -1);
            
            String displayedBuffer;
            portENTER_CRITICAL(&localDisplayLogMutex);
            for (const auto& entry : localDisplayLog) {
                const auto& msg = entry.message;
                String formattedLine = "Node " + getMacSuffix(msg.originalSenderMac) + " - ";
                if (msg.messageType == MSG_TYPE_ORGANIZER) formattedLine += "Organizer: ";
                else if (msg.messageType == MSG_TYPE_PUBLIC) formattedLine += "Public: ";
                else if (msg.messageType == MSG_TYPE_COMMAND) formattedLine += "Command: ";
                else if (msg.messageType == MSG_TYPE_AUTO_INIT) formattedLine += "Auto: ";
                formattedLine += String(msg.content);

                // Skip password update messages from display log
                if (msg.messageType == MSG_TYPE_PASSWORD_UPDATE) { 
                    continue; 
                }

                // Apply filters
                bool passesPublicFilter = !(formattedLine.indexOf("Public: ") != -1 && !showPublicView);
                bool passesUrgentFilter = !(formattedLine.indexOf("Urgent: ") == -1 && showUrgentView); // Only show urgent if showUrgentView is true

                if (passesPublicFilter && passesUrgentFilter) {
                    displayedBuffer += escapeHtml(formattedLine) + "\n";
                }
            }
            portEXIT_CRITICAL(&localDisplayLogMutex);

            client.println(F("<h2>Serial Data Log:</h2><h3 style='font-size:0.9em; margin-top:0; color:#555;'>Most recent messages at the top.</h3><pre>"));
            client.print(displayedBuffer);
            client.println(F("</pre>"));

            // Filter buttons
            client.println(F("<div style='text-align:center; margin: 15px; display:flex; justify-content:center; gap: 10px;'>"));
            
            // Public Filter Button
            String publicLink = "/";
            if (showPublicView) { // If currently showing public, link to hide public (preserve urgent state)
                publicLink += "?" + buildQueryString(sessionTokenParam, false, showUrgentView);
            } else { // If currently NOT showing public, link to show public (and disable urgent)
                publicLink += "?" + buildQueryString(sessionTokenParam, true, false);
            }
            client.print("<a href='" + publicLink + "' class='button-link" + (showPublicView ? " secondary" : "") + "'>");
            client.print(showPublicView ? "Hide Public Messages" : "Show Public Messages");
            client.println("</a>");

            // Urgent Filter Button
            String urgentLink = "/";
            if (showUrgentView) { // If currently showing urgent, link to show all (preserve public state)
                urgentLink += "?" + buildQueryString(sessionTokenParam, showPublicView, false);
            } else { // If currently NOT showing urgent, link to show urgent (and disable public)
                urgentLink += "?" + buildQueryString(sessionTokenParam, false, true);
            }
            client.print("<a href='" + urgentLink + "' class='button-link" + (showUrgentView ? " secondary" : "") + "'>");
            client.print(showUrgentView ? "Show All Messages" : "Show Urgent Only");
            client.println("</a>");

            client.println(F("</div>"));


            // Display Organizer Controls based on session token (isOrganizerSessionActive)
            if(isOrganizerSessionActive) {
                client.println(F("<details open><summary>Organizer Controls</summary>"));
                client.println(F("<div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                
                // Only show message sending forms if the node is capable (password set)
                if (passwordChangeLocked) {
                    client.println(F("<h3>Send Organizer Message:</h3><form action='/' method='POST'><input type='hidden' name='action' value='sendMessage'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    // Preserve current filter states for redirect
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));

                    client.printf(F("<label for='msg_input'>Message:</label><input type='text' id='msg_input' name='message' required maxlength='%d'>"), MAX_WEB_MESSAGE_INPUT_LENGTH);
                    client.println(F("<div style='display:flex;align-items:center;justify-content:center;width:80%;margin-bottom:10px;'><input type='checkbox' id='urgent_input' name='urgent' value='on' style='margin-right:8px;'><label for='urgent_input' style='margin-bottom:0;'>Urgent Message</label></div>"));
                    client.println(F("<input type='submit' value='Send Message'></form></div>"));

                    client.println(F("<div class='form-container' style='box-shadow:none;border:none;padding-top:5px;margin-top:5px;'><h3>Admin Actions</h3>"));
                    client.println(F("<form action='/' method='POST' style='flex-direction:row;justify-content:center;gap:10px;'>"));
                    client.println(F("<input type='hidden' name='action' value='rebroadcastCache'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<input type='submit' value='Re-broadcast Cache'></form>"));
                    client.println(F("<form action='/' method='POST' style='flex-direction:row;justify-content:center;gap:10px;margin-top:10px;'>"));
                    client.println(F("<input type='hidden' name='action' value='togglePublic'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    
                    // NEW: Public messaging toggle button logic
                    if (publicMessagingLocked) {
                        client.print(F("<input type='submit' value='Public Msgs Locked (Off)' disabled class='button-link disabled'>"));
                    } else {
                        client.print(F("<input type='submit' value='"));
                        client.print(publicMessagingEnabled ? "Disable Public Msgs" : "Enable Public Msgs");
                        client.println(F("'></form>"));
                    }
                    client.println(F("</div>")); // Close Admin Actions form-container
                } else {
                    // If session is active but node is not capable (password not set)
                    client.println(F("<p class='feedback' style='color:orange;'>You are logged in, but this node is not yet configured to send messages. Please set an organizer password to enable sending messages. Alternatively, if the password has already been set on another node in the mesh, this node will eventually receive it and enable sending.</p>"));
                }

                // Always show Exit Organizer Mode button if logged in
                client.println(F("<form action='/' method='POST' style='margin-top:10px;'><input type='hidden' name='action' value='exitOrganizer'>"));
                client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                client.println(F("<input type='submit' value='Exit Organizer Mode' class='button-link secondary' style='background-color:#dc3545;'></form>"));

                client.println(F("</div></details>")); // Close Organizer Controls details and form-container

                // Password Management Section (Consolidated)
                client.println(F("<details style='margin-top:10px;'><summary style='font-size:1.1em;font-weight:bold;cursor:pointer;padding:5px 0;text-align:center; outline: none; border: none; background-color:#007bff; color:white; border-radius:4px;'>Organizer Password Management</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                client.println(F("<h3>Set/Reset Organizer Password:</h3>"));
                
                if (passwordChangeLocked) {
                    client.println(F("<p class='feedback' style='color:red; font-size:0.8em; margin-top:10px;'>The organizer password for this node cannot be changed after it has been set. To reset the password, you must reboot the board.</p>"));
                } else {
                    client.println(F("<form action='/' method='POST'>"));
                    client.println(F("<input type='hidden' name='action' value='setOrganizerPassword'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));

                    client.println(F("<label for='new_pass_input'>New Password:</label>"));
                    client.println(F("<input type='password' id='new_pass_input' name='new_password' required>"));
                    client.println(F("<label for='confirm_new_pass_input'>Confirm New Password:</label>"));
                    client.println(F("<input type='password' id='confirm_new_pass_input' name='confirm_new_password' required>"));
                    
                    client.println(F("<input type='submit' value='Set New Password' class='button-link'>"));
                    client.println(F("</form>"));
                    client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>Once the organizer password is set for this node, this option will be locked. To reset the password, you must reboot the board.</p>"));
                }
                client.println(F("</div></details>"));

            } else { // Not in organizer session (isOrganizerSessionActive is false)
                // If passwordChangeLocked is false, prompt to set initial password
                if (!passwordChangeLocked) {
                    client.println(F("<details open><summary>Set Initial Organizer Password</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<h3>Set Your Organizer Password:</h3><form action='/' method='POST'><input type='hidden' name='action' value='setOrganizerPassword'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='new_pass_input'>New Password:</label><input type='password' id='new_pass_input' name='new_password' required>"));
                    client.println(F("<label for='confirm_new_pass_input'>Confirm New Password:</label><input type='password' id='confirm_new_pass_input' name='confirm_new_password' required>"));
                    client.println(F("<input type='submit' value='Set Password' class='button-link' style='background-color:#007bff;'></form>"));
                    client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>Once the organizer password is set for this node, this option will be hidden and you will need to log in to change it.</p>")); // Restored explanation
                    client.println(F("</div></details>"));
                } else { // Password has been set, prompt to log in
                    client.println(F("<details><summary>Enter Organizer Mode</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<form id='organizerLoginForm' action='/' method='POST'><input type='hidden' name='action' value='enterOrganizer'>"));
                    client.println(F("<input type='hidden' id='challenge_nonce_input' name='challenge_nonce' value=''>"));
                    client.println(F("<input type='hidden' id='password_response_hash_input' name='password_response_hash' value=''>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='pass_input'>Password:</label><input type='password' id='pass_input' name='password_plaintext_client' required>"));
                    client.println(F("<input type='submit' value='Enter Mode'></form></div></details>"));
                }
                
                // Public message sending form (only if enabled AND node is capable)
                if(publicMessagingEnabled && passwordChangeLocked) { 
                    client.println(F("<details><summary>Send a Public Message</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<h3>Message (no password required):</h3><form action='/' method='POST'><input type='hidden' name='action' value='sendPublicMessage'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.printf(F("<label for='pub_msg_input'>Message:</label><input type='text' id='pub_msg_input' name='message' required maxlength='%d'>"), MAX_WEB_MESSAGE_INPUT_LENGTH);
                    client.println(F("<input type='submit' value='Send Public Message'></form></div></details>"));
                } else if (publicMessagingEnabled && !passwordChangeLocked) {
                    client.println(F("<p class='feedback' style='color:orange;'>Public messaging is enabled, but this node is not yet configured to send messages. Please set an organizer password to enable sending messages. Alternatively, if the password has already been set on another node in the mesh, this node will eventually receive it and enable sending.</p>"));
                }
            }

            client.print(detectedNodesHtmlContent);
            client.println(F("</div></div></body></html>"));
            break;
          } else {
            if (currentLine.startsWith("GET")) {
              isPost = false;
              int pathStart = currentLine.indexOf(' ') + 1;
              int pathEnd = currentLine.indexOf(' ', pathStart);
              if (pathStart != -1 && pathEnd != -1 && pathEnd > pathStart) {
                requestedPath = currentLine.substring(pathStart, pathEnd);
              }
            } else if (currentLine.startsWith("POST")) {
              isPost = true;
            }
            if (currentLine.startsWith("Content-Length: ")) {
              contentLength = currentLine.substring(16).toInt();
              if (contentLength > MAX_POST_BODY_LENGTH) {
                  Serial.printf("Error: Excessive Content-Length (%d). Closing connection to prevent DoS.\n", contentLength);
                  client.stop();
                  return;
              }
            }
            currentLine = "";
          }
        } else if (c != '\r') {
          currentLine += c;
        }
      }
    }
    client.stop();
  }

  // The userMessageBuffer is likely from a previous iteration or a placeholder.
  // With the new authentication model, messages should primarily originate from the web UI.
  // Keeping this for now, but it would also need to respect passwordChangeLocked.
  if (userMessageBuffer.length() > 0) {
    String messageContent = userMessageBuffer;
    uint8_t messageType = MSG_TYPE_PUBLIC; // Default to public if not set by organizer
    if (messageContent.startsWith("Urgent: ")) {
        totalUrgentMessages++;
        messageType = MSG_TYPE_ORGANIZER; // Assuming urgent messages are from organizer
    } else {
        messageType = MSG_TYPE_PUBLIC;
    }

    // This part now relies on createAndSendMessage's internal capability check
    createAndSendMessage(messageContent.c_str(), messageContent.length(), messageType);
    userMessageBuffer = "";
  }

#if USE_DISPLAY
  // Dedicated display refresh logic
  if (millis() - lastDisplayRefresh >= DISPLAY_REFRESH_INTERVAL_MS) {
    lastDisplayRefresh = millis();
    if (currentDisplayMode == MODE_CHAT_LOG) {
      displayChatLogMode(TFT_CHAT_LOG_LINES);
    } else if (currentDisplayMode == MODE_URGENT_ONLY) {
      displayUrgentOnlyMode(TFT_URGENT_ONLY_LINES);
    } else if (currentDisplayMode == MODE_DEVICE_INFO) {
      displayDeviceInfoMode();
    } else if (currentDisplayMode == MODE_STATS_INFO) {
      displayStatsInfoMode();
    }
  }

  if (digitalRead(TFT_TOUCH_IRQ_PIN) == LOW && (millis() - lastTouchTime > TOUCH_DEBOUNCE_MS)) {
    lastTouchTime = millis();
    Serial.println("Touch detected! Switching display mode.");

    if (currentDisplayMode == MODE_CHAT_LOG) {
      currentDisplayMode = MODE_URGENT_ONLY;
      displayUrgentOnlyMode(TFT_URGENT_ONLY_LINES);
    } else if (currentDisplayMode == MODE_URGENT_ONLY) {
      currentDisplayMode = MODE_DEVICE_INFO;
      displayDeviceInfoMode();
    } else if (currentDisplayMode == MODE_DEVICE_INFO) {
      currentDisplayMode = MODE_STATS_INFO;
      displayStatsInfoMode();
    }
    else {
      currentDisplayMode = MODE_CHAT_LOG;
      displayChatLogMode(TFT_CHAT_LOG_LINES);
    }
    // Force a display refresh immediately after mode change
    lastDisplayRefresh = 0; // Reset timer to trigger immediate refresh
  }
#endif
}

#if USE_DISPLAY
void displayChatLogMode(int numLines) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: All Messages");
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  
  portENTER_CRITICAL(&localDisplayLogMutex);
  int linesPrinted = 0;
  // Iterate through localDisplayLog (which is sorted newest first)
  for (const auto& entry : localDisplayLog) {
    if (linesPrinted >= numLines) break;
    const auto& msg = entry.message;
    String formattedLine = "Node " + getMacSuffix(msg.originalSenderMac) + " - ";
    if (msg.messageType == MSG_TYPE_ORGANIZER) formattedLine += "Organizer: ";
    else if (msg.messageType == MSG_TYPE_PUBLIC) formattedLine += "Public: ";
    else if (msg.messageType == MSG_TYPE_COMMAND) formattedLine += "Command: ";
    else if (msg.messageType == MSG_TYPE_AUTO_INIT) formattedLine += "Auto: ";
    formattedLine += String(msg.content);

    // Ensure password update messages are not displayed
    if (msg.messageType == MSG_TYPE_PASSWORD_UPDATE) { 
        continue; 
    }
    tft.println(formattedLine);
    linesPrinted++;
  }
  portEXIT_CRITICAL(&localDisplayLogMutex);
}

void displayUrgentOnlyMode(int numLines) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN);        tft.println("Mode: Urgent Only");
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");

  portENTER_CRITICAL(&localDisplayLogMutex);
  int linesPrinted = 0;
  for (const auto& entry : localDisplayLog) {
    if (linesPrinted >= numLines) break;
    const auto& msg = entry.message;
    if (String(msg.content).indexOf("Urgent: ") != -1) { // Check content for "Urgent: " prefix
        String formattedLine = "Node " + getMacSuffix(msg.originalSenderMac) + " - ";
        if (msg.messageType == MSG_TYPE_ORGANIZER) formattedLine += "Organizer: "; // Still include type for display
        formattedLine += String(msg.content);
        tft.println(formattedLine);
        linesPrinted++;
    }
  }
  portEXIT_CRITICAL(&localDisplayLogMutex);
}

void displayDeviceInfoMode() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: Device Info");

  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  tft.println("Nearby Nodes (Last Seen):");

  portENTER_CRITICAL(&lastSeenPeersMutex); // Use the lastSeenPeers for display
  std::vector<std::pair<String, unsigned long>> sortedSeenPeers;
  for (auto const& [macStr, timestamp] : lastSeenPeers) { sortedSeenPeers.push_back({macStr, timestamp}); }
  std::sort(sortedSeenPeers.begin(), sortedSeenPeers.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

  int linesPrinted = 0;
  if (sortedSeenPeers.empty()) {
    tft.println("  No other nodes detected yet.");
  } else {
    for (const auto& macPair : sortedSeenPeers) {
        if (linesPrinted >= MAX_NODES_TO_DISPLAY_TFT) break;
        uint8_t macBytes[6];
        unsigned int tempMac[6]; // Temporary array for sscanf
        sscanf(macPair.first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
               &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);
        // Copy values from temporary unsigned int array to uint8_t array
        for (int k = 0; k < 6; ++k) {
            macBytes[k] = (uint8_t)tempMac[k];
        }

        tft.printf("  %s (seen %lu s ago)\n", formatMaskedMac(macBytes).c_str(), (millis() - macPair.second) / 1000);
        linesPrinted++;
    }
  }
  portEXIT_CRITICAL(&lastSeenPeersMutex);
}

void displayStatsInfoMode() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: Stats Info");
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");

  unsigned long uptimeMillis = millis();
  unsigned long seconds = uptimeMillis / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  unsigned long days = hours / 24;
  seconds %= 60; minutes %= 60; hours %= 24;

  tft.println("Uptime:");
  tft.printf("  Days: %lu, H: %lu, M: %lu, S: %lu\n", days, hours, minutes, seconds);
  tft.println("");

  tft.println("Message Stats:");
  tft.printf("  Total Sent: %lu\n", totalMessagesSent);
  tft.printf("  Total Received: %lu\n", totalMessagesReceived);
  tft.printf("  Urgent Messages: %lu\n", totalUrgentMessages);
  tft.printf("  Cache Size: %u/%u\n", seenMessages.size(), MAX_CACHE_SIZE);

  tft.println("");
  tft.println("Mode Status:");
  tft.printf("  Public Msgs: %s\n", publicMessagingEnabled ? "ENABLED" : "DISABLED");
  tft.printf("  Public Lock: %s\n", publicMessagingLocked ? "LOCKED" : "UNLOCKED"); // NEW: Display public lock status
  tft.printf("  Node Capable (Password Set): %s\n", passwordChangeLocked ? "YES" : "NO"); // Updated display for capability
}
#endif
