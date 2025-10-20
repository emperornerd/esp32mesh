#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h> // For esp_wifi_set_channel
#include <vector>
#include <algorithm>
#include <string.h>
#include <set>
#include <map>
#include <DNSServer.h>
#include <esp_system.h>
#include <esp_mac.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <Preferences.h>
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h" // Added for HMAC


#define USE_DISPLAY true

#if USE_DISPLAY
#include <TFT_eSPI.h>
TFT_eSPI tft = TFT_eSPI();
bool displayActive = false;
// Define the T_IRQ pin explicitly for direct digitalRead debugging
#define TFT_TOUCH_IRQ_PIN 36
#endif

// --- Debugging & Verbosity ---
#define VERBOSE_MODE false // Set to true for detailed serial output, false for quiet operation

// --- Network Configuration Constants ---
const int WIFI_CHANNEL = 1;
const int WEB_SERVER_PORT = 80;
const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress NET_MASK(255, 255, 255, 0);
const int MAX_AP_CONNECTIONS = 8; // Max clients for our AP
const unsigned long AP_INACTIVITY_TIMEOUT_SEC = 600; // 10 minutes to drop inactive clients

// --- Message & Protocol Constants ---
// Maximum content length, must be a multiple of 16 for AES. Total message size is 238 bytes.
#define MAX_MESSAGE_CONTENT_LEN 224
#define MAX_TTL_HOPS 40

// --- NEW: HMAC and Payload Definitions ---
#define HMAC_LEN 32 // Using HMAC-SHA256, which is 32 bytes
// Payload length is the total content length MINUS the HMAC length. 224 - 32 = 192.
#define MAX_PAYLOAD_LEN (MAX_MESSAGE_CONTENT_LEN - HMAC_LEN) 

// Message types for processing and display
#define MSG_TYPE_ORGANIZER 0
#define MSG_TYPE_PUBLIC 1
#define MSG_TYPE_AUTO_INIT 2
#define MSG_TYPE_COMMAND 3
#define MSG_TYPE_UNKNOWN 4
#define MSG_TYPE_DISCOVERY 5
#define MSG_TYPE_PASSWORD_UPDATE 6
#define MSG_TYPE_STATUS_REQUEST 7
#define MSG_TYPE_STATUS_RESPONSE 8
#define MSG_TYPE_JAMMING_ALERT 9

// Command prefixes
const char* CMD_PREFIX = "CMD::";
const char* CMD_PUBLIC_ON = "CMD::PUBLIC_ON";
const char* CMD_PUBLIC_OFF = "CMD::PUBLIC_OFF";

typedef struct __attribute__((packed)) {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  uint8_t ttl;
  uint8_t messageType;
  uint16_t checksum; // No longer used for authentication, replaced by HMAC in content[]
  char content[MAX_MESSAGE_CONTENT_LEN]; // Buffer now holds [HMAC(32) | Payload(192)]
} esp_now_message_t;

// This initial password is used once at setup to generate the initial hash for the web UI.
const char* WEB_PASSWORD = "password";
// Stores the hash of the organizer password for web UI authentication.
String hashedOrganizerPassword;

WiFiServer server(WEB_SERVER_PORT);
IPAddress IP;
String MAC_full_str;
String MAC_suffix_str;
String ssid;
uint8_t ourMacBytes[6];

String userMessageBuffer = "";
String webFeedbackMessage = "";

// --- Session & Authentication Constants ---
String organizerSessionToken = "";
unsigned long sessionTokenTimestamp = 0;
const unsigned long SESSION_TIMEOUT_MS = 900000; // 15 minutes
bool publicMessagingEnabled = false; // Volatile
bool publicMessagingLocked = false;  // Volatile
bool passwordChangeLocked = false; // Volatile: True if organizer password has been set
bool isOrganizerSessionActive = false;
// --- NEW --- Global flag to track which security model is active
bool isUsingDefaultPsk = false; 

int loginAttempts = 0;
unsigned long lockoutTime = 0;
const int MAX_LOGIN_ATTEMPTS = 20;
const unsigned long LOCKOUT_DURATION_MS = 300000; // 5 minutes

// --- Statistics Variables ---
unsigned long totalMessagesSent = 0;
unsigned long totalMessagesReceived = 0;
unsigned long totalUrgentMessages = 0;

// --- Jamming Detection & Security Logging Variables ---
Preferences preferences; // Used for all security logs now
const unsigned long JAMMING_DETECTION_THRESHOLD_MS = 60000; // 60 seconds
const unsigned long JAMMING_ALERT_COOLDOWN_MS = 60000;
const unsigned long JAMMING_MEMORY_RESET_MS = 300000;
unsigned long lastMessageReceivedTimestamp = 0;
bool isCurrentlyJammed = false;
unsigned long lastJammingEventTimestamp = 0;
unsigned long lastJammingAlertSent = 0;
unsigned long communicationRestoredTimestamp = 0;
uint32_t jammingIncidentCount = 0; // Persisted in NVS
unsigned long lastJammingTimestampPersisted = 0; // Persisted timestamp of last jamming start
unsigned long lastJammingDurationPersisted = 0;  // Persisted duration of last jamming event
uint32_t hashFailureCount = 0;     // Persisted in NVS
const int MAX_FAIL_LOG_ENTRIES = 5;
bool securityCountersDirty = false; // Flag to trigger batched NVS write
const unsigned long NVS_WRITE_INTERVAL_MS = 60000; // 1 minute
unsigned long lastNvsWrite = 0;

// --- Infiltration Detection & Security Logging Variables ---
const unsigned long INFILTRATION_WINDOW_MS = 300000; // 5 minutes
const int INFILTRATION_THRESHOLD = 2; // More than 2 unique passwords (i.e., 3+) triggers the alert
bool isInfiltrationAlert = false; // Volatile
unsigned long lastInfiltrationEventTimestamp = 0;
uint32_t infiltrationIncidentCount = 0; // Persisted in NVS
unsigned long lastInfiltrationTimestampPersisted = 0; // Persisted timestamp of last infiltration alert
const int MAX_INFIL_LOG_ENTRIES = 5;

struct PasswordUpdateEvent {
    unsigned long timestamp;
    String passwordHash;
    uint8_t senderMac[6];
};
std::vector<PasswordUpdateEvent> passwordUpdateHistory;
portMUX_TYPE passwordUpdateHistoryMutex = portMUX_INITIALIZER_UNLOCKED;

// --- Timing & Interval Constants ---
unsigned long lastRebroadcast = 0;
const unsigned long DISPLAY_REFRESH_INTERVAL_MS = 10000;
unsigned long lastDisplayRefresh = 0;
const unsigned long LOCAL_DISPLAY_LOG_MANAGE_INTERVAL_MS = 5000;
unsigned long lastLocalDisplayLogManage = 0;
const unsigned long LAST_SEEN_PEERS_MANAGE_INTERVAL_MS = 60000;
unsigned long lastSeenPeersManage = 0;
const unsigned long PEER_DISCOVERY_INTERVAL_MS = 15000;
unsigned long lastDiscoveryBroadcast = 0;
const unsigned long AUTO_REBROADCAST_INTERVAL_MS = 30000;
const unsigned long AP_MANAGEMENT_INTERVAL_MS = 5000; // Interval to check AP status
unsigned long lastApManagement = 0;

DNSServer dnsServer;

// --- START FLASHER FIX ---
// The default factory key.
// THIS ARRAY MUST BE 20 BYTES LONG.
// The first 4 bytes (DE AD BE EF) are "magic bytes" that the web flasher
// searches for. The flasher then *replaces* the 16 bytes that follow.
//
// ***** THE FIX *****
// The 'volatile' keyword is critical here. It tells the compiler that this
// memory can be changed by an external process (our flasher tool). This
// FORCES the compiler to generate code that reads the key from memory at
// runtime in setup(), preventing it from optimizing away the security check.
volatile uint8_t PRE_SHARED_KEY[] = {
  0xDE, 0xAD, 0xBE, 0xEF, // 4-byte Magic prefix for the flasher
  0x7C, 0xE3, 0x91, 0x2F, 0xA8, 0x5D, 0xB4, 0x69, // 16-byte Default PSK
  0x3E, 0xC7, 0x14, 0xF2, 0x86, 0x0B, 0xD9, 0x4A
};
// --- END FLASHER FIX ---

// The session key, derived from the organizer password, used for all other traffic.
uint8_t sessionKey[16]; // Volatile
bool useSessionKey = false; // Volatile

// --- START: AES-CTR Encryption/Decryption ---
// Helper function for AES-CTR encryption/decryption.
void aesCtrCrypt(uint8_t* data, size_t dataLen, uint32_t messageID, const uint8_t* mac, const uint8_t* key) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    unsigned char nonce_counter[16] = {0};
    memcpy(nonce_counter, &messageID, sizeof(messageID));
    memcpy(nonce_counter + sizeof(messageID), mac, 6);

    size_t nc_off = 0;
    unsigned char stream_block[16] = {0};

    mbedtls_aes_crypt_ctr(&aes, dataLen, &nc_off, nonce_counter, stream_block, data, data);
    mbedtls_aes_free(&aes);
}

// Wrapper for encryption, passes the specified key.
void aesCtrEncrypt(uint8_t* data, size_t dataLen, uint32_t messageID, const uint8_t* mac, const uint8_t* key) {
    aesCtrCrypt(data, dataLen, messageID, mac, key);
}

// Wrapper for decryption, passes the specified key.
void aesCtrDecrypt(uint8_t* data, size_t dataLen, uint32_t messageID, const uint8_t* mac, const uint8_t* key) {
    aesCtrCrypt(data, dataLen, messageID, mac, key);
}
// --- END: AES-CTR Encryption/Decryption ---

// A secure SHA-256 hash function with a pseudo-salt for the web UI.
String simpleHash(const String& input) {
    // The pseudo-salt ensures the hash is unique to this application.
    const String PSEUDO_SALT = "ProtestNodeSalt123XYZ";
    String saltedInput = input + PSEUDO_SALT;
    unsigned char hashOutput[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&ctx, (const unsigned char*)saltedInput.c_str(), saltedInput.length());
    mbedtls_sha256_finish(&ctx, hashOutput);
    mbedtls_sha256_free(&ctx);

    String hashString = "";
    for(int i = 0; i < sizeof(hashOutput); i++){
        char hex[3];
        sprintf(hex, "%02x", hashOutput[i]);
        hashString += hex;
    }
    return hashString;
}

// Derives a 16-byte session key from a password and sets state. All changes are VOLATILE.
void deriveAndSetSessionKey(const String& password) {
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char*)password.c_str(), password.length(), hash, 0);
    memcpy(sessionKey, hash, 16); // Use first 16 bytes of SHA-256 hash as the AES key
    useSessionKey = true;
    passwordChangeLocked = true;
    hashedOrganizerPassword = simpleHash(password); // For web UI authentication
    if(VERBOSE_MODE) Serial.println("Volatile session key derived from password.");
}

// This function is still used for *internal* display logs, not for network message security.
uint16_t calculateChecksum(const char* data, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += (uint8_t)data[i];
    }
    return sum;
}

// --- NEW: Secure HMAC Generation Function ---
/**
 * @brief Generates an HMAC-SHA256 for message authentication.
 * * @param msg The message struct (used for headers like ID, MAC, type).
 * @param plaintext_payload The actual user data payload (as a null-terminated string).
 * @param key The 16-byte secret key (sessionKey or PRE_SHARED_KEY).
 * @param hmac_output A 32-byte buffer to store the resulting HMAC.
 */
void generateHMAC(const esp_now_message_t& msg, const char* plaintext_payload, const uint8_t* key, uint8_t* hmac_output) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1); // 1 = hmac
    mbedtls_md_hmac_starts(&ctx, key, 16); // 16-byte key
    
    // Hash the non-content, immutable fields
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)&msg.messageID, sizeof(msg.messageID));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.originalSenderMac, sizeof(msg.originalSenderMac));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)&msg.messageType, sizeof(msg.messageType));
    
    // Hash the actual plaintext payload
    size_t payload_len = strlen(plaintext_payload);
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)plaintext_payload, payload_len);
    
    mbedtls_md_hmac_finish(&ctx, hmac_output);
    mbedtls_md_free(&ctx);
}

struct SeenMessage {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  unsigned long timestamp;
  esp_now_message_t messageData; // Stores the full message data (encrypted) for re-broadcasting
};
std::vector<SeenMessage> seenMessages;
portMUX_TYPE seenMessagesMutex = portMUX_INITIALIZER_UNLOCKED;

// --- Cache & Peer Management Constants ---
const unsigned long DEDUP_CACHE_DURATION_MS = 1800000; // 30 minutes
const size_t MAX_CACHE_SIZE = 100;
const unsigned long PEER_LAST_SEEN_DURATION_MS = 600000; // 10 minutes
const unsigned long ESP_NOW_PEER_TIMEOUT_MS = 300000; // 5 minutes

// Struct for messages queued from ISR to loop()
typedef struct {
    esp_now_message_t messageData;
    uint8_t senderMac[6];
    unsigned long timestamp;
} IsrQueueMessage;

// Struct for logging security events to NVS from the main loop
typedef struct {
    uint8_t senderMac[6];
    uint32_t messageID;
    int type; // e.g., 0 for hash failure
} NvsQueueItem;

QueueHandle_t messageQueue;
QueueHandle_t nvsQueue;
const size_t QUEUE_SIZE = 10;
const size_t NVS_QUEUE_SIZE = 5;

// Struct for messages held for local display
struct LocalDisplayEntry {
    esp_now_message_t message; // Stored in decrypted form (payload only)
    unsigned long timestamp;
};
std::vector<LocalDisplayEntry> localDisplayLog;
portMUX_TYPE localDisplayLogMutex = portMUX_INITIALIZER_UNLOCKED;
const size_t MAX_LOCAL_DISPLAY_LOG_SIZE = 50;
const size_t NUM_ORGANIZER_MESSAGES_TO_RETAIN = 5;
// MAX_WEB_MESSAGE_INPUT_LENGTH: 192 (MAX_PAYLOAD_LEN) - 8 (for "Urgent: " prefix) = 184
const size_t MAX_WEB_MESSAGE_INPUT_LENGTH = 184;
const size_t MAX_POST_BODY_LENGTH = 2048;

// Map to store MACs of all peers for display and management
std::map<String, unsigned long> lastSeenPeers;
portMUX_TYPE lastSeenPeersMutex = portMUX_INITIALIZER_UNLOCKED;

// Map for peers added to ESP-NOW for sending
std::map<String, unsigned long> espNowAddedPeers;
portMUX_TYPE espNowAddedPeersMutex = portMUX_INITIALIZER_UNLOCKED;

// Set to store unique MACs of clients connected to our Soft AP
std::set<String> apConnectedClients;
portMUX_TYPE apClientsMutex = portMUX_INITIALIZER_UNLOCKED;

enum DisplayMode {
  MODE_CHAT_LOG,
  MODE_URGENT_ONLY,
  MODE_DEVICE_INFO,
  MODE_STATS_INFO
};
DisplayMode currentDisplayMode = MODE_CHAT_LOG;

unsigned long lastTouchTime = 0;
const unsigned long TOUCH_DEBOUNCE_MS = 500;
const int TFT_CHAT_LOG_LINES = 22;
const int TFT_URGENT_ONLY_LINES = 22;
const int MAX_NODES_TO_DISPLAY_TFT = 15;

#if USE_DISPLAY
void displayChatLogMode(int numLines);
void displayUrgentOnlyMode(int numLines);
void displayDeviceInfoMode();
void displayStatsInfoMode();
#endif

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

void addDisplayLog(const String& message) {
    portENTER_CRITICAL(&localDisplayLogMutex);
    // Create a dummy message structure for local log entries
    esp_now_message_t dummyMsg;
    memset(&dummyMsg, 0, sizeof(dummyMsg));
    dummyMsg.messageType = MSG_TYPE_UNKNOWN;
    memcpy(dummyMsg.originalSenderMac, ourMacBytes, 6);
    // Use MAX_PAYLOAD_LEN for internal logs, as content[] now holds payload
    message.toCharArray(dummyMsg.content, MAX_PAYLOAD_LEN);
    dummyMsg.content[MAX_PAYLOAD_LEN - 1] = '\0';
    // This checksum is for the internal-only log entry, not network auth
    dummyMsg.checksum = calculateChecksum(dummyMsg.content, strlen(dummyMsg.content));
    LocalDisplayEntry newEntry = {dummyMsg, millis()};
    localDisplayLog.push_back(newEntry);
    if (localDisplayLog.size() > MAX_LOCAL_DISPLAY_LOG_SIZE) {
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
      updated = true;
      break;
    }
  }
  if (!updated) {
    // Prune old messages, but never prune a PASSWORD_UPDATE message
    seenMessages.erase(std::remove_if(seenMessages.begin(), seenMessages.end(),
                                     [currentTime](const SeenMessage& msg) {
                                         // This logic correctly keeps PASSWORD_UPDATE messages forever
                                         if (msg.messageData.messageType == MSG_TYPE_PASSWORD_UPDATE) {
                                             return false;
                                         }
                                         return (currentTime - msg.timestamp) > DEDUP_CACHE_DURATION_MS;
                                     }),
                      seenMessages.end());

    // Manage cache size, ensuring we don't discard a PASSWORD_UPDATE message
    if (seenMessages.size() >= MAX_CACHE_SIZE) {
      auto oldest = std::min_element(seenMessages.begin(), seenMessages.end(),
                                     [](const SeenMessage& a, const SeenMessage& b) {
                                         if (a.messageData.messageType == MSG_TYPE_PASSWORD_UPDATE) return false;
                                         if (b.messageData.messageType == MSG_TYPE_PASSWORD_UPDATE) return true;
                                         return a.timestamp < b.timestamp;
                                     });
      if (oldest != seenMessages.end() && oldest->messageData.messageType != MSG_TYPE_PASSWORD_UPDATE) {
        seenMessages.erase(oldest);
      }
    }
    
    // The message being passed in (msgData) is already encrypted correctly by the caller.
    // Just store it directly, but reset the TTL for our own rebroadcasts.
    esp_now_message_t storedMessage = msgData;
    storedMessage.ttl = MAX_TTL_HOPS;

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
  qMsg.timestamp = millis();

  // Decrypt content using the appropriate key.
  // --- FLASHER FIX: Use (PRE_SHARED_KEY + 4) to skip magic bytes ---
  const uint8_t* keyToUse = (const uint8_t*)PRE_SHARED_KEY + 4;
  if (useSessionKey && qMsg.messageData.messageType != MSG_TYPE_PASSWORD_UPDATE) {
      keyToUse = sessionKey;
  }
  aesCtrDecrypt((uint8_t*)qMsg.messageData.content, MAX_MESSAGE_CONTENT_LEN, qMsg.messageData.messageID, qMsg.messageData.originalSenderMac, keyToUse);
  qMsg.messageData.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0'; // Ensure null termination for safety

  // --- START: HMAC Authentication ---
  // The decrypted content is now [HMAC(32) | Payload(192)]

  // 1. Extract received HMAC
  uint8_t received_hmac[HMAC_LEN];
  memcpy(received_hmac, qMsg.messageData.content, HMAC_LEN);
  
  // 2. Extract received payload
  char received_payload[MAX_PAYLOAD_LEN];
  memcpy(received_payload, qMsg.messageData.content + HMAC_LEN, MAX_PAYLOAD_LEN);
  received_payload[MAX_PAYLOAD_LEN - 1] = '\0';
  
  // 3. Calculate expected HMAC
  uint8_t expected_hmac[HMAC_LEN];
  // Note: We pass the *original* message struct (qMsg.messageData) to generateHMAC,
  // as it uses fields like messageID, mac, and type. But we pass the *extracted* payload.
  generateHMAC(qMsg.messageData, received_payload, keyToUse, expected_hmac);

  // 4. Compare HMACs in constant time
  int diff = 0;
  for (int i = 0; i < HMAC_LEN; i++) {
      diff |= received_hmac[i] ^ expected_hmac[i];
  }

  if (diff != 0) {
      // HMAC mismatch, queue for logging in main loop.
      NvsQueueItem nvsItem;
      memcpy(nvsItem.senderMac, recvInfo->src_addr, 6);
      nvsItem.messageID = qMsg.messageData.messageID;
      nvsItem.type = 0; // 0 for hash/HMAC failure
      xQueueSendFromISR(nvsQueue, &nvsItem, 0);
      return; // Drop the message
  }

  // 5. Authentication successful. Overwrite the content buffer with *only* the payload
  //    so the rest of the code works as expected.
  memset(qMsg.messageData.content, 0, MAX_MESSAGE_CONTENT_LEN);
  memcpy(qMsg.messageData.content, received_payload, strlen(received_payload) + 1); // +1 for null term
  
  // --- END: HMAC Authentication ---

  if (qMsg.messageData.ttl == 0) {
      return;
  }

  // Queue the message for processing in the main loop
  if (xQueueSendFromISR(messageQueue, &qMsg, 0) != pdPASS) {
    // Message dropped due to queue full
  }
}

void sendToAllPeers(esp_now_message_t& message) {
  uint8_t currentMacBytes[6];
  memcpy(currentMacBytes, ourMacBytes, 6);

  if (message.ttl > 0) {
      message.ttl--; // Decrement TTL for this hop
  } else {
      if(VERBOSE_MODE) Serial.println("Attempted to re-broadcast message with TTL 0. Skipping.");
      return;
  }

  portENTER_CRITICAL(&espNowAddedPeersMutex);
  for (auto const& [macStr, timestamp] : espNowAddedPeers) {
    uint8_t peerMacBytes[6];
    unsigned int tempMac[6];
    sscanf(macStr.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
           &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);
    for (int k = 0; k < 6; ++k) { peerMacBytes[k] = (uint8_t)tempMac[k]; }

    // Only send to peers that are NOT our own MAC and NOT the original sender
    if (memcmp(peerMacBytes, currentMacBytes, 6) != 0 && memcmp(peerMacBytes, message.originalSenderMac, 6) != 0) {
      esp_now_send(peerMacBytes, (uint8_t*)&message, sizeof(esp_now_message_t));
    }
  }
  portEXIT_CRITICAL(&espNowAddedPeersMutex);
}

void createAndSendMessage(const char* plaintext_data, size_t plaintext_data_len, uint8_t type, const uint8_t* targetMac = nullptr) {
  // Node can send Organizer/Public messages only if a non-default password has been set.
 if ((type == MSG_TYPE_ORGANIZER || type == MSG_TYPE_PUBLIC) && !useSessionKey) {
        if(VERBOSE_MODE) Serial.println("Node not capable of sending this message type (password not set). Skipping send.");
    webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Node not configured to send this message. Set an organizer password first.</p>";
    return;
  }

  esp_now_message_t newMessage;
  memset(&newMessage, 0, sizeof(newMessage));
  newMessage.messageID = esp_random();
  memcpy(newMessage.originalSenderMac, ourMacBytes, 6);
  newMessage.ttl = MAX_TTL_HOPS;
  newMessage.messageType = type;

  // Copy plaintext to a temporary buffer, respecting new payload length
  size_t len_to_copy = std::min(plaintext_data_len, (size_t)MAX_PAYLOAD_LEN - 1);
  char plaintext_payload[MAX_PAYLOAD_LEN];
  strncpy(plaintext_payload, plaintext_data, len_to_copy);
  plaintext_payload[len_to_copy] = '\0';


  // Determine the key to use for HMAC and Encryption
  // --- FLASHER FIX: Use (PRE_SHARED_KEY + 4) to skip magic bytes ---
  const uint8_t* keyToUse = (const uint8_t*)PRE_SHARED_KEY + 4; // Default to factory key
  if (useSessionKey && type != MSG_TYPE_PASSWORD_UPDATE) {
      keyToUse = sessionKey;
  }

  // --- NEW: Generate HMAC and construct content buffer ---
  // 1. Generate HMAC based on plaintext payload and message headers
  uint8_t hmac_output[HMAC_LEN];
  generateHMAC(newMessage, plaintext_payload, keyToUse, hmac_output);
  
  // 2. Construct the final content: [HMAC(32) | Payload(192)]
  memset(newMessage.content, 0, MAX_MESSAGE_CONTENT_LEN);
  memcpy(newMessage.content, hmac_output, HMAC_LEN);
  memcpy(newMessage.content + HMAC_LEN, plaintext_payload, strlen(plaintext_payload) + 1); // +1 for null
  
  // 3. Set old checksum to 0, it's not used for authentication
  newMessage.checksum = 0;
  // --- END: HMAC Logic ---

  // Encrypt the entire content buffer [HMAC | Payload]
  aesCtrEncrypt((uint8_t*)newMessage.content, MAX_MESSAGE_CONTENT_LEN, newMessage.messageID, newMessage.originalSenderMac, keyToUse);

  if (targetMac != nullptr) {
      esp_now_send(targetMac, (uint8_t*)&newMessage, sizeof(esp_now_message_t));
      if(VERBOSE_MODE) Serial.printf("Sent unicast message (Type: %d, ID: %u) to %02X:%02X:%02X:%02X:%02X:%02X\n",
                    type, newMessage.messageID, targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5]);
  } else {
      sendToAllPeers(newMessage);
  }
  totalMessagesSent++;

  // System messages are not cached or added to the local display log
  if (type == MSG_TYPE_DISCOVERY || type == MSG_TYPE_STATUS_REQUEST || type == MSG_TYPE_STATUS_RESPONSE || type == MSG_TYPE_JAMMING_ALERT) {
      return;
  }
  
  // Pass the already-encrypted message to the cache.
  addOrUpdateMessageToSeen(newMessage.messageID, newMessage.originalSenderMac, newMessage);

  // Add to local display log immediately for originating node (must decrypt a copy first)
  portENTER_CRITICAL(&localDisplayLogMutex);
  esp_now_message_t displayMessage = newMessage;
  aesCtrDecrypt((uint8_t*)displayMessage.content, MAX_MESSAGE_CONTENT_LEN, displayMessage.messageID, displayMessage.originalSenderMac, keyToUse);
  
  // Extract payload from [HMAC | payload] for local display
  char payload_only[MAX_PAYLOAD_LEN];
  memcpy(payload_only, displayMessage.content + HMAC_LEN, MAX_PAYLOAD_LEN);
  payload_only[MAX_PAYLOAD_LEN - 1] = '\0';
  
  // Overwrite the content with just the payload for the display log
  memset(displayMessage.content, 0, MAX_MESSAGE_CONTENT_LEN);
  strncpy(displayMessage.content, payload_only, MAX_PAYLOAD_LEN - 1);
  
  LocalDisplayEntry newEntry = {displayMessage, millis()};
  localDisplayLog.push_back(newEntry);
  portEXIT_CRITICAL(&localDisplayLogMutex);

  if(VERBOSE_MODE) Serial.println("Sending (Plaintext): " + String(plaintext_payload));
}

void manageLocalDisplayLog() {
    portENTER_CRITICAL(&localDisplayLogMutex);
    // 1. Sort the entire log by timestamp, newest first
    std::sort(localDisplayLog.begin(), localDisplayLog.end(), [](const LocalDisplayEntry& a, const LocalDisplayEntry& b) {
        return a.timestamp > b.timestamp;
    });

    std::vector<LocalDisplayEntry> newLocalDisplayLog;
    std::set<std::pair<uint32_t, String>> addedMessageKeys;

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

    // 3. Add other messages until MAX_LOCAL_DISPLAY_LOG_SIZE is reached.
    for (const auto& entry : localDisplayLog) {
        if (newLocalDisplayLog.size() >= MAX_LOCAL_DISPLAY_LOG_SIZE) {
            break;
        }
        if (addedMessageKeys.find({entry.message.messageID, getMacSuffix(entry.message.originalSenderMac)}) == addedMessageKeys.end()) {
            newLocalDisplayLog.push_back(entry);
            addedMessageKeys.insert({entry.message.messageID, getMacSuffix(entry.message.originalSenderMac)});
        }
    }
    localDisplayLog = newLocalDisplayLog;
    portEXIT_CRITICAL(&localDisplayLogMutex);
}

// WiFi event handler to track unique client connections to the AP
void WiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
    if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 info.wifi_ap_staconnected.mac[0], info.wifi_ap_staconnected.mac[1],
                 info.wifi_ap_staconnected.mac[2], info.wifi_ap_staconnected.mac[3],
                 info.wifi_ap_staconnected.mac[4], info.wifi_ap_staconnected.mac[5]);
        portENTER_CRITICAL(&apClientsMutex);
        apConnectedClients.insert(String(macStr));
        portEXIT_CRITICAL(&apClientsMutex);
        if(VERBOSE_MODE) {
            Serial.printf("Station connected to AP: %s\n", macStr);
            Serial.printf("Total unique clients: %d\n", apConnectedClients.size());
        }
    }
}

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(0));

  publicMessagingEnabled = false;
  publicMessagingLocked = false;
  passwordChangeLocked = false;
  isOrganizerSessionActive = false;
  lastMessageReceivedTimestamp = millis();

  messageQueue = xQueueCreate(QUEUE_SIZE, sizeof(IsrQueueMessage));
  if (messageQueue == NULL) {
    Serial.println("Failed to create message queue!");
    while(true) { delay(100); }
  }

  nvsQueue = xQueueCreate(NVS_QUEUE_SIZE, sizeof(NvsQueueItem));
  if (nvsQueue == NULL) {
    Serial.println("Failed to create NVS queue!");
    while(true) { delay(100); }
  }

  preferences.begin("protest-node", false); // false = read/write mode for security logs
  jammingIncidentCount = preferences.getUInt("jamCount", 0);
  lastJammingTimestampPersisted = preferences.getULong("jamLastTs", 0);
  lastJammingDurationPersisted = preferences.getULong("jamLastDur", 0);
  hashFailureCount = preferences.getUInt("hashFailCount", 0);
  infiltrationIncidentCount = preferences.getUInt("infilCount", 0);
  lastInfiltrationTimestampPersisted = preferences.getULong("infilLastTs", 0);
  if (VERBOSE_MODE) Serial.printf("Loaded from NVS -> Jamming: %u, Hash Failures: %u, Infiltration Attempts: %u\n", jammingIncidentCount, hashFailureCount, infiltrationIncidentCount);
  
  // --- START MODIFIED LOGIC ---
  // Determine operational mode based on the PSK at boot time.

  // --- START FLASHER FIX (RUNTIME KEY) ---
  // Define the factory key as a string literal of hex escape codes.
  // This prevents the compiler from treating it as an identical const array
  // for optimization purposes.
  const char* factory_key_string = "\x7C\xE3\x91\x2F\xA8\x5D\xB4\x69"
                                   "\x3E\xC7\x14\xF2\x86\x0B\xD9\x4A";

  // Create a buffer on the stack to hold the key at runtime.
  uint8_t factory_key_runtime[16];

  // Copy the key into the stack buffer.
  // Because this is a runtime operation (memcpy), the compiler
  // CANNOT optimize away the comparison.
  memcpy(factory_key_runtime, factory_key_string, 16);
  // --- END FLASHER FIX (RUNTIME KEY) ---
  

  // --- FLASHER FIX: Compare (PRE_SHARED_KEY + 4) to skip magic bytes ---
  // Because PRE_SHARED_KEY is volatile AND factory_key_runtime is a runtime variable,
  // this memcmp is FORCED to execute at runtime, defeating the optimizer.
  if (memcmp((const void*)(PRE_SHARED_KEY + 4), factory_key_runtime, 16) == 0) {
    // The key IS the default factory key.
    isUsingDefaultPsk = true;
    if(VERBOSE_MODE) Serial.println("Operating Mode: Compatibility. Awaiting organizer password to secure mesh.");
    // Set the initial web UI password to the default value. This is ONLY for login.
    hashedOrganizerPassword = simpleHash(WEB_PASSWORD);
  } else {
    // The key IS NOT the default. It was flashed by the secure tool.
    isUsingDefaultPsk = false;
    if(VERBOSE_MODE) Serial.println("Operating Mode: Secure. Flashed PSK is the final mesh key.");
    
    // Immediately adopt the flashed key as the session key for mesh communication.
    // --- FLASHER FIX: Copy from (PRE_SHARED_KEY + 4) to skip magic bytes ---
    memcpy(sessionKey, (const void*)(PRE_SHARED_KEY + 4), 16);
    useSessionKey = true;
    
    // Set the initial web UI password to the default value. The organizer will
    // need to log in with "password" and then set a new HUMAN-READABLE password
    // for future UI logins. This new password will NOT change the mesh key.
    hashedOrganizerPassword = simpleHash(WEB_PASSWORD);
  }  // --- END MODIFIED LOGIC ---

  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.onEvent(WiFiEvent);

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
  // Configure AP with a max number of connections. SSID is initially visible (param 4 is 0).
  WiFi.softAP(ssid.c_str(), nullptr, WIFI_CHANNEL, 0, MAX_AP_CONNECTIONS);
  
  // Set a timeout to automatically disconnect inactive clients to free up slots.
  esp_wifi_set_inactive_time(WIFI_IF_AP, AP_INACTIVITY_TIMEOUT_SEC);

  IP = WiFi.softAPIP();
  server.begin();

  dnsServer.start(53, "*", AP_IP);
  Serial.println("DNS server started, redirecting all domains to: " + IP.toString());

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
  if(VERBOSE_MODE) Serial.printf("T_IRQ pin set to INPUT_PULLUP on GPIO%d\n", TFT_TOUCH_IRQ_PIN);
  displayChatLogMode(TFT_CHAT_LOG_LINES);
#endif

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    while(true) { delay(100); }
  }

  uint8_t broadcastMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  esp_now_peer_info_t peer{};
  memcpy(peer.peer_addr, broadcastMac, 6);
  peer.channel = WIFI_CHANNEL;
  peer.encrypt = false;
  esp_now_add_peer(&peer);

  portENTER_CRITICAL(&espNowAddedPeersMutex);
  espNowAddedPeers[formatMac(broadcastMac)] = millis();
  portEXIT_CRITICAL(&espNowAddedPeersMutex);

  esp_now_register_recv_cb(onDataRecv);

  char msgContentBuf[MAX_PAYLOAD_LEN];
  snprintf(msgContentBuf, sizeof(msgContentBuf), "Node %s initializing", MAC_suffix_str.c_str());
  createAndSendMessage(msgContentBuf, strlen(msgContentBuf), MSG_TYPE_AUTO_INIT);

  createAndSendMessage(MAC_full_str.c_str(), MAC_full_str.length(), MSG_TYPE_DISCOVERY);
  lastDiscoveryBroadcast = millis();

  lastRebroadcast = millis();
  lastLocalDisplayLogManage = millis();
  lastSeenPeersManage = millis();
  lastNvsWrite = millis();
  lastApManagement = millis();
}

String buildQueryString(const String& sessionToken, bool showPublic, bool showUrgent, bool hideSystem) {
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
    if (hideSystem) {
        if (query.length() > 0) query += "&";
        query += "hide_system=true";
    }
    return query;
}

void loop() {
  dnsServer.processNextRequest();

  // --- Process Security Event Queue for NVS Logging ---
  NvsQueueItem nvsItem;
  while (xQueueReceive(nvsQueue, &nvsItem, 0) == pdPASS) {
      if (nvsItem.type == 0) { // Hash/HMAC failure
          hashFailureCount++;
          securityCountersDirty = true;
          uint8_t failLogIndex = preferences.getUChar("failLogIdx", 0);
          String logData = formatMac(nvsItem.senderMac) + " | ID: " + String(nvsItem.messageID);
          String key = "failMsg" + String(failLogIndex);
          preferences.putString(key.c_str(), logData);
          failLogIndex = (failLogIndex + 1) % MAX_FAIL_LOG_ENTRIES;
          preferences.putUChar("failLogIdx", failLogIndex);
          if(VERBOSE_MODE) Serial.printf("Logged hash/HMAC failure from %s. Total failures: %u\n", formatMac(nvsItem.senderMac).c_str(), hashFailureCount);
      }
  }

  IsrQueueMessage qMsg;
  while (xQueueReceive(messageQueue, &qMsg, 0) == pdPASS) {
    lastMessageReceivedTimestamp = millis();
    if (isCurrentlyJammed) {
        isCurrentlyJammed = false;
        communicationRestoredTimestamp = millis();
        if(VERBOSE_MODE) Serial.println("Communication restored. Jamming appears to have stopped.");
        if (lastJammingEventTimestamp > 0) {
            lastJammingDurationPersisted = millis() - lastJammingEventTimestamp;
            securityCountersDirty = true;
        }
        addDisplayLog("Communication restored.");
    }

    esp_now_message_t incomingMessage = qMsg.messageData;
    uint8_t* recvInfoSrcAddr = qMsg.senderMac;
    unsigned long receptionTimestamp = qMsg.timestamp;
    // Note: incomingMessage.content is now *only* the payload, auth was handled in onDataRecv
    String incomingContent = String(incomingMessage.content); 
    String originalSenderMacSuffix = getMacSuffix(incomingMessage.originalSenderMac);

    portENTER_CRITICAL(&lastSeenPeersMutex);
    lastSeenPeers[formatMac(recvInfoSrcAddr)] = receptionTimestamp;
    portEXIT_CRITICAL(&lastSeenPeersMutex);

    String senderMacStr = formatMac(recvInfoSrcAddr);
    esp_now_peer_info_t peer{};
    memcpy(peer.peer_addr, recvInfoSrcAddr, 6);
    peer.channel = WIFI_CHANNEL;
    peer.encrypt = false;

    esp_err_t addPeerResult = esp_now_add_peer(&peer);
    if (addPeerResult == ESP_OK || addPeerResult == ESP_ERR_ESPNOW_EXIST) {
      portENTER_CRITICAL(&espNowAddedPeersMutex);
      espNowAddedPeers[senderMacStr] = millis();
      portEXIT_CRITICAL(&espNowAddedPeersMutex);
    } else {
      if(VERBOSE_MODE) Serial.printf("Failed to add peer %s: %d\n", senderMacStr.c_str(), addPeerResult);
    }

    if (incomingMessage.messageType == MSG_TYPE_DISCOVERY) {
        continue;
    }

    if (incomingMessage.messageType == MSG_TYPE_JAMMING_ALERT) {
        if (lastJammingEventTimestamp == 0) {
            if(VERBOSE_MODE) Serial.println("Received JAMMING_ALERT from a peer. Updating local status.");
            lastJammingEventTimestamp = millis();
            jammingIncidentCount++;
            lastJammingTimestampPersisted = millis();
            securityCountersDirty = true;
        }
        // Need to re-create the [HMAC | payload] structure for caching
        esp_now_message_t encryptedForCache = incomingMessage;
        // --- FLASHER FIX: Use (PRE_SHARED_KEY + 4) to skip magic bytes ---
        const uint8_t* keyToUse = useSessionKey ? sessionKey : (const uint8_t*)(PRE_SHARED_KEY + 4);
        
        char payload_for_hmac[MAX_PAYLOAD_LEN];
        strncpy(payload_for_hmac, incomingMessage.content, MAX_PAYLOAD_LEN - 1);
        payload_for_hmac[MAX_PAYLOAD_LEN - 1] = '\0';
        
        uint8_t hmac_output[HMAC_LEN];
        generateHMAC(encryptedForCache, payload_for_hmac, keyToUse, hmac_output);
        
        memset(encryptedForCache.content, 0, MAX_MESSAGE_CONTENT_LEN);
        memcpy(encryptedForCache.content, hmac_output, HMAC_LEN);
        memcpy(encryptedForCache.content + HMAC_LEN, payload_for_hmac, strlen(payload_for_hmac) + 1);

        aesCtrEncrypt((uint8_t*)encryptedForCache.content, MAX_MESSAGE_CONTENT_LEN, encryptedForCache.messageID, encryptedForCache.originalSenderMac, keyToUse);
        addOrUpdateMessageToSeen(encryptedForCache.messageID, encryptedForCache.originalSenderMac, encryptedForCache);
        continue;
    }

    bool wasAlreadySeen = isMessageSeen(incomingMessage.messageID, incomingMessage.originalSenderMac);
    bool skipDisplayLog = false;

    if (incomingMessage.messageType == MSG_TYPE_STATUS_REQUEST) {
        if(VERBOSE_MODE) Serial.printf("Received STATUS_REQUEST from %02X:%02X:%02X:%02X:%02X:%02X. Replying with status.\n", recvInfoSrcAddr[0], recvInfoSrcAddr[1], recvInfoSrcAddr[2], recvInfoSrcAddr[3], recvInfoSrcAddr[4], recvInfoSrcAddr[5]);
        char responseContent[3];
        responseContent[0] = publicMessagingEnabled ? '1' : '0';
        responseContent[1] = publicMessagingLocked ? '1' : '0';
        responseContent[2] = '\0';
        createAndSendMessage(responseContent, strlen(responseContent), MSG_TYPE_STATUS_RESPONSE, incomingMessage.originalSenderMac);
        if(VERBOSE_MODE) Serial.printf("Sent STATUS_RESPONSE (publicEnabled=%s, publicLocked=%s) to %02X:%02X:%02X:%02X:%02X:%02X\n",
                      publicMessagingEnabled ? "true" : "false", publicMessagingLocked ? "true" : "false", incomingMessage.originalSenderMac[0], incomingMessage.originalSenderMac[1], incomingMessage.originalSenderMac[2], incomingMessage.originalSenderMac[3], incomingMessage.originalSenderMac[4], incomingMessage.originalSenderMac[5]);
        continue;
    }

    if (incomingMessage.messageType == MSG_TYPE_STATUS_RESPONSE) {
        bool peerPublicStatus = (incomingMessage.content[0] == '1');
        bool peerPublicLockedStatus = (incomingMessage.content[1] == '1');
        if(VERBOSE_MODE) Serial.printf("Received STATUS_RESPONSE from %02X:%02X:%02X:%02X:%02X:%02X. Peer Public Enabled: %s, Peer Public Locked: %s\n",
                      incomingMessage.originalSenderMac[0], incomingMessage.originalSenderMac[1], incomingMessage.originalSenderMac[2], incomingMessage.originalSenderMac[3], incomingMessage.originalSenderMac[4], incomingMessage.originalSenderMac[5], peerPublicStatus ? "true" : "false", peerPublicLockedStatus ? "true" : "false");
        addDisplayLog(String("Peer ") + getMacSuffix(incomingMessage.originalSenderMac) + " Public Status: " + (peerPublicStatus ? "ENABLED" : "DISABLED") + ", Locked: " + (peerPublicLockedStatus ? "YES" : "NO"));
        if (!publicMessagingLocked) {
            publicMessagingEnabled = peerPublicStatus;
            if(VERBOSE_MODE) Serial.printf("Local publicMessagingEnabled set to: %s (from peer status)\n", publicMessagingEnabled ? "true" : "false");
        }
        if (peerPublicLockedStatus && !publicMessagingLocked) {
            publicMessagingLocked = true;
            publicMessagingEnabled = false;
            if(VERBOSE_MODE) Serial.println("Local publicMessagingLocked set to TRUE (from peer status). Public messaging DISABLED.");
        }
        continue;
    }
    
    // --- START: MODIFIED/FIXED PASSWORD_UPDATE BLOCK ---
    if (incomingMessage.messageType == MSG_TYPE_PASSWORD_UPDATE) {
        String incomingPass = String(incomingMessage.content);

        // This core logic should only run the *first* time we see this password update
        if (!wasAlreadySeen) {
            // always update web UI login password
            hashedOrganizerPassword = simpleHash(incomingPass);
            passwordChangeLocked    = true;

            // Compatibility mode nodes need to derive the new key.
            if (isUsingDefaultPsk) {
                if(VERBOSE_MODE) Serial.println("Received new password in Compat mode. Deriving new session key.");
                deriveAndSetSessionKey(incomingPass);
            } else {
                if(VERBOSE_MODE) Serial.println("Received new password in Secure mode. Updating web UI hash only.");
            }
        }
            
        // Infiltration Detection Logic (runs for all password updates)    
        // --- START: Infiltration Detection Logic (runs for all password updates) ---
        String newPasswordHash = simpleHash(String(incomingMessage.content));
        unsigned long currentTime = millis();

        portENTER_CRITICAL(&passwordUpdateHistoryMutex);
        // 1. Prune old entries from history
        passwordUpdateHistory.erase(std::remove_if(passwordUpdateHistory.begin(), passwordUpdateHistory.end(),
            [currentTime](const PasswordUpdateEvent& event) {
                return (currentTime - event.timestamp) > INFILTRATION_WINDOW_MS;
            }), passwordUpdateHistory.end());

        // 2. Add the new event
        PasswordUpdateEvent newEvent;
        newEvent.timestamp = currentTime;
        newEvent.passwordHash = newPasswordHash;
        memcpy(newEvent.senderMac, incomingMessage.originalSenderMac, 6);
        passwordUpdateHistory.push_back(newEvent);

        // 3. Check for conflicting passwords
        std::set<String> uniqueHashesInWindow;
        for (const auto& event : passwordUpdateHistory) {
            uniqueHashesInWindow.insert(event.passwordHash);
        }
        portEXIT_CRITICAL(&passwordUpdateHistoryMutex);

        if (uniqueHashesInWindow.size() > INFILTRATION_THRESHOLD) {
            if (!isInfiltrationAlert) {
                if(VERBOSE_MODE) Serial.println("INFILTRATION ATTEMPT DETECTED: Multiple conflicting passwords received in a short period.");
                isInfiltrationAlert = true;
                lastInfiltrationEventTimestamp = millis();
                infiltrationIncidentCount++;
                lastInfiltrationTimestampPersisted = millis();
                securityCountersDirty = true;

                // Log the MAC of the sender that triggered the alert
                uint8_t infilLogIndex = preferences.getUChar("infilLogIdx", 0);
                String logData = formatMac(incomingMessage.originalSenderMac);
                String key = "infilMsg" + String(infilLogIndex);
                preferences.putString(key.c_str(), logData);
                infilLogIndex = (infilLogIndex + 1) % MAX_INFIL_LOG_ENTRIES;
                preferences.putUChar("infilLogIdx", infilLogIndex);
                if (VERBOSE_MODE) Serial.printf("Logged infiltration attempt from %s. Total attempts: %u\n", formatMac(incomingMessage.originalSenderMac).c_str(), infiltrationIncidentCount);

                addDisplayLog("Infiltration Alert!");
            }
        }
        
        skipDisplayLog = true;

        // --- FIX ---
        // We DO NOT call createAndSendMessage() here. This was causing a broadcast storm
        // by re-originating the password update message on every node.
        // We now fall-through to the generic message handler below, which will
        // correctly add the message to the cache and forward it (not re-originate)
        // if it was not seen.
    }
    // --- END: MODIFIED/FIXED PASSWORD_UPDATE BLOCK ---
    
    // For every message that isn't a discovery/status message, prepare it for caching and potential rebroadcast
    // We must re-create the [HMAC | payload] structure and re-encrypt it for the cache
    esp_now_message_t encryptedForCache = incomingMessage; // incomingMessage has plaintext *payload only*
    // --- FLASHER FIX: Use (PRE_SHARED_KEY + 4) to skip magic bytes ---
    const uint8_t* keyToUseForCache = (const uint8_t*)PRE_SHARED_KEY + 4; // Default to PSK
    if(useSessionKey && encryptedForCache.messageType != MSG_TYPE_PASSWORD_UPDATE) {
        keyToUseForCache = sessionKey; // Use session key for normal traffic
    }
    
    // Re-create payload for HMAC
    char payload_for_hmac[MAX_PAYLOAD_LEN];
    strncpy(payload_for_hmac, incomingMessage.content, MAX_PAYLOAD_LEN - 1);
    payload_for_hmac[MAX_PAYLOAD_LEN - 1] = '\0';
    
    // Generate HMAC
    uint8_t hmac_output[HMAC_LEN];
    generateHMAC(encryptedForCache, payload_for_hmac, keyToUseForCache, hmac_output);
    
    // Construct the [HMAC | payload] buffer
    memset(encryptedForCache.content, 0, MAX_MESSAGE_CONTENT_LEN);
    memcpy(encryptedForCache.content, hmac_output, HMAC_LEN);
    memcpy(encryptedForCache.content + HMAC_LEN, payload_for_hmac, strlen(payload_for_hmac) + 1);

    // Encrypt the message content before caching
    aesCtrEncrypt((uint8_t*)encryptedForCache.content, MAX_MESSAGE_CONTENT_LEN, encryptedForCache.messageID, encryptedForCache.originalSenderMac, keyToUseForCache);
    addOrUpdateMessageToSeen(encryptedForCache.messageID, encryptedForCache.originalSenderMac, encryptedForCache);

    if (!wasAlreadySeen) {
        totalMessagesReceived++;
        if (String(incomingMessage.content).indexOf("Urgent: ") != -1) {
            totalUrgentMessages++;
        }
        if (!skipDisplayLog) {
            portENTER_CRITICAL(&localDisplayLogMutex);
            // incomingMessage already contains *only* the payload
            LocalDisplayEntry newEntry = {incomingMessage, millis()};
            localDisplayLog.push_back(newEntry);
            portEXIT_CRITICAL(&localDisplayLogMutex);
        }
        if (incomingMessage.ttl > 0) {
            // Re-use the already encrypted version we prepared for the cache
            sendToAllPeers(encryptedForCache);
        } else {
            if(VERBOSE_MODE) Serial.println("Message reached TTL limit, not re-broadcasting.");
        }
    }

    if (incomingMessage.messageType == MSG_TYPE_COMMAND) {
        if (incomingContent.equals(CMD_PUBLIC_ON)) {
            if (!publicMessagingLocked) {
                if (!publicMessagingEnabled) {
                    publicMessagingEnabled = true;
                    if(VERBOSE_MODE) Serial.println("Received command: ENABLE public messaging.");
                    webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging was ENABLED by an organizer.</p>";
                }
            } else {
                if(VERBOSE_MODE) Serial.println("Received command: ENABLE public messaging, but it is locked OFF. Ignoring.");
                webFeedbackMessage = "<p class='feedback' style='color:orange;'>Public messaging is locked OFF by a previous organizer command. Cannot re-enable.</p>";
            }
        } else if (incomingContent.equals(CMD_PUBLIC_OFF)) {
            if (publicMessagingEnabled || !publicMessagingLocked) {
                publicMessagingEnabled = false;
                publicMessagingLocked = true;
                if(VERBOSE_MODE) Serial.println("Received command: DISABLE public messaging. Status is now LOCKED OFF.");
                webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging was DISABLED and LOCKED OFF by an organizer.</p>";
            } else {
                if(VERBOSE_MODE) Serial.println("Received command: DISABLE public messaging, but it was already locked OFF. No change.");
            }
        }
    }
    if(VERBOSE_MODE) Serial.println("Message processed from queue: Node " + originalSenderMacSuffix + " - " + incomingContent);
  }

  // --- Jamming Detection Logic ---
  bool hasPeers = false;
  portENTER_CRITICAL(&lastSeenPeersMutex);
  hasPeers = lastSeenPeers.size() > 1;
  portEXIT_CRITICAL(&lastSeenPeersMutex);

  if (hasPeers && !isCurrentlyJammed && (millis() - lastMessageReceivedTimestamp > JAMMING_DETECTION_THRESHOLD_MS)) {
      if(VERBOSE_MODE) Serial.println("Jamming detected: No messages received from known peers for threshold duration.");
      isCurrentlyJammed = true;
      if (lastJammingEventTimestamp == 0) {
          lastJammingEventTimestamp = millis();
          jammingIncidentCount++;
          lastJammingTimestampPersisted = millis();
          securityCountersDirty = true;
          if(VERBOSE_MODE) Serial.printf("New jamming incident logged. Total incidents: %u\n", jammingIncidentCount);
          addDisplayLog("Jamming event detected!");
      }
      if (millis() - lastJammingAlertSent > JAMMING_ALERT_COOLDOWN_MS) {
          if(VERBOSE_MODE) Serial.println("Sending jamming alert to the mesh.");
          char alertContent[MAX_PAYLOAD_LEN];
          snprintf(alertContent, sizeof(alertContent), "Jamming Alert from %s", MAC_suffix_str.c_str());
          createAndSendMessage(alertContent, strlen(alertContent), MSG_TYPE_JAMMING_ALERT);
          lastJammingAlertSent = millis();
      }
  }

  // --- Jamming Long-Term Memory Reset Logic ---
  if (lastJammingEventTimestamp > 0 && !isCurrentlyJammed && communicationRestoredTimestamp > 0 &&
      (millis() - communicationRestoredTimestamp > JAMMING_MEMORY_RESET_MS)) {
      if(VERBOSE_MODE) Serial.println("Sustained communication detected. Resetting long-term jamming memory.");
      lastJammingEventTimestamp = 0;
      communicationRestoredTimestamp = 0;
      addDisplayLog("Jamming alert cleared.");
  }

  // --- Infiltration Alert Reset Logic ---
  if (isInfiltrationAlert && (millis() - lastInfiltrationEventTimestamp > JAMMING_MEMORY_RESET_MS)) {
      if(VERBOSE_MODE) Serial.println("Infiltration alert timeout. Resetting alert status.");
      isInfiltrationAlert = false;
      // Also clear the history to prevent immediate re-triggering from old data
      portENTER_CRITICAL(&passwordUpdateHistoryMutex);
      passwordUpdateHistory.clear();
      portEXIT_CRITICAL(&passwordUpdateHistoryMutex);
      addDisplayLog("Infiltration alert cleared.");
  }

  // --- Batched NVS Write for Security Counters ---
  if (securityCountersDirty && (millis() - lastNvsWrite > NVS_WRITE_INTERVAL_MS)) {
      preferences.putUInt("jamCount", jammingIncidentCount);
      preferences.putULong("jamLastTs", lastJammingTimestampPersisted);
      preferences.putULong("jamLastDur", lastJammingDurationPersisted);
      preferences.putUInt("hashFailCount", hashFailureCount);
      preferences.putUInt("infilCount", infiltrationIncidentCount);
      preferences.putULong("infilLastTs", lastInfiltrationTimestampPersisted);
      securityCountersDirty = false;
      lastNvsWrite = millis();
      if(VERBOSE_MODE) Serial.println("Security counters written to NVS.");
  }

  if (millis() - lastRebroadcast >= AUTO_REBROADCAST_INTERVAL_MS) {
    lastRebroadcast = millis();
    portENTER_CRITICAL(&seenMessagesMutex);
    std::vector<esp_now_message_t> messagesToRebroadcast;
    for (const auto& seenMsg : seenMessages) {
      if (seenMsg.messageData.ttl > 0) {
        messagesToRebroadcast.push_back(seenMsg.messageData);
      }
    }
    portEXIT_CRITICAL(&seenMessagesMutex);
    for (auto& msg : messagesToRebroadcast) {
      sendToAllPeers(msg);
    }
  }

  if (millis() - lastDiscoveryBroadcast >= PEER_DISCOVERY_INTERVAL_MS) {
      lastDiscoveryBroadcast = millis();
      createAndSendMessage(MAC_full_str.c_str(), MAC_full_str.length(), MSG_TYPE_DISCOVERY);
  }

  if (millis() - lastLocalDisplayLogManage >= LOCAL_DISPLAY_LOG_MANAGE_INTERVAL_MS) {
      lastLocalDisplayLogManage = millis();
      manageLocalDisplayLog();
  }

  if (millis() - lastSeenPeersManage >= LAST_SEEN_PEERS_MANAGE_INTERVAL_MS) {
      lastSeenPeersManage = millis();
      unsigned long currentTime = millis();
      portENTER_CRITICAL(&lastSeenPeersMutex);
      for (auto it = lastSeenPeers.begin(); it != lastSeenPeers.end(); ) {
          if ((currentTime - it->second) > PEER_LAST_SEEN_DURATION_MS) { it = lastSeenPeers.erase(it); }
          else { ++it; }
      }
      portEXIT_CRITICAL(&lastSeenPeersMutex);
      portENTER_CRITICAL(&espNowAddedPeersMutex);
      for (auto it = espNowAddedPeers.begin(); it != espNowAddedPeers.end(); ) {
          if (it->first == "FF:FF:FF:FF:FF:FF") { ++it; continue; }
          if ((currentTime - it->second) > ESP_NOW_PEER_TIMEOUT_MS) {
              uint8_t peerMacBytes[6]; unsigned int tempMac[6];
              sscanf(it->first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);
              for (int k = 0; k < 6; ++k) { peerMacBytes[k] = (uint8_t)tempMac[k]; }
              esp_now_del_peer(peerMacBytes);
              it = espNowAddedPeers.erase(it);
          } else {
              ++it;
          }
      }
      portEXIT_CRITICAL(&espNowAddedPeersMutex);
  }

  // --- AP Management: Dynamic SSID Broadcast ---
  if (millis() - lastApManagement >= AP_MANAGEMENT_INTERVAL_MS) {
    lastApManagement = millis();

    // Dynamically hide/show the SSID based on whether the AP is full.
    // This prevents user frustration from trying to connect to a full AP.
    wifi_config_t conf;
    esp_wifi_get_config((wifi_interface_t)WIFI_IF_AP, &conf);
    int num_stations = WiFi.softAPgetStationNum();

    if (num_stations >= MAX_AP_CONNECTIONS && conf.ap.ssid_hidden == 0) {
        // AP is full, hide SSID
        conf.ap.ssid_hidden = 1;
        esp_wifi_set_config((wifi_interface_t)WIFI_IF_AP, &conf);
        if(VERBOSE_MODE) Serial.printf("AP is full (%d clients). Hiding SSID.\n", num_stations);
    } else if (num_stations < MAX_AP_CONNECTIONS && conf.ap.ssid_hidden == 1) {
        // AP has free slots, show SSID
        conf.ap.ssid_hidden = 0;
        esp_wifi_set_config((wifi_interface_t)WIFI_IF_AP, &conf);
        if(VERBOSE_MODE) Serial.printf("AP has a free slot (%d/%d clients). Broadcasting SSID.\n", num_stations, MAX_AP_CONNECTIONS);
    }
  }

  WiFiClient client = server.available();
  if (client) {
    String currentLine = ""; String postBody = ""; bool isPost = false;
    unsigned long clientTimeout = millis(); int contentLength = 0;
    String requestedPath = "/"; String currentQueryParams = "";

    while (client.connected() && (millis() - clientTimeout < 2000)) {
      if (client.available()) {
        clientTimeout = millis(); char c = client.read();
        if (c == '\n') {
          if (currentLine.length() == 0) {
            String sessionTokenParam = "";
            int queryStart = requestedPath.indexOf('?');
            if (queryStart != -1) {
                currentQueryParams = requestedPath.substring(queryStart + 1);
                requestedPath = requestedPath.substring(0, queryStart);
            }

            if (isPost) {
                for (int i = 0; i < contentLength && client.available(); i++) postBody += (char)client.read();
                if(VERBOSE_MODE) Serial.println("Received POST Body: " + postBody);
                int tokenStart = postBody.indexOf("session_token=");
                if (tokenStart != -1) {
                    int tokenEnd = postBody.indexOf('&', tokenStart);
                    if (tokenEnd == -1) tokenEnd = postBody.length();
                    sessionTokenParam = postBody.substring(tokenStart + 14, tokenEnd);
                }
            } else {
                int tokenStart = currentQueryParams.indexOf("session_token=");
                if (tokenStart != -1) {
                    int tokenEnd = currentQueryParams.indexOf('&', tokenStart);
                    if (tokenEnd == -1) tokenEnd = currentQueryParams.length();
                    sessionTokenParam = currentQueryParams.substring(tokenStart + 14, tokenEnd);
                }
            }
            isOrganizerSessionActive = isOrganizerSessionValid(sessionTokenParam);
            if (isOrganizerSessionActive) sessionTokenTimestamp = millis();

            // --- START: Connectivity Check Response Patch ---
            if (!isPost) {
              bool isConnectivityCheck = false; String lowerPath = requestedPath; lowerPath.toLowerCase();
              if (lowerPath == "/generate_204" || lowerPath == "/hotspot-detect.html" || lowerPath == "/ncsi.txt" ||
                  lowerPath == "/connecttest.txt" || lowerPath == "/captive-portal" || lowerPath == "/success.txt" ||
                  lowerPath == "/library/test/success.html" || lowerPath.startsWith("/redirect") ||
                  lowerPath.indexOf("connectivitycheck.gstatic.com") != -1 || lowerPath.indexOf("msftconnecttest.com") != -1 ||
                  lowerPath.indexOf("apple.com") != -1 || lowerPath.indexOf("hotspot-detect.html") != -1 ) {
                isConnectivityCheck = true;
              }

              if (isConnectivityCheck) {
                if (lowerPath == "/generate_204") {
                  client.println(F("HTTP/1.1 204 No Content")); client.println(F("Connection: close"));
                  client.println(F("Cache-Control: no-cache, no-store, must-revalidate")); client.println(F("Pragma: no-cache"));
                  client.println(F("Expires: 0")); client.println(); client.stop(); return;
                } else if (lowerPath == "/hotspot-detect.html" || lowerPath == "/ncsi.txt" || lowerPath == "/connecttest.txt" || lowerPath == "/success.txt") {
                  client.println(F("HTTP/1.1 200 OK")); client.println(F("Content-Type: text/plain")); client.println(F("Connection: close"));
                  client.println(F("Cache-Control: no-cache, no-store, must-revalidate")); client.println(F("Pragma: no-cache"));
                  client.println(F("Expires: 0")); client.println(); client.println("Success"); client.stop(); return;
                } else {
                  client.println(F("HTTP/1.1 200 OK")); client.println(F("Content-Type: text/html")); client.println(F("Connection: close"));
                  client.println(F("Cache-Control: no-cache, no-store, must-revalidate")); client.println(F("Pragma: no-cache"));
                  client.println(F("Expires: 0")); client.println();
                  client.println(F("<html><head><title>Success</title></head><body>Success</body></html>")); client.stop(); return;
                }
              }
            }
            // --- END: Connectivity Check Response Patch ---
            if (requestedPath != "/" && currentQueryParams.indexOf("show_public") == -1 && currentQueryParams.indexOf("show_urgent") == -1 && currentQueryParams.indexOf("session_token") == -1) {
                if(VERBOSE_MODE) Serial.println("Intercepted non-root GET request for: " + requestedPath + ". Redirecting to captive portal.");
                client.println(F("HTTP/1.1 302 Found")); client.println(F("Location: http://192.168.4.1/"));
                client.println(F("Connection: close")); client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                client.println(F("Pragma: no-cache")); client.println(F("Expires: 0")); client.println(); client.stop(); return;
            }

            if (isPost) {
              String messageParam = "", passwordParam = "", urgentParam = "", actionParam = "", newPasswordParam = "", confirmNewPasswordParam = "";
              int messageStart = postBody.indexOf("message=");
              if (messageStart != -1) {
                int messageEnd = postBody.indexOf('&', messageStart);
                if (messageEnd == -1) messageEnd = postBody.length();
                messageParam = postBody.substring(messageStart + 8, messageEnd);
              }
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

              // Decode URL-encoded parameters
              messageParam.replace('+', ' '); String decodedMessage = "";
              for (int i = 0; i < messageParam.length(); i++) {
                if (messageParam.charAt(i) == '%' && (i + 2) < messageParam.length()) { decodedMessage += (char)strtol((messageParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedMessage += messageParam.charAt(i); }
              }
              passwordParam.replace('+', ' '); String decodedPassword = "";
              for (int i = 0; i < passwordParam.length(); i++) {
                if (passwordParam.charAt(i) == '%' && (i + 2) < passwordParam.length()) { decodedPassword += (char)strtol((messageParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedPassword += passwordParam.charAt(i); }
              }
              newPasswordParam.replace('+', ' '); String decodedNewPassword = "";
              for (int i = 0; i < newPasswordParam.length(); i++) {
                if (newPasswordParam.charAt(i) == '%' && (i + 2) < newPasswordParam.length()) { decodedNewPassword += (char)strtol((newPasswordParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedNewPassword += newPasswordParam.charAt(i); }
              }
              confirmNewPasswordParam.replace('+', ' '); String decodedConfirmNewPassword = "";
              for (int i = 0; i < confirmNewPasswordParam.length(); i++) {
                if (confirmNewPasswordParam.charAt(i) == '%' && (i + 2) < confirmNewPasswordParam.length()) { decodedConfirmNewPassword += (char)strtol((confirmNewPasswordParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedConfirmNewPassword += confirmNewPasswordParam.charAt(i); }
              }

              if (actionParam == "enterOrganizer") {
                  if (lockoutTime > 0 && millis() < lockoutTime) { webFeedbackMessage = "<p class='feedback' style='color:red;'>Too many failed attempts. Try again later.</p>"; }
                  else {
                      if (lockoutTime > 0 && millis() >= lockoutTime) { lockoutTime = 0; loginAttempts = 0; }
                      String receivedPasswordHash = simpleHash(decodedPassword);
                      if(VERBOSE_MODE) {
                          Serial.print("Current hashedOrganizerPassword (for login): '"); Serial.print(hashedOrganizerPassword); Serial.println("'");
                          Serial.print("Received Password Hash (after hashing plaintext): '"); Serial.print(receivedPasswordHash); Serial.println("'");
                      }
                      if (receivedPasswordHash.equalsIgnoreCase(hashedOrganizerPassword)) {
                          loginAttempts = 0;
                          organizerSessionToken = String(esp_random()) + String(esp_random());
                          sessionTokenTimestamp = millis();
                          isOrganizerSessionActive = true;
                          webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer Mode activated.</p>";
                          if (!passwordChangeLocked) { webFeedbackMessage += "<p class='feedback' style='color:orange;'>Note: Node's organizer password is still default. Set a new password to enable sending messages.</p>"; }
                          String redirectQuery = currentQueryParams;
                          if (redirectQuery.length() > 0) redirectQuery += "&";
                          redirectQuery += "session_token=" + organizerSessionToken;
                          client.println(F("HTTP/1.1 303 See Other")); client.println("Location: /?" + redirectQuery);
                          client.println(F("Connection: close")); client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                          client.println(F("Pragma: no-cache")); client.println(F("Expires: 0")); client.println(); client.stop(); return;
                      } else {
                          loginAttempts++;
                          if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                              lockoutTime = millis() + LOCKOUT_DURATION_MS; loginAttempts = 0;
                              webFeedbackMessage = "<p class='feedback' style='color:red;'>Login locked for 5 minutes due to too many failures.</p>";
                          } else { webFeedbackMessage = "<p class='feedback' style='color:red;'>Incorrect password. " + String(MAX_LOGIN_ATTEMPTS - loginAttempts) + " attempts remaining.</p>"; }
                      }
                  }
              } else if (actionParam == "exitOrganizer") {
                  webFeedbackMessage = "";
                  if (isOrganizerSessionActive) {
                      organizerSessionToken = ""; isOrganizerSessionActive = false;
                      webFeedbackMessage = "<p class='feedback' style='color:blue;'>Exited Organizer Mode.</p>";
                  } else { webFeedbackMessage = "<p class='feedback' style='color:orange;'>Not currently in Organizer Mode.</p>"; }
              } else if (actionParam == "togglePublic") {
                  if (isOrganizerSessionActive && passwordChangeLocked) {
                      sessionTokenTimestamp = millis();
                      if (publicMessagingLocked) { webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Public messaging is locked OFF. Cannot re-enable.</p>"; }
                      else {
                          publicMessagingEnabled = !publicMessagingEnabled;
                          webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging has been " + String(publicMessagingEnabled ? "ENABLED" : "DISABLED") + ".</p>";
                          createAndSendMessage(publicMessagingEnabled ? CMD_PUBLIC_ON : CMD_PUBLIC_OFF, strlen(publicMessagingEnabled ? CMD_PUBLIC_ON : CMD_PUBLIC_OFF), MSG_TYPE_COMMAND);
                      }
                  } else { webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Not logged in as organizer or node's password not set.</p>"; }
              } else if (actionParam == "sendMessage") {
                  if (isOrganizerSessionActive && passwordChangeLocked) {
                      sessionTokenTimestamp = millis();
                      if (decodedMessage.length() == 0) { webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>"; }
                      else {
                          uint8_t messageType = MSG_TYPE_ORGANIZER;
                          if (urgentParam == "on") decodedMessage = "Urgent: " + decodedMessage;
                          if (decodedMessage.length() >= MAX_PAYLOAD_LEN) decodedMessage = decodedMessage.substring(0, MAX_PAYLOAD_LEN - 1);
                          createAndSendMessage(decodedMessage.c_str(), decodedMessage.length(), messageType);
                          if (webFeedbackMessage.length() == 0) webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer message queued!</p>";
                      }
                  } else { webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Not logged in as organizer or node's password not set.</p>"; }
              } else if (actionParam == "sendPublicMessage") {
                  if (publicMessagingEnabled && passwordChangeLocked) {
                      if (decodedMessage.length() == 0) { webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>"; }
                      else {
                          if (decodedMessage.length() >= MAX_PAYLOAD_LEN) decodedMessage = decodedMessage.substring(0, MAX_PAYLOAD_LEN - 1);
                          createAndSendMessage(decodedMessage.c_str(), decodedMessage.length(), MSG_TYPE_PUBLIC);
                          if (webFeedbackMessage.length() == 0) webFeedbackMessage = "<p class='feedback' style='color:green;'>Public message queued!</p>";
                      }
                  } else if (isOrganizerSessionActive) {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Public messaging is disabled or node's password not set.</p>";
                  }
              } else if (actionParam == "rebroadcastCache") {
                  if (isOrganizerSessionActive && passwordChangeLocked) {
                      sessionTokenTimestamp = millis(); int rebroadcastedCount = 0;
                      portENTER_CRITICAL(&seenMessagesMutex);
                      for (const auto& seenMsg : seenMessages) {
                          if (seenMsg.messageData.ttl > 0) {
                            esp_now_message_t msgCopy = seenMsg.messageData;
                            sendToAllPeers(msgCopy);
                            rebroadcastedCount++;
                          }
                      }
                      portEXIT_CRITICAL(&seenMessagesMutex);
                      webFeedbackMessage = "<p class='feedback' style='color:green;'>Re-broadcasted " + String(rebroadcastedCount) + " messages!</p>";
                  } else { webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Not logged in as organizer or node's password not set.</p>"; }
              } else if (actionParam == "setOrganizerPassword") {
                  // --- START MODIFIED PASSWORD LOGIC ---
                  if (passwordChangeLocked) {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>The organizer password for this node cannot be changed after it has been set. To reset the password, you must reboot the board.</p>";
                  } else { // This block only runs if the password has NOT been set yet.
                      if(VERBOSE_MODE) Serial.println("Attempting to set new password for the first time.");
                      if (decodedNewPassword.length() == 0) {
                          webFeedbackMessage = "<p class='feedback' style='color:orange;'>New password cannot be empty.</p>";
                      } else if (decodedNewPassword != decodedConfirmNewPassword) {
                          webFeedbackMessage = "<p class='feedback' style='color:red;'>New passwords do not match. Please try again.</p>";
                      } else {
                          // The action depends on the mode detected at boot.
                          if (isUsingDefaultPsk) {
                              // Compatibility Mode: Derive a new key and broadcast it.
                              if(VERBOSE_MODE) Serial.println("Setting password in Compatibility Mode. Deriving and broadcasting new session key.");
                              deriveAndSetSessionKey(decodedNewPassword);
                              createAndSendMessage(decodedNewPassword.c_str(), decodedNewPassword.length(), MSG_TYPE_PASSWORD_UPDATE);
                          } else {
    // Secure Flash Mode: Only update the web UI login password. Do NOT change the mesh key.
    if(VERBOSE_MODE) Serial.println("Setting password in Secure Mode. Updating web UI login hash only.");
    hashedOrganizerPassword = simpleHash(decodedNewPassword);
    passwordChangeLocked = true; // Lock from further changes.

    // Broadcast the new organizer password so other secure nodes update their web-login too.
    // MSG_TYPE_PASSWORD_UPDATE messages are encrypted with the flashed PSK (PRE_SHARED_KEY+4),
    // so plaintext here is transported safely to other nodes sharing the same flashed key.
    createAndSendMessage(decodedNewPassword.c_str(), decodedNewPassword.length(), MSG_TYPE_PASSWORD_UPDATE);

                          }
                          webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer password updated successfully!</p>";
                          loginAttempts = 0;
                          lockoutTime = 0;
                      }
                  }
                  // --- END MODIFIED PASSWORD LOGIC ---
              }
              client.println(F("HTTP/1.1 303 See Other"));
              String redirectQuery = currentQueryParams;
              if (isOrganizerSessionActive && sessionTokenParam.length() > 0) {
                  if (redirectQuery.length() > 0) redirectQuery += "&";
                  redirectQuery += "session_token=" + sessionTokenParam;
              }
              client.println("Location: /?" + redirectQuery);
              client.println(F("Connection: close")); client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
              client.println(F("Pragma: no-cache")); client.println(F("Expires: 0")); client.println(); client.stop(); return;
            }

            String detectedNodesHtmlContent = "<div class='recent-senders-display-wrapper'><span class='detected-nodes-label'>Senders:</span><div class='detected-nodes-mac-list'>";
            int count = 0;
            portENTER_CRITICAL(&lastSeenPeersMutex);
            std::vector<std::pair<String, unsigned long>> sortedSeenPeers;
            for (auto const& [macStr, timestamp] : lastSeenPeers) { sortedSeenPeers.push_back({macStr, timestamp}); }
            std::sort(sortedSeenPeers.begin(), sortedSeenPeers.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
            const int MAX_NODES_TO_DISPLAY_WEB = 4;
            for (const auto& macPair : sortedSeenPeers) {
                if (count >= MAX_NODES_TO_DISPLAY_WEB) break;
                
                // --- START FIX ---
                // Directly parse into uint8_t array using %hhX specifier
                uint8_t macBytes[6];
                sscanf(macPair.first.c_str(), "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
                       &macBytes[0], &macBytes[1], &macBytes[2], &macBytes[3], &macBytes[4], &macBytes[5]);
                // --- END FIX ---

                detectedNodesHtmlContent += "<span class='detected-node-item-compact'>" + formatMaskedMac(macBytes) + "</span>";
                count++;
            }
            portEXIT_CRITICAL(&lastSeenPeersMutex);
            if (count == 0) { detectedNodesHtmlContent += "<span class='detected-node-item-compact'>None</span>"; }
            detectedNodesHtmlContent += "</div></div>";

            client.println(F("HTTP/1.1 200 OK"));
            client.println(F("Content-type:text/html"));
            client.println(F("Connection: close"));
            client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
            client.println(F("Pragma: no-cache"));
            client.println(F("Expires: 0"));
            client.println();
            client.println(F("<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Protest Info Node</title>"));
            client.println(F("<meta http-equiv=\"refresh\" content=\"120\">")); // Auto-refresh page every 120 seconds
            client.println(F("<style>"));
            client.println(F("body{font-family:Helvetica,Arial,sans-serif;margin:0;padding:0;background-color:#f8f8f8;color:#333;display:flex;flex-direction:column;min-height:100vh;}"));
            client.println(F("header{background-color:#f0f0f0;padding:10px 15px;border-bottom:1px solid #ddd;text-align:center; display: flex; flex-direction: column; align-items: center; justify-content: center; width:100%;}"));
            client.println(F("h1,h2,h3{margin:0;padding:5px 0;color:#333;text-align:center;} h1{font-size:1.4em;} h2{font-size:1.2em;} h3{font-size:1.1em;margin-bottom:10px;}"));
            client.println(F("p{margin:3px 0;font-size:0.9em;text-align:center;} .info-line{font-size:0.8em;color:#666;margin-bottom:10px;}"));
            client.println(F(".content-wrapper{display:flex;flex-direction:column;align-items:center;width:100%;max-width:900px;margin:15px auto;padding:0 10px;flex-grow:1;}"));
            client.println(F(".chat-main-content{flex:1;width:100%;max-width:700px;margin:0 auto;background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);border:1px solid #ddd;}"));
            client.println(F("pre{background:#eee;padding:10px;border-radius:5px;text-align:left;max-width:100%;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;font-size:0.85em;border:1px solid #ccc;min-height:200px;}"));
            client.println(F("details, .form-container{background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);max-width:450px;margin:15px auto;border:1px solid #ddd;}"));
            client.println(F("summary{font-size:1.1em;font-weight:bold;cursor:pointer;padding:5px 0;text-align:center; outline: none; border: none;}"));
            client.println(F("form{display:flex;flex-direction:column;align-items:center;margin-top:10px;}"));
            client.println(F("label{font-size:0.9em;margin-bottom:5px;align-self:flex-start;width:80%;}"));
            client.println(F("input[type=text],input[type=password]{width:80%;max-width:350px;padding:8px;margin-bottom:10px;border-radius:4px;border:1px solid #ccc;font-size:0.9em;}"));
            client.println(F("input[type=submit]{background-color:#007bff;color:white!important;padding:8px 15px;border:none;border-radius:4px;cursor:pointer;font-size:1em;transition:background-color 0.3s ease;text-decoration:none;display:block; margin: 0 auto;}"));
            client.println(F(".button-link{background-color:#007bff;color:white!important;border:none;border-radius:4px;cursor:pointer;font-size:1em;transition:background-color 0.3s ease;text-decoration:none;display:inline-block; width:85px; padding: 8px 5px; line-height:1.3; text-align:center;}"));
            client.println(F(".button-link.secondary{background-color:#6c757d;} .button-link.secondary:hover{background-color:#5a6268;}"));
            client.println(F(".button-link.disabled{background-color:#cccccc; cursor: not-allowed;}"));
            client.println(F(".recent-senders-display-wrapper{display:flex;flex-direction:column;align-items:center;width:100%;max-width:450px;background:#e6f7ff;border:1px solid #cceeff;border-radius:12px;padding:10px 15px;font-size:0.75em;color:#0056b3;margin:15px auto; box-sizing: border-box;}"));
            client.println(F(".detected-nodes-label{font-weight:bold;margin-bottom:5px;color:#003366;}"));
            client.println(F(".detected-nodes-mac-list{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;width:100%;}"));
            client.println(F("</style></head><body><script>"));
            client.println(F("document.addEventListener('DOMContentLoaded', () => { const preElement = document.querySelector('pre'); if (preElement) { preElement.scrollTop = 0; } });"));
            client.println(F("</script>"));
            client.println(F("<body><header><h1>Protest Information Node</h1>"));
            client.printf("<p class='info-line'><strong>IP:</strong> %s | <strong>MAC:</strong> %s</p>", IP.toString().c_str(), MAC_suffix_str.c_str());
            client.println(F("<p style='font-weight:bold; color:#007bff; margin-top:10px;'>All protest activities are non-violent. Please remain calm, even if others are not.</p>"));
            if (publicMessagingEnabled) { client.println(F("<p class='feedback' style='color:orange;'>Warning: Public messages are unmoderated.</p>")); }
            client.println(F("</header>"));

            if (lastJammingEventTimestamp > 0) { client.println(F("<div style='background-color:#ffdddd; border:1px solid #f5c6cb; color:#721c24; padding:10px; text-align:center; font-weight:bold;'>WARNING: JAMMING EVENT DETECTED</div>")); }
            if (isInfiltrationAlert) { client.println(F("<div style='background-color:#fff3cd; border:1px solid #ffeeba; color:#856404; padding:10px; text-align:center; font-weight:bold;'>WARNING: INFILTRATION ATTEMPT DETECTED</div>")); }
            client.println(F("<div class='content-wrapper'><div class='chat-main-content'>"));
            if (webFeedbackMessage.length() > 0) { client.println(webFeedbackMessage); webFeedbackMessage = ""; }

            bool showPublicView = (currentQueryParams.indexOf("show_public=true") != -1);
            bool showUrgentView = (currentQueryParams.indexOf("show_urgent=true") != -1);
            bool hideSystemView = (isOrganizerSessionActive && currentQueryParams.indexOf("hide_system=true") != -1);
            String displayedBuffer;
            portENTER_CRITICAL(&localDisplayLogMutex);
            for (const auto& entry : localDisplayLog) {
                const auto& msg = entry.message;
                bool isSystemMessage = (msg.messageType == MSG_TYPE_COMMAND || msg.messageType == MSG_TYPE_AUTO_INIT);

                // Filter 1: Hide system messages completely if not an organizer
                if (!isOrganizerSessionActive && isSystemMessage) {
                    continue;
                }
                
                String formattedLine = "Node " + getMacSuffix(msg.originalSenderMac) + " - ";
                if (msg.messageType == MSG_TYPE_ORGANIZER) formattedLine += "Organizer: ";
                else if (msg.messageType == MSG_TYPE_PUBLIC) formattedLine += "Public: ";
                else if (msg.messageType == MSG_TYPE_COMMAND) formattedLine += "Command: ";
                else if (msg.messageType == MSG_TYPE_AUTO_INIT) formattedLine += "Auto: ";
                formattedLine += String(msg.content);

                if (msg.messageType == MSG_TYPE_PASSWORD_UPDATE) { continue; }
                
                bool passesPublicFilter = !(formattedLine.indexOf("Public: ") != -1 && !showPublicView);
                bool passesUrgentFilter = !(formattedLine.indexOf("Urgent: ") == -1 && showUrgentView);
                // Filter 2: Apply the organizer's toggle for system messages
                bool passesSystemFilter = !(isSystemMessage && hideSystemView);

                if (passesPublicFilter && passesUrgentFilter && passesSystemFilter) { 
                    displayedBuffer += escapeHtml(formattedLine) + "\n"; 
                }
            }
            portEXIT_CRITICAL(&localDisplayLogMutex);

            client.println(F("<h2>Serial Data Log:</h2><h3 style='font-size:0.9em; margin-top:0; color:#555;'>Most recent messages at the top.</h3><pre>"));
            client.print(displayedBuffer);
            client.println(F("</pre>"));

            client.println(F("<div style='text-align:center; margin: 15px; display:flex; justify-content:center; gap: 10px; flex-wrap: wrap;'>"));
            String publicLink = "/?" + buildQueryString(sessionTokenParam, !showPublicView, showPublicView ? showUrgentView : false, hideSystemView);
            client.print("<a href='" + publicLink + "' class='button-link" + (showPublicView ? " secondary" : "") + "'>");
            client.print(showPublicView ? "Hide<br>Public" : "Show<br>Public"); client.println("</a>");
            String urgentLink = "/?" + buildQueryString(sessionTokenParam, showUrgentView ? showPublicView : false, !showUrgentView, hideSystemView);
            client.print("<a href='" + urgentLink + "' class='button-link" + (showUrgentView ? " secondary" : "") + "'>");
            client.print(showUrgentView ? "Show<br>All" : "Only<br>Urgent"); client.println("</a>");
            if (isOrganizerSessionActive) {
                String systemLink = "/?" + buildQueryString(sessionTokenParam, showPublicView, showUrgentView, !hideSystemView);
                client.print("<a href='" + systemLink + "' class='button-link" + (hideSystemView ? " secondary" : "") + "'>");
                client.print(hideSystemView ? "Show<br>System" : "Hide<br>System"); client.println("</a>");
            }
            client.println(F("</div>"));

            if(isOrganizerSessionActive) {
                client.println(F("<details open><summary>Organizer Controls</summary>"));
                client.println(F("<div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                if (passwordChangeLocked) {
                    client.println(F("<h3>Send Organizer Message:</h3><form action='/' method='POST'><input type='hidden' name='action' value='sendMessage'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    if (hideSystemView) client.println(F("<input type='hidden' name='hide_system' value='true'>"));
                    client.printf(F("<label for='msg_input'>Message:</label><input type='text' id='msg_input' name='message' required maxlength='%d'>"), MAX_WEB_MESSAGE_INPUT_LENGTH);
                    client.println(F("<div style='display:flex;align-items:center;justify-content:center;width:80%;margin-bottom:10px;'><input type='checkbox' id='urgent_input' name='urgent' value='on' style='margin-right:8px;'><label for='urgent_input' style='margin-bottom:0;'>Urgent Message</label></div>"));
                    client.println(F("<input type='submit' value='Send Message'></form></div>"));
                    client.println(F("<div class='form-container' style='box-shadow:none;border:none;padding-top:5px;margin-top:5px;'><h3>Admin Actions</h3>"));
                    client.println(F("<form action='/' method='POST' style='flex-direction:row;justify-content:center;gap:10px;'>"));
                    client.println(F("<input type='hidden' name='action' value='rebroadcastCache'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    if (hideSystemView) client.println(F("<input type='hidden' name='hide_system' value='true'>"));
                    client.println(F("<input type='submit' value='Re-broadcast Cache'></form>"));
                    client.println(F("<form action='/' method='POST' style='flex-direction:row;justify-content:center;gap:10px;margin-top:10px;'>"));
                    client.println(F("<input type='hidden' name='action' value='togglePublic'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    if (hideSystemView) client.println(F("<input type='hidden' name='hide_system' value='true'>"));
                    if (publicMessagingLocked) { client.print(F("<input type='submit' value='Public Msgs Locked (Off)' disabled class='button-link disabled'>")); }
                    else { client.print(F("<input type='submit' value='")); client.print(publicMessagingEnabled ? "Disable Public Msgs" : "Enable Public Msgs"); client.println(F("'></form>")); }
                    client.println(F("</div>"));
                } else { client.println(F("<p class='feedback' style='color:orange;'>You are logged in, but this node is not yet configured to send messages. Please set an organizer password to enable sending messages. Alternatively, if the password has already been set on another node in the mesh, this node will eventually receive it and enable sending.</p>")); }
                
                client.println(F("<details style='margin-top:10px;'><summary style='font-size:1.1em;font-weight:bold;cursor:pointer;padding:5px 0;text-align:center;'>Security & Password</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px; text-align: left;'>"));
                
                // --- ADDED FORENSIC DATA DISPLAY ---
                client.printf("<h3 style='text-align:left;'>Jamming Incidents (since first boot): %u</h3>", jammingIncidentCount);
                if (jammingIncidentCount > 0) {
                    char timeAgo[20];
                    unsigned long secondsAgo = (millis() - lastJammingTimestampPersisted) / 1000;
                    if (secondsAgo < 60) snprintf(timeAgo, sizeof(timeAgo), "%lus ago", secondsAgo);
                    else if (secondsAgo < 3600) snprintf(timeAgo, sizeof(timeAgo), "%lum ago", secondsAgo / 60);
                    else snprintf(timeAgo, sizeof(timeAgo), "%luh ago", secondsAgo / 3600);
                    client.printf("<p style='font-size:0.8em; margin-left: 15px;'>Last Event: %s (%lu ms duration)</p>", 
                                  lastJammingTimestampPersisted == 0 ? "N/A" : timeAgo, lastJammingDurationPersisted);
                }

                client.printf("<h3 style='text-align:left;'>Checksum/HMAC Failures (since first boot): %u</h3>", hashFailureCount);
                if (hashFailureCount > 0) {
                    client.println(F("<h4>Recent Failure Log:</h4><ul style='font-size:0.8em; padding-left: 20px;'>"));
                    for (int i = 0; i < MAX_FAIL_LOG_ENTRIES; i++) {
                        String key = "failMsg" + String(i); String logEntry = preferences.getString(key.c_str(), "");
                        if (logEntry.length() > 0) { client.print(F("<li>")); client.print(escapeHtml(logEntry)); client.println(F("</li>")); }
                    }
                    client.println(F("</ul>"));
                }

                client.printf("<h3 style='text-align:left;'>Infiltration Attempts (since first boot): %u</h3>", infiltrationIncidentCount);
                if (infiltrationIncidentCount > 0) {
                    char timeAgo[20];
                    unsigned long secondsAgo = (millis() - lastInfiltrationTimestampPersisted) / 1000;
                    if (secondsAgo < 60) snprintf(timeAgo, sizeof(timeAgo), "%lus ago", secondsAgo);
                    else if (secondsAgo < 3600) snprintf(timeAgo, sizeof(timeAgo), "%lum ago", secondsAgo / 60);
                    else snprintf(timeAgo, sizeof(timeAgo), "%luh ago", secondsAgo / 3600);
                     client.printf("<p style='font-size:0.8em; margin-left: 15px;'>Last Event: %s</p>", 
                                  lastInfiltrationTimestampPersisted == 0 ? "N/A" : timeAgo);
                }
                if (infiltrationIncidentCount > 0) {
                    client.println(F("<h4>Recent Infiltration Attempt Log (Sender MACs):</h4><ul style='font-size:0.8em; padding-left: 20px;'>"));
                    for (int i = 0; i < MAX_INFIL_LOG_ENTRIES; i++) {
                        String key = "infilMsg" + String(i); String logEntry = preferences.getString(key.c_str(), "");
                        if (logEntry.length() > 0) { client.print(F("<li>")); client.print(escapeHtml(logEntry)); client.println(F("</li>")); }
                    }
                    client.println(F("</ul>"));
                }
                // --- END FORENSIC DATA DISPLAY ---

                client.println(F("<hr style='margin: 15px 0;'><h3>Set/Reset Organizer Password:</h3>"));
                if (passwordChangeLocked) {
                    client.println(F("<p class='feedback' style='color:red; font-size:0.8em; margin-top:10px;'>The organizer password for this node cannot be changed after it has been set. To reset the password, you must reboot the board.</p>"));
                } else {
                    client.println(F("<form action='/' method='POST'><input type='hidden' name='action' value='setOrganizerPassword'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='new_pass_input'>New Password:</label><input type='password' id='new_pass_input' name='new_password' required>"));
                    client.println(F("<label for='confirm_new_pass_input'>Confirm New Password:</label><input type='password' id='confirm_new_pass_input' name='confirm_new_password' required>"));
                    client.println(F("<input type='submit' value='Set New Password' class='button-link'></form>"));
                    if (isUsingDefaultPsk) {
                        client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>Setting a new password will distribute it to the mesh, replacing any existing password.</p>"));
                    } else {
                        client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>This node was flashed with a secure key. Setting a password here will ONLY change the web login password and will NOT affect mesh encryption.</p>"));
                    }
                }
                client.println(F("</div></details>"));

                client.println(F("<form action='/' method='POST' style='margin-top:10px;'><input type='hidden' name='action' value='exitOrganizer'>"));
                client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                if (hideSystemView) client.println(F("<input type='hidden' name='hide_system' value='true'>"));
                client.println(F("<input type='submit' value='Exit Organizer Mode' class='button-link secondary' style='background-color:#dc3545; width: auto;'></form>"));
                client.println(F("</div></details>"));
            } else {
                if (!passwordChangeLocked) {
                    // If password isn't set yet, show the form to set it directly. NO LOGIN REQUIRED.
                    client.println(F("<details open><summary>Set Initial Organizer Password</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<h3>Set Your Organizer Password:</h3><form action='/' method='POST'><input type='hidden' name='action' value='setOrganizerPassword'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='new_pass_input'>New Password:</label><input type='password' id='new_pass_input' name='new_password' required>"));
                    client.println(F("<label for='confirm_new_pass_input'>Confirm New Password:</label><input type='password' id='confirm_new_pass_input' name='confirm_new_password' required>"));
                    client.println(F("<input type='submit' value='Set Password' class='button-link' style='background-color:#007bff; width: auto;'></form>"));
                    if (isUsingDefaultPsk) {
                        client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>Set the mesh-wide password. After setting, you must log in with this password to access organizer functions.</p>"));
                    } else {
                        client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>This node was flashed with a secure key. Set the web login password here. This will NOT affect mesh encryption.</p>"));
                    }
                    client.println(F("</div></details>"));
                } else {
                    // If password IS set, then show the standard login form.
                    client.println(F("<details><summary>Enter Organizer Mode</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<form action='/' method='POST'><input type='hidden' name='action' value='enterOrganizer'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='pass_input'>Password:</label><input type='password' id='pass_input' name='password_plaintext_client' required>"));
                    client.println(F("<input type='submit' value='Enter Mode' style='width: auto;'></form></div></details>"));
                }
                if(publicMessagingEnabled && passwordChangeLocked) {
                    client.println(F("<details><summary>Send a Public Message</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<h3>Message (no password required):</h3><form action='/' method='POST'><input type='hidden' name='action' value='sendPublicMessage'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.printf(F("<label for='pub_msg_input'>Message:</label><input type='text' id='pub_msg_input' name='message' required maxlength='%d'>"), MAX_WEB_MESSAGE_INPUT_LENGTH);
                    client.println(F("<input type='submit' value='Send Public Message' style='width: auto;'></form></div></details>"));
                } else if (publicMessagingEnabled && !passwordChangeLocked) { client.println(F("<p class='feedback' style='color:orange;'>Public messaging is enabled, but this node is not yet configured to send messages. Please set an organizer password to enable sending messages. Alternatively, if the password has already been set on another node in the mesh, this node will eventually receive it and enable sending.</p>")); }
            }
            client.print(detectedNodesHtmlContent);
            client.println(F("</div></div></body></html>"));
            break;
          } else {
            if (currentLine.startsWith("GET")) {
              isPost = false; int pathStart = currentLine.indexOf(' ') + 1; int pathEnd = currentLine.indexOf(' ', pathStart);
              if (pathStart != -1 && pathEnd != -1 && pathEnd > pathStart) { requestedPath = currentLine.substring(pathStart, pathEnd); }
            } else if (currentLine.startsWith("POST")) { isPost = true; }
            if (currentLine.startsWith("Content-Length: ")) {
              contentLength = currentLine.substring(16).toInt();
              if (contentLength > MAX_POST_BODY_LENGTH) { Serial.printf("Error: Excessive Content-Length (%d). Closing connection to prevent DoS.\n", contentLength); client.stop(); return; }
            }
            currentLine = "";
          }
        } else if (c != '\r') { currentLine += c; }
      }
    }
    client.stop();
  }

#if USE_DISPLAY
  if (millis() - lastDisplayRefresh >= DISPLAY_REFRESH_INTERVAL_MS) {
    lastDisplayRefresh = millis();
    if (currentDisplayMode == MODE_CHAT_LOG) { displayChatLogMode(TFT_CHAT_LOG_LINES); }
    else if (currentDisplayMode == MODE_URGENT_ONLY) { displayUrgentOnlyMode(TFT_URGENT_ONLY_LINES); }
    else if (currentDisplayMode == MODE_DEVICE_INFO) { displayDeviceInfoMode(); }
    else if (currentDisplayMode == MODE_STATS_INFO) { displayStatsInfoMode(); }
  }
  if (digitalRead(TFT_TOUCH_IRQ_PIN) == LOW && (millis() - lastTouchTime > TOUCH_DEBOUNCE_MS)) {
    lastTouchTime = millis(); if(VERBOSE_MODE) Serial.println("Touch detected! Switching display mode.");
    if (currentDisplayMode == MODE_CHAT_LOG) { currentDisplayMode = MODE_URGENT_ONLY; displayUrgentOnlyMode(TFT_URGENT_ONLY_LINES); }
    else if (currentDisplayMode == MODE_URGENT_ONLY) { currentDisplayMode = MODE_DEVICE_INFO; displayDeviceInfoMode(); }
    else if (currentDisplayMode == MODE_DEVICE_INFO) { currentDisplayMode = MODE_STATS_INFO; displayStatsInfoMode(); }
    else { currentDisplayMode = MODE_CHAT_LOG; displayChatLogMode(TFT_CHAT_LOG_LINES); }
    lastDisplayRefresh = 0;
  }
#endif
}

#if USE_DISPLAY
void displayChatLogMode(int numLines) {
  tft.fillScreen(TFT_BLACK); tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN); tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN); tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN); tft.println("Mode: All Messages");
  tft.setTextColor(TFT_WHITE); tft.println("----------------------");
  portENTER_CRITICAL(&localDisplayLogMutex);
  int linesPrinted = 0;
  for (const auto& entry : localDisplayLog) {
    if (linesPrinted >= numLines) break;
    const auto& msg = entry.message; char formattedLine[256]; const char* messageTypePrefix = "";
    if (msg.messageType == MSG_TYPE_ORGANIZER) messageTypePrefix = "Organizer: ";
    else if (msg.messageType == MSG_TYPE_PUBLIC) messageTypePrefix = "Public: ";
    else if (msg.messageType == MSG_TYPE_COMMAND) messageTypePrefix = "Command: ";
    else if (msg.messageType == MSG_TYPE_AUTO_INIT) messageTypePrefix = "Auto: ";
    if (msg.messageType == MSG_TYPE_PASSWORD_UPDATE) { continue; }
    snprintf(formattedLine, sizeof(formattedLine), "Node %s - %s%s", getMacSuffix(msg.originalSenderMac).c_str(), messageTypePrefix, msg.content);
    tft.println(formattedLine);
    linesPrinted++;
  }
  portEXIT_CRITICAL(&localDisplayLogMutex);
}

void displayUrgentOnlyMode(int numLines) {
  tft.fillScreen(TFT_BLACK); tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN); tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN); tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN); tft.println("Mode: Urgent Only");
  tft.setTextColor(TFT_WHITE); tft.println("----------------------");
  portENTER_CRITICAL(&localDisplayLogMutex);
  int linesPrinted = 0;
  for (const auto& entry : localDisplayLog) {
    if (linesPrinted >= numLines) break;
    const auto& msg = entry.message;
    if (String(msg.content).indexOf("Urgent: ") != -1) {
        char formattedLine[256]; const char* messageTypePrefix = "";
        if (msg.messageType == MSG_TYPE_ORGANIZER) messageTypePrefix = "Organizer: ";
        snprintf(formattedLine, sizeof(formattedLine), "Node %s - %s%s", getMacSuffix(msg.originalSenderMac).c_str(), messageTypePrefix, msg.content);
        tft.println(formattedLine);
        linesPrinted++;
    }
  }
  portEXIT_CRITICAL(&localDisplayLogMutex);
}

void displayDeviceInfoMode() {
  tft.fillScreen(TFT_BLACK); tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN); tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN); tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN); tft.println("Mode: Device Info");
  tft.setTextColor(TFT_WHITE); tft.println("----------------------");
  tft.println("Nearby Nodes (Last Seen):");
  portENTER_CRITICAL(&lastSeenPeersMutex);
  std::vector<std::pair<String, unsigned long>> sortedSeenPeers;
  for (auto const& [macStr, timestamp] : lastSeenPeers) { sortedSeenPeers.push_back({macStr, timestamp}); }
  std::sort(sortedSeenPeers.begin(), sortedSeenPeers.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
  int linesPrinted = 0;
  if (sortedSeenPeers.empty()) { tft.println("  No other nodes detected yet."); }
  else {
    for (const auto& macPair : sortedSeenPeers) {
        if (linesPrinted >= MAX_NODES_TO_DISPLAY_TFT) break;
        
        // --- START FIX ---
        // Directly parse into uint8_t array using %hhX specifier
        uint8_t macBytes[6];
        sscanf(macPair.first.c_str(), "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
               &macBytes[0], &macBytes[1], &macBytes[2], &macBytes[3], &macBytes[4], &macBytes[5]);
        // --- END FIX ---

        tft.printf("  %s (seen %lu s ago)\n", formatMaskedMac(macBytes).c_str(), (millis() - macPair.second) / 1000);
        linesPrinted++;
    }
  }
  portEXIT_CRITICAL(&lastSeenPeersMutex);
}

void displayStatsInfoMode() {
  tft.fillScreen(TFT_BLACK); tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN); tft.print("MAC: "); tft.println(MAC_full_str);
  tft.setTextColor(TFT_GREEN); tft.print("IP: "); tft.println(IP.toString());
  tft.setTextColor(TFT_GREEN); tft.println("Mode: Stats Info");
  tft.setTextColor(TFT_WHITE); tft.println("----------------------");
  unsigned long uptimeMillis = millis(), seconds = uptimeMillis / 1000, minutes = seconds / 60, hours = minutes / 60, days = hours / 24;
  seconds %= 60; minutes %= 60; hours %= 24;
  tft.println("Uptime:");
  tft.printf("  Days: %lu, H: %lu, M: %lu, S: %lu\n", days, hours, minutes, seconds);
  tft.println("Message Stats:");
  tft.printf("  Total Sent: %lu\n", totalMessagesSent);
  tft.printf("  Total Received: %lu\n", totalMessagesReceived);
  tft.printf("  Urgent Messages: %lu\n", totalUrgentMessages);
  tft.printf("  Cache Size: %u/%u\n", seenMessages.size(), MAX_CACHE_SIZE);
  tft.println("Mode Status:");
  tft.printf("  Security Mode: %s\n", isUsingDefaultPsk ? "Compatibility" : "Secure");
  tft.print("  Active Key:    ");
  if (useSessionKey) {
      // This is true in Secure mode, or in Compat mode after a password is set.
      tft.printf("Session ...%02X%02X\n", sessionKey[14], sessionKey[15]);
  } else {
      // This is only true in Compat mode before a password is set (using the default factory key).
      // The key bytes start at index 4 of PRE_SHARED_KEY. Last two bytes are at index 18 and 19.
      tft.printf("Default ...%02X%02X\n", PRE_SHARED_KEY[18], PRE_SHARED_KEY[19]);
  }
  tft.printf("  Public Msgs:   %s\n", publicMessagingEnabled ? "ENABLED" : "DISABLED");
  tft.printf("  Public Lock:   %s\n", publicMessagingLocked ? "LOCKED" : "UNLOCKED");
  tft.printf("  Node Capable:  %s\n", passwordChangeLocked ? "YES" : "NO");
  portENTER_CRITICAL(&apClientsMutex);
  int uniqueClients = apConnectedClients.size();
  portEXIT_CRITICAL(&apClientsMutex);
  tft.println("AP Stats:");
  tft.printf("  Unique Clients: %d\n", uniqueClients);
  
  tft.println("Network Security:");
  tft.printf("  HMAC Failures: %u\n", hashFailureCount);
  tft.printf("  Current Jamming: %s\n", isCurrentlyJammed ? "YES" : "NO");
  tft.printf("  Jamming Incidents: %u\n", jammingIncidentCount);
  if(jammingIncidentCount > 0 && lastJammingTimestampPersisted > 0) {
      tft.printf("    Last: %lu s ago\n", (millis() - lastJammingTimestampPersisted) / 1000);
      tft.printf("    Dur: %lu ms\n", lastJammingDurationPersisted);
  }
  tft.printf("  Infiltration Alert: %s\n", isInfiltrationAlert ? "YES" : "NO");
  tft.printf("  Infiltration Attempts: %u\n", infiltrationIncidentCount);
  if(infiltrationIncidentCount > 0 && lastInfiltrationTimestampPersisted > 0) {
      tft.printf("    Last: %lu s ago\n", (millis() - lastInfiltrationTimestampPersisted) / 1000);
  }
}
#endif
