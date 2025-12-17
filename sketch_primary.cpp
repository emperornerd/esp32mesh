 #include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h> 
#include <esp_wifi_types.h> 
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
#include "mbedtls/md.h" 


#define USE_DISPLAY true

#if USE_DISPLAY
#include <TFT_eSPI.h>
TFT_eSPI tft = TFT_eSPI();
bool displayActive = false;

#define TFT_TOUCH_IRQ_PIN 36
#endif


#define VERBOSE_MODE false


const int WIFI_CHANNEL = 1;
const int WEB_SERVER_PORT = 80;
const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress NET_MASK(255, 255, 255, 0);
const int MAX_AP_CONNECTIONS = 8; 
const unsigned long AP_INACTIVITY_TIMEOUT_SEC = 600; 


#define MAX_MESSAGE_CONTENT_LEN 224
#define MAX_TTL_HOPS 40


#define HMAC_LEN 32 

#define MAX_PAYLOAD_LEN (MAX_MESSAGE_CONTENT_LEN - HMAC_LEN) 


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


const int MESH_KDF_ITERATIONS = 1000; 
const char* MESH_KDF_SALT = "89Prot43e589040392lt123XYZ";


const char* CMD_PREFIX = "CMD::";
const char* CMD_PUBLIC_ON = "CMD::PUBLIC_ON";
const char* CMD_PUBLIC_OFF = "CMD::PUBLIC_OFF";

typedef struct __attribute__((packed)) {
  uint64_t messageID; 
  uint8_t originalSenderMac[6];
  uint8_t ttl;
  uint8_t messageType;
  uint16_t checksum; 
  char content[MAX_MESSAGE_CONTENT_LEN]; 
} esp_now_message_t;


const char* WEB_PASSWORD = "4kfu4ofkf0w020ijfkus9w98";

String hashedOrganizerPassword;

WiFiServer server(WEB_SERVER_PORT);
IPAddress IP;
String MAC_full_str;
String MAC_suffix_str;
String ssid;
uint8_t ourMacBytes[6];

String userMessageBuffer = "";
String webFeedbackMessage = "";


String organizerSessionToken = "";
unsigned long sessionTokenTimestamp = 0;
const unsigned long SESSION_TIMEOUT_MS = 900000; 
bool publicMessagingEnabled = false; 
bool publicMessagingLocked = false;  
bool passwordChangeLocked = false; 
bool isOrganizerSessionActive = false;

bool isUsingDefaultPsk = false; 

int loginAttempts = 0;
unsigned long lockoutTime = 0;
const int MAX_LOGIN_ATTEMPTS = 20;
const unsigned long LOCKOUT_DURATION_MS = 300000; 


unsigned long totalMessagesSent = 0;
unsigned long totalMessagesReceived = 0;
unsigned long totalUrgentMessages = 0;


Preferences preferences; 
const unsigned long JAMMING_DETECTION_THRESHOLD_MS = 60000; 
const unsigned long JAMMING_ALERT_COOLDOWN_MS = 60000;
const unsigned long JAMMING_MEMORY_RESET_MS = 300000;
unsigned long lastMessageReceivedTimestamp = 0;
bool isCurrentlyJammed = false;
unsigned long lastJammingEventTimestamp = 0;
unsigned long lastJammingAlertSent = 0;
unsigned long communicationRestoredTimestamp = 0;
uint32_t jammingIncidentCount = 0; 
unsigned long lastJammingTimestampPersisted = 0; 
unsigned long lastJammingDurationPersisted = 0;  
uint32_t hashFailureCount = 0;     
const int MAX_FAIL_LOG_ENTRIES = 5;
bool securityCountersDirty = false; 
const unsigned long NVS_WRITE_INTERVAL_MS = 60000; 
unsigned long lastNvsWrite = 0;



bool isPromiscuousCheckActive = false;
unsigned long promiscuousCheckStartTime = 0;
const unsigned long PROMISCUOUS_SAMPLE_DURATION_MS = 2000; 
volatile long totalRssi = 0;
volatile int rssiSampleCount = 0;

const int RSSI_JAMMING_THRESHOLD = -54; 



const unsigned long INFILTRATION_WINDOW_MS = 300000; 
const int INFILTRATION_THRESHOLD = 2; 
bool isInfiltrationAlert = false; 
unsigned long lastInfiltrationEventTimestamp = 0;
uint32_t infiltrationIncidentCount = 0; 
unsigned long lastInfiltrationTimestampPersisted = 0; 
const int MAX_INFIL_LOG_ENTRIES = 5;

struct PasswordUpdateEvent {
    unsigned long timestamp;
    String passwordHash;
    uint8_t senderMac[6];
};
std::vector<PasswordUpdateEvent> passwordUpdateHistory;
portMUX_TYPE passwordUpdateHistoryMutex = portMUX_INITIALIZER_UNLOCKED;


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
const unsigned long AP_MANAGEMENT_INTERVAL_MS = 5000; 
unsigned long lastApManagement = 0;

DNSServer dnsServer;









volatile uint8_t PRE_SHARED_KEY[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 
  0x7C, 0xE3, 0x91, 0x2F, 0xA8, 0x5D, 0xB4, 0x69, 
  0x3E, 0xC7, 0x14, 0xF2, 0x86, 0x0B, 0xD9, 0x4A
};


uint8_t sessionKey[16]; 
bool useSessionKey = false; 




void aesCtrCrypt(uint8_t* data, size_t dataLen, uint64_t messageID, const uint8_t* mac, const uint8_t* key) {
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



void aesCtrEncrypt(uint8_t* data, size_t dataLen, uint64_t messageID, const uint8_t* mac, const uint8_t* key) {
    aesCtrCrypt(data, dataLen, messageID, mac, key);
}



void aesCtrDecrypt(uint8_t* data, size_t dataLen, uint64_t messageID, const uint8_t* mac, const uint8_t* key) {
    aesCtrCrypt(data, dataLen, messageID, mac, key);
}



String simpleHash(const String& input) {
    
    const String PSEUDO_SALT = "89Prot43estNodeSalt123XYZ";
    String saltedInput = input + PSEUDO_SALT;
    unsigned char hashOutput[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); 
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


void deriveAndSetSessionKey(const String& password) {
    unsigned char hash[32]; 
    
    
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1); 

    const unsigned char* pass_bytes = (const unsigned char*)password.c_str();
    size_t pass_len = password.length();
    const unsigned char* salt_bytes = (const unsigned char*)MESH_KDF_SALT;
    size_t salt_len = strlen(MESH_KDF_SALT);

    
    mbedtls_md_hmac_starts(&ctx, pass_bytes, pass_len);
    mbedtls_md_hmac_update(&ctx, salt_bytes, salt_len);
    mbedtls_md_hmac_finish(&ctx, hash);

    
    for (int i = 1; i < MESH_KDF_ITERATIONS; i++) {
        // Fix 1: Feed the watchdog to prevent timeouts/instability during long calculations
        if ((i % 100) == 0) delay(1); 

        unsigned char temp_hash[32];
        memcpy(temp_hash, hash, 32); 

        mbedtls_md_hmac_starts(&ctx, pass_bytes, pass_len);
        mbedtls_md_hmac_update(&ctx, temp_hash, 32); 
        mbedtls_md_hmac_finish(&ctx, hash);
    }
    
    mbedtls_md_free(&ctx);
    

    memcpy(sessionKey, hash, 16); 
    useSessionKey = true;
    passwordChangeLocked = true;
    // Fix 2: REMOVED: hashedOrganizerPassword update. This side effect was causing the hash mismatch.
    if(VERBOSE_MODE) Serial.println("Volatile session key derived from password (stretched).");
}

uint16_t calculateChecksum(const char* data, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += (uint8_t)data[i];
    }
    return sum;
}








void generateHMAC(const esp_now_message_t& msg, const char* plaintext_payload, const uint8_t* key, uint8_t* hmac_output) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1); 
    mbedtls_md_hmac_starts(&ctx, key, 16); 
    
    
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)&msg.messageID, sizeof(msg.messageID));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.originalSenderMac, sizeof(msg.originalSenderMac));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)&msg.messageType, sizeof(msg.messageType));
    
    
    size_t payload_len = strlen(plaintext_payload);
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)plaintext_payload, payload_len);
    
    mbedtls_md_hmac_finish(&ctx, hmac_output);
    mbedtls_md_free(&ctx);
}

struct SeenMessage {
  uint64_t messageID; 
  uint8_t originalSenderMac[6];
  unsigned long timestamp;
  esp_now_message_t messageData; 
};
std::vector<SeenMessage> seenMessages;
portMUX_TYPE seenMessagesMutex = portMUX_INITIALIZER_UNLOCKED;


const unsigned long DEDUP_CACHE_DURATION_MS = 1800000; 
const size_t MAX_CACHE_SIZE = 100;
const unsigned long PEER_LAST_SEEN_DURATION_MS = 600000; 
const unsigned long ESP_NOW_PEER_TIMEOUT_MS = 300000; 


typedef struct {
    esp_now_message_t messageData;
    uint8_t senderMac[6];
    unsigned long timestamp;
} IsrQueueMessage;


typedef struct {
    uint8_t senderMac[6];
    uint64_t messageID; 
    int type; 
} NvsQueueItem;

QueueHandle_t messageQueue;
QueueHandle_t nvsQueue;
const size_t QUEUE_SIZE = 10;
const size_t NVS_QUEUE_SIZE = 5;


struct LocalDisplayEntry {
    esp_now_message_t message; 
    unsigned long timestamp;
};
std::vector<LocalDisplayEntry> localDisplayLog;
portMUX_TYPE localDisplayLogMutex = portMUX_INITIALIZER_UNLOCKED;
const size_t MAX_LOCAL_DISPLAY_LOG_SIZE = 50;
const size_t NUM_ORGANIZER_MESSAGES_TO_RETAIN = 5;

const size_t MAX_WEB_MESSAGE_INPUT_LENGTH = 184;
const size_t MAX_POST_BODY_LENGTH = 2048;


std::map<String, unsigned long> lastSeenPeers;
portMUX_TYPE lastSeenPeersMutex = portMUX_INITIALIZER_UNLOCKED;


std::map<String, unsigned long> espNowAddedPeers;
portMUX_TYPE espNowAddedPeersMutex = portMUX_INITIALIZER_UNLOCKED;


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
    
    esp_now_message_t dummyMsg;
    memset(&dummyMsg, 0, sizeof(dummyMsg));
    dummyMsg.messageType = MSG_TYPE_UNKNOWN;
    memcpy(dummyMsg.originalSenderMac, ourMacBytes, 6);
    
    message.toCharArray(dummyMsg.content, MAX_PAYLOAD_LEN);
    dummyMsg.content[MAX_PAYLOAD_LEN - 1] = '\0';
    
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


bool isMessageSeen(uint64_t id, const uint8_t* mac) {
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


void addOrUpdateMessageToSeen(uint64_t id, const uint8_t* mac, const esp_now_message_t& msgData) {
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
    
    seenMessages.erase(std::remove_if(seenMessages.begin(), seenMessages.end(),
                                     [currentTime](const SeenMessage& msg) {
                                         
                                         if (msg.messageData.messageType == MSG_TYPE_PASSWORD_UPDATE) {
                                             return false;
                                         }
                                         return (currentTime - msg.timestamp) > DEDUP_CACHE_DURATION_MS;
                                     }),
                      seenMessages.end());

    
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
    
    
    
    esp_now_message_t storedMessage = msgData;
    storedMessage.ttl = MAX_TTL_HOPS;

    SeenMessage newMessage = {id, {0}, currentTime, storedMessage};
    memcpy(newMessage.originalSenderMac, mac, 6);
    seenMessages.push_back(newMessage);
  }
  portEXIT_CRITICAL(&seenMessagesMutex);
}






void promiscuousRxCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    
    if (isPromiscuousCheckActive) {
        wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
        
        
        portENTER_CRITICAL_ISR(&lastSeenPeersMutex); 
        totalRssi += pkt->rx_ctrl.rssi; 
        rssiSampleCount++;
        portEXIT_CRITICAL_ISR(&lastSeenPeersMutex);
    }
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

  
  
  const uint8_t* keyToUse = (const uint8_t*)PRE_SHARED_KEY + 4;
  if (useSessionKey && qMsg.messageData.messageType != MSG_TYPE_PASSWORD_UPDATE) {
      keyToUse = sessionKey;
  }
  
  aesCtrDecrypt((uint8_t*)qMsg.messageData.content, MAX_MESSAGE_CONTENT_LEN, qMsg.messageData.messageID, qMsg.messageData.originalSenderMac, keyToUse);
  qMsg.messageData.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0'; 

  
  

  
  uint8_t received_hmac[HMAC_LEN];
  memcpy(received_hmac, qMsg.messageData.content, HMAC_LEN);
  
  
  char received_payload[MAX_PAYLOAD_LEN];
  memcpy(received_payload, qMsg.messageData.content + HMAC_LEN, MAX_PAYLOAD_LEN);
  received_payload[MAX_PAYLOAD_LEN - 1] = '\0';
  
  
  uint8_t expected_hmac[HMAC_LEN];
  
  
  generateHMAC(qMsg.messageData, received_payload, keyToUse, expected_hmac);

  
  int diff = 0;
  for (int i = 0; i < HMAC_LEN; i++) {
      diff |= received_hmac[i] ^ expected_hmac[i];
  }

  if (diff != 0) {
      
      NvsQueueItem nvsItem;
      memcpy(nvsItem.senderMac, recvInfo->src_addr, 6);
      nvsItem.messageID = qMsg.messageData.messageID; 
      nvsItem.type = 0; 
      xQueueSendFromISR(nvsQueue, &nvsItem, 0);
      return; 
  }

  
  
  memset(qMsg.messageData.content, 0, MAX_MESSAGE_CONTENT_LEN);
  memcpy(qMsg.messageData.content, received_payload, strlen(received_payload) + 1); 
  
  

  if (qMsg.messageData.ttl == 0) {
      return;
  }

  
  if (xQueueSendFromISR(messageQueue, &qMsg, 0) != pdPASS) {
    
  }
}

void sendToAllPeers(esp_now_message_t& message) {
  if (message.ttl > 0) {
      message.ttl--; 
  } else {
      if(VERBOSE_MODE) Serial.println("Attempted to re-broadcast message with TTL 0. Skipping.");
      return;
  }

  
  
  const uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  esp_now_send(broadcastAddress, (uint8_t*)&message, sizeof(esp_now_message_t));
  
  
}

void createAndSendMessage(const char* plaintext_data, size_t plaintext_data_len, uint8_t type, const uint8_t* targetMac = nullptr) {
  
 if ((type == MSG_TYPE_ORGANIZER || type == MSG_TYPE_PUBLIC) && !useSessionKey) {
        if(VERBOSE_MODE) Serial.println("Node not capable of sending this message type (password not set). Skipping send.");
    webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Node not configured to send this message. Set an organizer password first.</p>";
    return;
  }

  esp_now_message_t newMessage;
  memset(&newMessage, 0, sizeof(newMessage));
  
  uint64_t random_id = (uint64_t)esp_random() << 32 | esp_random();
  newMessage.messageID = random_id;
  memcpy(newMessage.originalSenderMac, ourMacBytes, 6);
  newMessage.ttl = MAX_TTL_HOPS;
  newMessage.messageType = type;

  
  size_t len_to_copy = std::min(plaintext_data_len, (size_t)MAX_PAYLOAD_LEN - 1);
  char plaintext_payload[MAX_PAYLOAD_LEN];
  strncpy(plaintext_payload, plaintext_data, len_to_copy);
  plaintext_payload[len_to_copy] = '\0';


  
  
  const uint8_t* keyToUse = (const uint8_t*)PRE_SHARED_KEY + 4; 
  if (useSessionKey && type != MSG_TYPE_PASSWORD_UPDATE) {
      keyToUse = sessionKey;
  }

  
  
  uint8_t hmac_output[HMAC_LEN];
  generateHMAC(newMessage, plaintext_payload, keyToUse, hmac_output);
  
  
  memset(newMessage.content, 0, MAX_MESSAGE_CONTENT_LEN);
  memcpy(newMessage.content, hmac_output, HMAC_LEN);
  memcpy(newMessage.content + HMAC_LEN, plaintext_payload, strlen(plaintext_payload) + 1); 
  
  
  newMessage.checksum = 0;
  

  
  
  aesCtrEncrypt((uint8_t*)newMessage.content, MAX_MESSAGE_CONTENT_LEN, newMessage.messageID, newMessage.originalSenderMac, keyToUse);

  if (targetMac != nullptr) {
      esp_now_send(targetMac, (uint8_t*)&newMessage, sizeof(esp_now_message_t));
      if(VERBOSE_MODE) Serial.printf("Sent unicast message (Type: %d, ID: %llu) to %02X:%02X:%02X:%02X:%02X:%02X\n",
                    type, newMessage.messageID, targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5]);
  } else {
      sendToAllPeers(newMessage);
  }
  totalMessagesSent++;

  
  if (type == MSG_TYPE_DISCOVERY || type == MSG_TYPE_STATUS_REQUEST || type == MSG_TYPE_STATUS_RESPONSE || type == MSG_TYPE_JAMMING_ALERT) {
      return;
  }
  
  
  
  addOrUpdateMessageToSeen(newMessage.messageID, newMessage.originalSenderMac, newMessage);

  
  portENTER_CRITICAL(&localDisplayLogMutex);
  esp_now_message_t displayMessage = newMessage;
  
  aesCtrDecrypt((uint8_t*)displayMessage.content, MAX_MESSAGE_CONTENT_LEN, displayMessage.messageID, displayMessage.originalSenderMac, keyToUse);
  
  
  char payload_only[MAX_PAYLOAD_LEN];
  memcpy(payload_only, displayMessage.content + HMAC_LEN, MAX_PAYLOAD_LEN);
  payload_only[MAX_PAYLOAD_LEN - 1] = '\0';
  
  
  memset(displayMessage.content, 0, MAX_MESSAGE_CONTENT_LEN);
  strncpy(displayMessage.content, payload_only, MAX_PAYLOAD_LEN - 1);
  
  LocalDisplayEntry newEntry = {displayMessage, millis()};
  localDisplayLog.push_back(newEntry);
  portEXIT_CRITICAL(&localDisplayLogMutex);

  if(VERBOSE_MODE) Serial.println("Sending (Plaintext): " + String(plaintext_payload));
}

void manageLocalDisplayLog() {
    portENTER_CRITICAL(&localDisplayLogMutex);
    
    std::sort(localDisplayLog.begin(), localDisplayLog.end(), [](const LocalDisplayEntry& a, const LocalDisplayEntry& b) {
        return a.timestamp > b.timestamp;
    });

    std::vector<LocalDisplayEntry> newLocalDisplayLog;
    
    std::set<std::pair<uint64_t, String>> addedMessageKeys;

    
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

  preferences.begin("protest-node", false); 
  jammingIncidentCount = preferences.getUInt("jamCount", 0);
  lastJammingTimestampPersisted = preferences.getULong("jamLastTs", 0);
  lastJammingDurationPersisted = preferences.getULong("jamLastDur", 0);
  hashFailureCount = preferences.getUInt("hashFailCount", 0);
  infiltrationIncidentCount = preferences.getUInt("infilCount", 0);
  lastInfiltrationTimestampPersisted = preferences.getULong("infilLastTs", 0);
  if (VERBOSE_MODE) Serial.printf("Loaded from NVS -> Jamming: %u, Hash Failures: %u, Infiltration Attempts: %u\n", jammingIncidentCount, hashFailureCount, infiltrationIncidentCount);
  
  
  

  
  
  
  const char* factory_key_string = "\x7C\xE3\x91\x2F\xA8\x5D\xB4\x69"
                                   "\x3E\xC7\x14\xF2\x86\x0B\xD9\x4A";

  
  uint8_t factory_key_runtime[16];

  
  
  memcpy(factory_key_runtime, factory_key_string, 16);
  
  

  
  
  
  
  bool keysMatch = true;
  for (int i = 0; i < 16; i++) {
      
      if (PRE_SHARED_KEY[i + 4] != factory_key_runtime[i]) {
          keysMatch = false;
          break;
      }
  }
  
if (keysMatch) {
    isUsingDefaultPsk = true;
    if(VERBOSE_MODE) Serial.println("Operating Mode: Compatibility. Awaiting organizer password to secure mesh.");
    
    // VERBOSE DEBUG: Boot initialization
    if(VERBOSE_MODE) Serial.printf("BOOT: Initializing default organizer password. Input Default: '%s'\n", WEB_PASSWORD);
    hashedOrganizerPassword = simpleHash(WEB_PASSWORD);
    if(VERBOSE_MODE) Serial.printf("BOOT: Resulting Hash set to: '%s'\n", hashedOrganizerPassword.c_str());
    
  } else {
    isUsingDefaultPsk = false;
    if(VERBOSE_MODE) Serial.println("Operating Mode: Secure. Flashed PSK is the final mesh key.");

    for (int i = 0; i < 16; i++) {
        sessionKey[i] = PRE_SHARED_KEY[i + 4];
    }
    useSessionKey = true;

    // VERBOSE DEBUG: Boot initialization
    if(VERBOSE_MODE) Serial.printf("BOOT: Initializing default organizer password. Input Default: '%s'\n", WEB_PASSWORD);
    hashedOrganizerPassword = simpleHash(WEB_PASSWORD);
    if(VERBOSE_MODE) Serial.printf("BOOT: Resulting Hash set to: '%s'\n", hashedOrganizerPassword.c_str());
  }
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
  
  WiFi.softAP(ssid.c_str(), nullptr, WIFI_CHANNEL, 0, MAX_AP_CONNECTIONS);
  
  
  esp_wifi_set_inactive_time(WIFI_IF_AP, AP_INACTIVITY_TIMEOUT_SEC);

  IP = WiFi.softAPIP();
  server.begin();

  dnsServer.start(53, "*", AP_IP);
  Serial.println("DNS server started, redirecting all domains to: " + IP.toString());

  esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);

  
  
  esp_wifi_set_promiscuous_rx_cb(promiscuousRxCallback);
  esp_wifi_set_promiscuous(false);
  

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

  
  NvsQueueItem nvsItem;
  while (xQueueReceive(nvsQueue, &nvsItem, 0) == pdPASS) {
      if (nvsItem.type == 0) { 
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
    
    
    if (isPromiscuousCheckActive) {
        esp_wifi_set_promiscuous(false);
        isPromiscuousCheckActive = false;
        if(VERBOSE_MODE) Serial.println("Received valid packet. Aborting promiscuous jamming check.");
    }
    

    if (isCurrentlyJammed) {
        isCurrentlyJammed = false;
        communicationRestoredTimestamp = millis();
        if(VERBOSE_MODE) Serial.println("Communication restored. Jamming appears to have stopped.");

        
        esp_wifi_set_promiscuous(false);
        isPromiscuousCheckActive = false;
        

        if (lastJammingEventTimestamp > 0) {
            lastJammingDurationPersisted = millis() - lastJammingEventTimestamp;
            securityCountersDirty = true;
        }
        addDisplayLog("Communication restored.");
    }

    esp_now_message_t incomingMessage = qMsg.messageData;
    uint8_t* recvInfoSrcAddr = qMsg.senderMac;
    unsigned long receptionTimestamp = qMsg.timestamp;
    
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
        
        esp_now_message_t encryptedForCache = incomingMessage;
        
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
    
    
if (incomingMessage.messageType == MSG_TYPE_PASSWORD_UPDATE) {
    String incomingContent = String(incomingMessage.content);

    
    if (!wasAlreadySeen) {
        // Check if the message contains a delimiter indicating "HASH|PLAINTEXT" format
        int delimiterPos = incomingContent.indexOf('|');
        
        if (delimiterPos > 0 && delimiterPos == 64) {
            // NEW PROTOCOL: "HASH|PLAINTEXT" format
            String receivedHash = incomingContent.substring(0, 64);
            String receivedPlaintext = incomingContent.substring(65);
            
            if(VERBOSE_MODE) {
                Serial.println("Received password update in HASH|PLAINTEXT format (new protocol)");
                Serial.printf("Received Hash: '%s'\n", receivedHash.c_str());
            }
            
            // Use the hash directly for web login (no re-hashing)
            hashedOrganizerPassword = receivedHash;
            passwordChangeLocked = true;
            
            // If in Compatibility mode, derive the session key from plaintext
            if (isUsingDefaultPsk) {
                if(VERBOSE_MODE) Serial.println("Deriving session key from plaintext portion");
                deriveAndSetSessionKey(receivedPlaintext);
            }
            
        } else {
            // LEGACY PROTOCOL: Just plaintext (for backward compatibility)
            if(VERBOSE_MODE) Serial.println("Received password update in plaintext format (legacy protocol)");
            
            hashedOrganizerPassword = simpleHash(incomingContent);
            passwordChangeLocked = true;

            if (isUsingDefaultPsk) {
                if(VERBOSE_MODE) Serial.println("Deriving session key from plaintext");
                deriveAndSetSessionKey(incomingContent);
            }
        }
    }            
        
        
        String newPasswordHash = simpleHash(String(incomingMessage.content));
        unsigned long currentTime = millis();

        portENTER_CRITICAL(&passwordUpdateHistoryMutex);
        
        passwordUpdateHistory.erase(std::remove_if(passwordUpdateHistory.begin(), passwordUpdateHistory.end(),
            [currentTime](const PasswordUpdateEvent& event) {
                return (currentTime - event.timestamp) > INFILTRATION_WINDOW_MS;
            }), passwordUpdateHistory.end());

        
        PasswordUpdateEvent newEvent;
        newEvent.timestamp = currentTime;
        newEvent.passwordHash = newPasswordHash;
        memcpy(newEvent.senderMac, incomingMessage.originalSenderMac, 6);
        passwordUpdateHistory.push_back(newEvent);

        
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

        
        
        
        
        
    }
    
    
    
    
    esp_now_message_t encryptedForCache = incomingMessage; 
    
    const uint8_t* keyToUseForCache = (const uint8_t*)PRE_SHARED_KEY + 4; 
    if(useSessionKey && encryptedForCache.messageType != MSG_TYPE_PASSWORD_UPDATE) {
        keyToUseForCache = sessionKey; 
    }
    
    
    char payload_for_hmac[MAX_PAYLOAD_LEN];
    strncpy(payload_for_hmac, incomingMessage.content, MAX_PAYLOAD_LEN - 1);
    payload_for_hmac[MAX_PAYLOAD_LEN - 1] = '\0';
    
    
    uint8_t hmac_output[HMAC_LEN];
    generateHMAC(encryptedForCache, payload_for_hmac, keyToUseForCache, hmac_output);
    
    
    memset(encryptedForCache.content, 0, MAX_MESSAGE_CONTENT_LEN);
    memcpy(encryptedForCache.content, hmac_output, HMAC_LEN);
    memcpy(encryptedForCache.content + HMAC_LEN, payload_for_hmac, strlen(payload_for_hmac) + 1);

    
    
    aesCtrEncrypt((uint8_t*)encryptedForCache.content, MAX_MESSAGE_CONTENT_LEN, encryptedForCache.messageID, encryptedForCache.originalSenderMac, keyToUseForCache);
    
    addOrUpdateMessageToSeen(encryptedForCache.messageID, encryptedForCache.originalSenderMac, encryptedForCache);

    if (!wasAlreadySeen) {
        totalMessagesReceived++;
        if (String(incomingMessage.content).indexOf("Urgent: ") != -1) {
            totalUrgentMessages++;
        }
        if (!skipDisplayLog) {
            portENTER_CRITICAL(&localDisplayLogMutex);
            
            LocalDisplayEntry newEntry = {incomingMessage, millis()};
            localDisplayLog.push_back(newEntry);
            portEXIT_CRITICAL(&localDisplayLogMutex);
        }
        if (incomingMessage.ttl > 0) {
            
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

  
  
  
  

  
  bool hasPeers = false;
  portENTER_CRITICAL(&lastSeenPeersMutex);
  hasPeers = lastSeenPeers.size() > 1;
  portEXIT_CRITICAL(&lastSeenPeersMutex);

  
  
  
  if (isPromiscuousCheckActive) {
      
      if (millis() - promiscuousCheckStartTime > PROMISCUOUS_SAMPLE_DURATION_MS) {
          
          
          esp_wifi_set_promiscuous(false);
          isPromiscuousCheckActive = false;
          if(VERBOSE_MODE) Serial.println("Promiscuous sampling complete. Analyzing noise floor...");

          
          float avgRssi = -100.0; 
          if (rssiSampleCount > 0) {
              avgRssi = (float)totalRssi / rssiSampleCount;
              if(VERBOSE_MODE) Serial.printf("Avg RSSI: %.1f dBm (from %d packets)\n", avgRssi, rssiSampleCount);
          } else {
              if(VERBOSE_MODE) Serial.println("No packets sniffed during check.");
          }

          
          if (avgRssi > RSSI_JAMMING_THRESHOLD) {
              
              
              if(VERBOSE_MODE) Serial.println("Jamming confirmed: Packet loss AND high noise floor.");
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
          } else {
              
              
              if(VERBOSE_MODE) Serial.println("False alarm: Packet loss but channel is quiet. Peers likely offline.");
              
              lastMessageReceivedTimestamp = millis(); 
          }
      }
  }
  
  
  else if (hasPeers && !isCurrentlyJammed && (millis() - lastMessageReceivedTimestamp > JAMMING_DETECTION_THRESHOLD_MS)) {
      
      
      
      if(VERBOSE_MODE) Serial.println("Packet loss detected (Factor 1). Starting promiscuous check (Factor 2)...");
      
      
      portENTER_CRITICAL(&lastSeenPeersMutex); 
      totalRssi = 0;
      rssiSampleCount = 0;
      portEXIT_CRITICAL(&lastSeenPeersMutex);
      
      
      isPromiscuousCheckActive = true;
      promiscuousCheckStartTime = millis();
      esp_wifi_set_promiscuous(true);
  }
  


  
  if (lastJammingEventTimestamp > 0 && !isCurrentlyJammed && communicationRestoredTimestamp > 0 &&
      (millis() - communicationRestoredTimestamp > JAMMING_MEMORY_RESET_MS)) {
      if(VERBOSE_MODE) Serial.println("Sustained communication detected. Resetting long-term jamming memory.");
      lastJammingEventTimestamp = 0;
      communicationRestoredTimestamp = 0;
      addDisplayLog("Jamming alert cleared.");
  }

  
  if (isInfiltrationAlert && (millis() - lastInfiltrationEventTimestamp > JAMMING_MEMORY_RESET_MS)) {
      if(VERBOSE_MODE) Serial.println("Infiltration alert timeout. Resetting alert status.");
      isInfiltrationAlert = false;
      
      portENTER_CRITICAL(&passwordUpdateHistoryMutex);
      passwordUpdateHistory.clear();
      portEXIT_CRITICAL(&passwordUpdateHistoryMutex);
      addDisplayLog("Infiltration alert cleared.");
  }

  
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

  
  if (millis() - lastApManagement >= AP_MANAGEMENT_INTERVAL_MS) {
    lastApManagement = millis();

    
    
    wifi_config_t conf;
    esp_wifi_get_config((wifi_interface_t)WIFI_IF_AP, &conf);
    int num_stations = WiFi.softAPgetStationNum();

    if (num_stations >= MAX_AP_CONNECTIONS && conf.ap.ssid_hidden == 0) {
        
        conf.ap.ssid_hidden = 1;
        esp_wifi_set_config((wifi_interface_t)WIFI_IF_AP, &conf);
        if(VERBOSE_MODE) Serial.printf("AP is full (%d clients). Hiding SSID.\n", num_stations);
    } else if (num_stations < MAX_AP_CONNECTIONS && conf.ap.ssid_hidden == 1) {
        
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
                unsigned long readTimeout = millis();
                while (postBody.length() < contentLength && (millis() - readTimeout < 2000)) {
                    if (client.available()) {
                        postBody += (char)client.read();
                        readTimeout = millis();
                    } else {
                        delay(1);
                    }
                }
                
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
            
            if (requestedPath != "/" && currentQueryParams.indexOf("show_public") == -1 && currentQueryParams.indexOf("show_urgent") == -1 && currentQueryParams.indexOf("session_token") == -1) {
                if(VERBOSE_MODE) Serial.println("Intercepted non-root GET request for: " + requestedPath + ". Redirecting to captive portal.");
                client.println(F("HTTP/1.1 302 Found")); client.println(F("Location: http://192.168.4.1/"));
                client.println(F("Connection: close")); client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
                client.println(F("Pragma: no-cache")); client.println(F("Expires: 0")); client.println(); client.stop(); return;
            }

if (isPost) {
              
              String messageParam = "", passwordHashParam = "", urgentParam = "", actionParam = "", newPasswordParam = "", confirmNewPasswordParam = "", newPasswordHashParam = "";
              
              
              int messageStart = postBody.indexOf("message=");
              if (messageStart != -1) {
                int messageEnd = postBody.indexOf('&', messageStart);
                if (messageEnd == -1) messageEnd = postBody.length();
                messageParam = postBody.substring(messageStart + 8, messageEnd);
              }
              
              int passwordHashStart = postBody.indexOf("password_hash_client=");
              if (passwordHashStart != -1) {
                int passwordHashEnd = postBody.indexOf('&', passwordHashStart);
                if (passwordHashEnd == -1) passwordHashEnd = postBody.length();
                passwordHashParam = postBody.substring(passwordHashStart + 21, passwordHashEnd);
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
              int newPasswordHashStart = postBody.indexOf("new_password_hash=");
              if (newPasswordHashStart != -1) {
                  int newPasswordHashEnd = postBody.indexOf('&', newPasswordHashStart);
                  if (newPasswordHashEnd == -1) newPasswordHashEnd = postBody.length();
                  newPasswordHashParam = postBody.substring(newPasswordHashStart + 18, newPasswordHashEnd);
              }

              
              messageParam.replace('+', ' '); String decodedMessage = "";
              for (int i = 0; i < messageParam.length(); i++) {
                if (messageParam.charAt(i) == '%' && (i + 2) < messageParam.length()) { decodedMessage += (char)strtol((messageParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedMessage += messageParam.charAt(i); }
              }
              
              
              passwordHashParam.replace('+', ' '); String decodedPasswordHash = "";
              for (int i = 0; i < passwordHashParam.length(); i++) {
                if (passwordHashParam.charAt(i) == '%' && (i + 2) < passwordHashParam.length()) { decodedPasswordHash += (char)strtol((passwordHashParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedPasswordHash += passwordHashParam.charAt(i); }
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
              
              newPasswordHashParam.replace('+', ' '); String decodedNewPasswordHash = "";
              for (int i = 0; i < newPasswordHashParam.length(); i++) {
                if (newPasswordHashParam.charAt(i) == '%' && (i + 2) < newPasswordHashParam.length()) { decodedNewPasswordHash += (char)strtol((newPasswordHashParam.substring(i + 1, i + 3)).c_str(), NULL, 16); i += 2; }
                else { decodedNewPasswordHash += newPasswordHashParam.charAt(i); }
              }

                if (actionParam == "enterOrganizer") {
                    if (lockoutTime > 0 && millis() < lockoutTime) { 
                        webFeedbackMessage = "<p class='feedback' style='color:red;'>Too many failed attempts. Try again later.</p>"; 
                    } else {
                        if (lockoutTime > 0 && millis() >= lockoutTime) { 
                            lockoutTime = 0; 
                            loginAttempts = 0; 
                        }
                        
                        // VERBOSE DEBUG: Login Attempt Comparison
                        if(VERBOSE_MODE) {
                            Serial.println("\n--- LOGIN ATTEMPT INITIATED ---");
                            
                            // 1. The Hash currently stored in memory (Expected)
                            Serial.printf("LOGIN DEBUG: [Variable: hashedOrganizerPassword] (Expected Web Hash): '%s'\n", hashedOrganizerPassword.c_str());
                            
                            // 2. The Stretched Key currently active in memory (For comparison to see if it overwrote the web hash)
                            String currentSessionKeyHex = "";
                            for(int k=0; k<16; k++) { char hexBuf[3]; sprintf(hexBuf, "%02X", sessionKey[k]); currentSessionKeyHex += hexBuf; }
                            Serial.printf("LOGIN DEBUG: [Variable: sessionKey] (Active Mesh Key):             '%s'\n", currentSessionKeyHex.c_str());

                            // 3. The Hash sent by the Client
                            Serial.printf("LOGIN DEBUG: [Variable: decodedPasswordHash] (Received Client Hash):  '%s'\n", decodedPasswordHash.c_str());
                            
                            if (hashedOrganizerPassword.length() == 0) {
                                Serial.println("LOGIN DEBUG: CRITICAL WARNING! Stored hash is EMPTY String!");
                            }
                            
                            if (decodedPasswordHash.equalsIgnoreCase(hashedOrganizerPassword)) {
                                Serial.println("LOGIN DEBUG: RESULT -> MATCH CONFIRMED.");
                            } else {
                                Serial.println("LOGIN DEBUG: RESULT -> MISMATCH DETECTED.");
                                if (decodedPasswordHash.equalsIgnoreCase(currentSessionKeyHex)) {
                                    Serial.println("LOGIN DEBUG: CRITICAL ERROR -> Client hash matches the MESH KEY, not the WEB HASH. Did the keys get swapped?");
                                }
                            }
                            Serial.println("-------------------------------\n");
                        }
                        
                        if (decodedPasswordHash.equalsIgnoreCase(hashedOrganizerPassword)) { 
                            loginAttempts = 0;
                            organizerSessionToken = String(esp_random()) + String(esp_random());
                            sessionTokenTimestamp = millis();
                            isOrganizerSessionActive = true;
                            webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer Mode activated.</p>";
                            if (!passwordChangeLocked) { 
                                webFeedbackMessage += "<p class='feedback' style='color:orange;'>Note: Node's organizer password is still default. Set a new password to enable sending messages.</p>"; 
                            }
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
                            } else { 
                                webFeedbackMessage = "<p class='feedback' style='color:red;'>Incorrect password. " + String(MAX_LOGIN_ATTEMPTS - loginAttempts) + " attempts remaining.</p>"; 
                            }
                        }
                    }
                } else if (actionParam == "exitOrganizer") 
    {
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

              client.println(F("HTTP/1.1 303 See Other"));
              String redirectQuery = currentQueryParams;
              if (isOrganizerSessionActive && sessionTokenParam.length() > 0) {
                  if (redirectQuery.length() > 0) redirectQuery += "&";
                  redirectQuery += "session_token=" + sessionTokenParam;
              }
              client.println("Location: /?" + redirectQuery);
              client.println(F("Connection: close")); client.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
              client.println(F("Pragma: no-cache")); client.println(F("Expires: 0")); client.println(); client.stop(); return;
} else if (actionParam == "setOrganizerPassword") {

    if (passwordChangeLocked) {
        webFeedbackMessage = "<p class='feedback' style='color:red;'>The organizer password for this node cannot be changed after it has been set. To reset the password, you must reboot the board.</p>";
    } else { 
        if(VERBOSE_MODE) {
            Serial.println("\n--- SET PASSWORD ATTEMPT START ---");
            Serial.printf("SET_PASS: Received plaintext: '%s'\n", decodedNewPassword.c_str());
        }

        if (decodedNewPassword.length() == 0) {
            webFeedbackMessage = "<p class='feedback' style='color:orange;'>New password cannot be empty.</p>";
        } else if (decodedNewPassword != decodedConfirmNewPassword) {
            webFeedbackMessage = "<p class='feedback' style='color:red;'>New passwords do not match. Please try again.</p>";
        } else {
            
            // 1. Calculate Simple Hash (For Web Login) - USING CLIENT PROVIDED HASH
            String correctWebHash = decodedNewPasswordHash;
            if (correctWebHash.length() == 0) {
                // Fallback only if client JS failed completely
                if(VERBOSE_MODE) Serial.println("SET_PASS WARNING: Client did not send hash! Falling back to server-side calc (might be flaky).");
                correctWebHash = simpleHash(decodedNewPassword);
            }

            if(VERBOSE_MODE) Serial.printf("SET_PASS DEBUG: Using Client-Provided Hash (for Web Login): '%s'\n", correctWebHash.c_str());

            if (isUsingDefaultPsk) {
                if(VERBOSE_MODE) Serial.println("SET_PASS: Mode is Compatibility.");
                
                // 2. Derive Stretched Key (For Mesh Encryption) - STILL USING PLAINTEXT
                deriveAndSetSessionKey(decodedNewPassword);
                
                // Capture the result of the derivation for logging
                String generatedSessionKeyHex = "";
                for(int k=0; k<16; k++) { char hexBuf[3]; sprintf(hexBuf, "%02X", sessionKey[k]); generatedSessionKeyHex += hexBuf; }
                if(VERBOSE_MODE) Serial.printf("SET_PASS DEBUG: Derived Stretched Key (for Mesh):      '%s'\n", generatedSessionKeyHex.c_str());

                // 3. Assign Web Hash to Global Variable
                hashedOrganizerPassword = correctWebHash;
                
                // 4. Verify what was actually stored
                if(VERBOSE_MODE) {
                    Serial.printf("SET_PASS DEBUG: FINAL CHECK [hashedOrganizerPassword] is now: '%s'\n", hashedOrganizerPassword.c_str());
                    if (hashedOrganizerPassword != correctWebHash) Serial.println("SET_PASS DEBUG: ERROR! Assignment failed or value corrupted!");
                }
                
                // *** FIX: Broadcast "HASH|PLAINTEXT" so receivers get both ***
                String broadcastPayload = correctWebHash + "|" + decodedNewPassword;
                createAndSendMessage(broadcastPayload.c_str(), broadcastPayload.length(), MSG_TYPE_PASSWORD_UPDATE);
                
                if(VERBOSE_MODE) {
                    Serial.printf("SET_PASS DEBUG: Broadcasting HASH|PLAINTEXT to mesh (length: %d)\n", broadcastPayload.length());
                }
            } else {
                if(VERBOSE_MODE) Serial.println("SET_PASS: Mode is Secure.");
                
                hashedOrganizerPassword = correctWebHash;

                if(VERBOSE_MODE) {
                    Serial.printf("SET_PASS DEBUG: FINAL CHECK [hashedOrganizerPassword] is now: '%s'\n", hashedOrganizerPassword.c_str());
                }

                // *** FIX: Broadcast "HASH|PLAINTEXT" for consistency ***
                String broadcastPayload = correctWebHash + "|" + decodedNewPassword;
                createAndSendMessage(broadcastPayload.c_str(), broadcastPayload.length(), MSG_TYPE_PASSWORD_UPDATE);
                
                if(VERBOSE_MODE) {
                    Serial.printf("SET_PASS DEBUG: Broadcasting HASH|PLAINTEXT to mesh (length: %d)\n", broadcastPayload.length());
                }
            }

            if(VERBOSE_MODE) Serial.println("--- SET PASSWORD ATTEMPT END ---\n");

            // Lock changes after setting
            passwordChangeLocked = true;
            webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer password updated successfully!</p>";
            loginAttempts = 0;
            lockoutTime = 0;
        }
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
                
                
                
                uint8_t macBytes[6];
                sscanf(macPair.first.c_str(), "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
                       &macBytes[0], &macBytes[1], &macBytes[2], &macBytes[3], &macBytes[4], &macBytes[5]);
                

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
            client.println(F("<meta http-equiv=\"refresh\" content=\"120\">")); 
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
            client.println(F("</style>"));
            
            
            
            client.println(F("<script>/* Embedded SHA256-lite */(function(){'use strict';function H(a,b,c){var d=0,e=0,f=0,g=0;a.constructor===Uint8Array?g=a.length:(a.constructor===String?(a=new TextEncoder(\"utf-8\").encode(a),g=a.length):g=0);if(0===g)return 0;for(b=new Uint32Array(g>>2);d<g;)b[d>>2]=a[d]<<24|a[d+1]<<16|a[d+2]<<8|a[d+3],d+=4;c=g%4;if(0!==c)for(e=c;e<4;)b[d>>2]|=a[d+e]<<(4-e-1)*8,e++;var h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541390259];a=[1116352408,1899447447,3049361855,3921009573,961987163,1508970016,3593144817,406816023,1290649138,3004264742,2321455201,4045716259,57705580,1859602716,3395469782,4118920178,1628844853,2492860718,3491485078,3901633936,609208033,1329193681,3815920427,400977604,1163531501,2342706862,3632440244,3884817595,1956699011,2130704874,207597394,1857173273,2754264857,1629227566,3881787524,1033485801,2177205429,112881515,4001127021,3660149591,157735391,2412708381,3828201639,584515726,3736713038,2066992612,3758327173,3817735313,3812723432,2994424399,280716301,272860766,622594287,248530933,73804301,90204780,1784774880,1236559866,1761066044,3730303524,4092019936,3694460776,145199670,1847177025,3688154181,1522774392,2643833823,265179200,3114854546,3681734255,2493976856,1240674715,1038133503,3703020674,2726917864,2896196590,4215389547,1550732330,1119788129,3301950169,3222384244,1017036298,3007366471,1038577814,141067277,3780759546,2444565612,2343943847,4273549970,1473187140,1751108724,1992749463,3574087978,4164318184,1535738821,3070593630,2860888917,4225563292,1011630717,1447752182,3474668285,1382997038,3679934726,3943505202,323645098,3547734297,1319985993,3323577539,3687155713,3809400263,333912643,1012447380,3101857488,1164993865,1136108269,2270897916,1543107025,3637525293,3988949519,2111559525,2873310033,1749197816,2386927914,975883529,629401876,1698069671,3667761022,2733995506,3238917601,1092640236,1954477817,395177673,33804754,3666487920,3801266474,1223361491,2506306560,3446277080,2656020583,2340701897,2937704207,1792461990,2637563286,4006180808,552545892,3055964894,629810857,1722887003,3464243087,3082524450,1139439325,127609322,3474884277,2049075301,3736744612,4011000673,2170208229,1716335198,3933068612,1765235456,654644793,3550264857,2144207698,2004780887,1785787925,925037283,3685410314,3606990263,3836378882,2772551525,4196142475,2556795499,1986617051,3602990601,237933827,2495861113,959955959,1031102008,185847526,3816694248,3555663953,3083594834,1328291886,3194857483,4152766624,3329325298,3628461464,3682055610,3815920875,726945033,2606132960,1118671206,1770282194,1542337777,2576404283,2516758473,3060601569,3226354613,813098522,1163583215,593123805,1557988352,1975797880,3039603007,2446722300,4216313132,1370094589,1448665727,3814030040,1925359195,3174544830,3616239120,4124453084,3301726073,3469055869,3257850550,2960544746,404751433,3917424606,1924343851,1803027771,3874248923,3138078752,3570189010,917955519,3070868153,3025078515,4001053361,1547847113,3862662991,192837583,4115392686,2275496417,1399659044,2673081016,1044749330,3274296791,3740288856,1557161803,1659956424,3743048501,4197178189,3688157774,1384461943,2121764653,1015949514,2440333202,4240889248,633917192,2348545806,2007804863,1674768909,2980755913,3071856021,75763567,1126048597,3631244837,3900259930,3593040374,743516346,2312069212,3247055080,1862192730,1970420042,3568853924,402506443,4217150537,3145404555,270693768,3602018859,3350920400,1658850239,391245044,3993212004,4241725596,2587586395,1905476632,803164746,1917429472,2170887602,2844038169,3114382891,3300589136,1775796067,3191057479,2588147820,3811314138,4167387420,776495115,2298715764,2500858674,2133400115,1422775988,3825201069,4142416972,130932529,1958615673,2487611592,3082536281,4029961608,1815967954,1969542036,678393582,3587425717,2532729938,2844297805,4206689658,2827104085,4206307128];var l=[109,101,115,104,83,97,108,116,49,50,51,88,89,90];for(d=0;320>d;d++){var m=b[d];b[d]=(m>>>18|m<<14)&4294967295^((m>>>3|m<<29)&4294967295)^((m>>>10|m<<22)&4294967295);var n=b[d-7];b[d]=(b[d]+b[d-16]+(m^n))&4294967295}d=h;for(e=0;64>e;e++){var o=d[7],p=d[4],q=d[0],r=d[1];o=o+(h[4]>>>6|h[4]<<26)&4294967295^((p>>>11|p<<21)&4294967295)^((p>>>25|p<<7)&4294967295)+((p&h[5])^((~p)&h[6]))+a[e]+b[e];p=o+(q>>>2|q<<30)&4294967295^((q>>>13|q<<19)&4294967295)^((q>>>22|q<<10)&4294967295)+((q&r)^(q&d[2])^(r&d[2]))+a[e];d[7]=d[6];d[6]=d[5];d[5]=d[4];d[4]=d[3]+o;d[3]=d[2];d[2]=d[1];d[1]=d[0];d[0]=p}for(e=0;8>e;e++)h[e]=(h[e]+d[e])&4294967295;g+=512;for(b=0;g>=512;)b+=16,g-=512;d=[];for(e=0;16>e;e++)d.push(b[b+e]);b=d;for(d=0;g>=8;)d+=1,g-=8;a=new Uint8Array(8);for(e=0;8>e;e++)a[e]=255&g>>>8*(7-e);h.push(128);for(;h.length%16!==14;)h.push(0);h=h.concat(a);a=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541390259];for(d=0;d<h.length;d+=16){for(e=0;16>e;e++)b[e]=h[d+e];for(e=16;64>e;e++){var s=b[e-2],t=b[e-15];b[e]=(s>>>18|s<<14)&4294967295^((s>>>3|s<<29)&4294967295)^((s>>>10|s<<22)&4294967295)+b[e-7]+((t>>>17|t<<15)&4294967295^((t>>>19|t<<13)&4294967295)^((t>>>10|t<<22)&4294967295)+b[e-16])&4294967295}d=a;for(e=0;64>e;e++){var u=d[7],v=d[4],w=d[0],x=d[1];u=u+(d[4]>>>6|d[4]<<26)&4294967295^((v>>>11|v<<21)&4294967295)^((v>>>25|v<<7)&4294967295)+((v&d[5])^((~v)&d[6]))+l[e]+b[e];v=u+(w>>>2|w<<30)&4294967295^((w>>>13|w<<19)&4294967295)^((w>>>22|w<<10)&4294967295)+((w&x)^(w&d[2])^(x&d[2]))+l[e];d[7]=d[6];d[6]=d[5];d[5]=d[4];d[4]=d[3]+u;d[3]=d[2];d[2]=d[1];d[1]=d[0];d[0]=v}for(e=0;8>e;e++)a[e]=(a[e]+d[e])&4294967295}c=[];for(d=0;8>d;d++)c.push(a[d]>>>24,a[d]>>>16&255,a[d]>>>8&255,a[d]&255);a=[];for(d=0;c.length>d;d++)a.push((16>c[d]?\"0\":\"\")+c[d].toString(16));return a.join(\"\")}window.sha256=H;})();</script>"));

client.println(F("<script>"));
            client.println(F("document.addEventListener('DOMContentLoaded', () => { const preElement = document.querySelector('pre'); if (preElement) { preElement.scrollTop = 0; } });"));
            client.println(F("function computeSimpleHash(inputStr) {"));
            
            client.println(F("  var saltedInput = inputStr + \"89Prot43estNodeSalt123XYZ\";"));
            
            client.println(F("  var hex = window.sha256(saltedInput);"));
            client.println(F("  return hex.toLowerCase();"));
            
            client.println(F("}"));
            
            client.println(F("function hashAndSubmitPassword(form) {"));
            client.println(F("  try {"));
            client.println(F("    var plainInput = form.querySelector('input[name=\"password_plaintext_client\"]');"));
            client.println(F("    var hashInput = form.querySelector('input[name=\"password_hash_client\"]');"));
            client.println(F("    if (!plainInput.value) { alert('Please enter a password.'); return false; }"));
            client.println(F("    var hash = computeSimpleHash(plainInput.value);"));
            client.println(F("    hashInput.value = hash;"));
            client.println(F("    return true;")); 
            client.println(F("  } catch (e) { console.error(\"Hashing failed\", e); return true; }"));
            client.println(F("  return false;"));
            client.println(F("}"));
            
            client.println(F("function hashAndSubmitSetPassword(form) {"));
            client.println(F("  try {"));
            client.println(F("    var plainInput = form.querySelector('input[name=\"new_password\"]');"));
            client.println(F("    var hashInput = form.querySelector('input[name=\"new_password_hash\"]');"));
            client.println(F("    if (!plainInput.value) { alert('Please enter a password.'); return false; }"));
            client.println(F("    var hash = computeSimpleHash(plainInput.value);"));
            client.println(F("    hashInput.value = hash;"));
            client.println(F("    return true;")); 
            client.println(F("  } catch (e) { console.error(\"Hashing failed\", e); return true; }"));
            client.println(F("  return false;"));
            client.println(F("}"));
            client.println(F("</script>"));         
            client.println(F("</head>")); 
            
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

                
                if (!isOrganizerSessionActive && isSystemMessage) {
                    continue;
                }
                
                String formattedLine = "Node " + getMacSuffix(msg.originalSenderMac) + " - ";
                String messageTypePrefix = "";
                if (msg.messageType == MSG_TYPE_ORGANIZER) messageTypePrefix = "Organizer: ";
                else if (msg.messageType == MSG_TYPE_PUBLIC) messageTypePrefix = "Public: ";
                else if (msg.messageType == MSG_TYPE_COMMAND) messageTypePrefix = "Command: ";
                else if (msg.messageType == MSG_TYPE_AUTO_INIT) messageTypePrefix = "Auto: ";
                formattedLine += String(msg.content);

                if (msg.messageType == MSG_TYPE_PASSWORD_UPDATE) { continue; }
                
                bool passesPublicFilter = !(formattedLine.indexOf("Public: ") != -1 && !showPublicView);
                bool passesUrgentFilter = !(formattedLine.indexOf("Urgent: ") == -1 && showUrgentView);
                
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
                

                client.println(F("<hr style='margin: 15px 0;'><h3>Set/Reset Organizer Password:</h3>"));
                if (passwordChangeLocked) {
                    client.println(F("<p class='feedback' style='color:red; font-size:0.8em; margin-top:10px;'>The organizer password for this node cannot be changed after it has been set. To reset the password, you must reboot the board.</p>"));
                } else {
                    client.println(F("<form action='/' method='POST' onsubmit='return hashAndSubmitSetPassword(this);'><input type='hidden' name='action' value='setOrganizerPassword'>"));
                    client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='new_pass_input'>New Password:</label><input type='password' id='new_pass_input' name='new_password' required>"));
                    client.println(F("<label for='confirm_new_pass_input'>Confirm New Password:</label><input type='password' id='confirm_new_pass_input' name='confirm_new_password' required>"));
                    client.println(F("<input type='hidden' name='new_password_hash' value=''>"));
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
                if (showPublicView) client.println(F("<input type'hidden' name='show_public' value='true'>"));
                if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                if (hideSystemView) client.println(F("<input type='hidden' name='hide_system' value='true'>"));
                client.println(F("<input type='submit' value='Exit Organizer Mode' class='button-link secondary' style='background-color:#dc3545; width: auto;'></form>"));
                client.println(F("</div></details>"));
            } else {
                if (!passwordChangeLocked) {
                    
                    client.println(F("<details open><summary>Set Initial Organizer Password</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<h3>Set Your Organizer Password:</h3><form action='/' method='POST' onsubmit='return hashAndSubmitSetPassword(this);'><input type='hidden' name='action' value='setOrganizerPassword'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='new_pass_input'>New Password:</label><input type='password' id='new_pass_input' name='new_password' required>"));
                    client.println(F("<label for='confirm_new_pass_input'>Confirm New Password:</label><input type='password' id='confirm_new_pass_input' name='confirm_new_password' required>"));
                    client.println(F("<input type='hidden' name='new_password_hash' value=''>"));
                    client.println(F("<input type='submit' value='Set Password' class='button-link' style='background-color:#007bff; width: auto;'></form>"));
                    if (isUsingDefaultPsk) {
                        client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>Set the mesh-wide password. After setting, you must log in with this password to access organizer functions.</p>"));
                    } else {
                        client.println(F("<p class='feedback' style='color:blue; font-size:0.8em; margin-top:10px;'>This node was flashed with a secure key. Set the web login password here. This will NOT affect mesh encryption.</p>"));
                    }
                    client.println(F("</div></details>"));
                } else {
                    
                    client.println(F("<details><summary>Enter Organizer Mode</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<form action='/' method='POST' onsubmit='return hashAndSubmitPassword(this);'><input type='hidden' name='action' value='enterOrganizer'>"));
                    if (showPublicView) client.println(F("<input type='hidden' name='show_public' value='true'>"));
                    if (showUrgentView) client.println(F("<input type='hidden' name='show_urgent' value='true'>"));
                    client.println(F("<label for='pass_input_client'>Password:</label><input type='password' id='pass_input_client' name='password_plaintext_client' required>")); 
                    client.println(F("<input type='hidden' name='password_hash_client' value=''>"));
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
        
        
        
        uint8_t macBytes[6];
        sscanf(macPair.first.c_str(), "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
               &macBytes[0], &macBytes[1], &macBytes[2], &macBytes[3], &macBytes[4], &macBytes[5]);
        

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
      
      tft.printf("Session ...%02X%02X\n", sessionKey[14], sessionKey[15]);
  } else {
      
      
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
