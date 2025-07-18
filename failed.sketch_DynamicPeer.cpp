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
#include <esp_mac.h>    // For ESP_MAC_WIFI_STA

#define USE_DISPLAY true

#if USE_DISPLAY
#include <TFT_eSPI.h>
TFT_eSPI tft = TFT_eSPI();
bool displayActive = false;

// Define the T_IRQ pin explicitly here for direct digitalRead debugging
#define TFT_TOUCH_IRQ_PIN 36 // Example: Change to 39 if your board uses GPIO39 for T_IRQ
#endif

const char* WEB_PASSWORD = "password"; // The password for accessing the message input

const int WIFI_CHANNEL = 1;

WiFiServer server(80);
IPAddress IP; // This will store the actual IP of the SoftAP (192.168.4.1)
String MAC_full_str; // Full MAC address of this ESP32 (e.g., "AA:BB:CC:DD:EE:FF")
String MAC_suffix_str; // Last 4 chars of our MAC (e.g., "EEFF")
String ssid; // Our unique SSID
uint8_t ourMacBytes[6];

String serialBuffer = "";         // Stores messages, most recent on top
String userMessageBuffer = "";  // To hold the user-entered message from POST
String webFeedbackMessage = ""; // To send messages back to the web client (e.g., success/error)

String organizerSessionToken = "";          // Stores the active organizer session token
unsigned long sessionTokenTimestamp = 0;    // Timestamp of when the token was created/last used
const unsigned long SESSION_TIMEOUT_MS = 900000; // Session timeout: 15 minutes
bool publicMessagingEnabled = false;

int loginAttempts = 0;
unsigned long lockoutTime = 0;
const int MAX_LOGIN_ATTEMPTS = 20;
const unsigned long LOCKOUT_DURATION_MS = 300000; // 5 minutes

const char* CMD_PREFIX = "CMD::";
const char* CMD_PUBLIC_ON = "CMD::PUBLIC_ON";
const char* CMD_PUBLIC_OFF = "CMD::PUBLIC_OFF";

unsigned long totalMessagesSent = 0;
unsigned long totalMessagesReceived = 0;
unsigned long totalUrgentMessages = 0;

unsigned long lastRebroadcast = 0; // Timestamp for last re-broadcast

int counter = 1; // Still used for the initial auto message

IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);

DNSServer dnsServer;

#define MAX_MESSAGE_CONTENT_LEN 239 // 250 (max ESP-NOW) - 4 (ID) - 6 (MAC) - 1 (TTL) = 239
#define MAX_TTL_HOPS 40 // Maximum Time-To-Live (hops) for a message

typedef struct __attribute__((packed)) {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  uint8_t ttl;
  char content[MAX_MESSAGE_CONTENT_LEN];
} esp_now_message_t;

struct SeenMessage {
  uint32_t messageID;
  uint8_t originalSenderMac[6];
  unsigned long timestamp;
  esp_now_message_t messageData;
};

std::vector<SeenMessage> seenMessages;
portMUX_TYPE seenMessagesMutex = portMUX_INITIALIZER_UNLOCKED;

const unsigned long DEDUP_CACHE_DURATION_MS = 600000; // 10 minutes
const size_t MAX_CACHE_SIZE = 50;
const unsigned long AUTO_REBROADCAST_INTERVAL_MS = 30000; // 30 seconds

QueueHandle_t messageQueue;
#define QUEUE_SIZE 10

// PEER DETECTION
std::vector<std::array<uint8_t, 6>> knownPeers;
portMUX_TYPE peersMutex = portMUX_INITIALIZER_UNLOCKED;

enum DisplayMode {
  MODE_CHAT_LOG,
  MODE_URGENT_ONLY,
  MODE_DEVICE_INFO,
  MODE_STATS_INFO
};
DisplayMode currentDisplayMode = MODE_CHAT_LOG;

unsigned long lastTouchTime = 0;
const unsigned long TOUCH_DEBOUNCE_MS = 500;

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
    seenMessages.erase(std::remove_if(seenMessages.begin(), seenMessages.end(),
                                     [currentTime](const SeenMessage& msg) {
                                         return (currentTime - msg.timestamp) > DEDUP_CACHE_DURATION_MS;
                                     }),
                      seenMessages.end());
    if (seenMessages.size() >= MAX_CACHE_SIZE) {
      auto oldest = std::min_element(seenMessages.begin(), seenMessages.end(),
                                     [](const SeenMessage& a, const SeenMessage& b) {
                                         return a.timestamp < b.timestamp;
                                     });
      if (oldest != seenMessages.end()) {
          seenMessages.erase(oldest);
      }
    }
    SeenMessage newMessage = {id, {0}, currentTime, msgData};
    memcpy(newMessage.originalSenderMac, mac, 6);
    seenMessages.push_back(newMessage);
  }
  portEXIT_CRITICAL(&seenMessagesMutex);
}

// Add peer MAC if not already in knownPeers, and add to ESP-NOW peer list.
void addPeerIfNew(const uint8_t* mac) {
  portENTER_CRITICAL(&peersMutex);
  for (const auto& peer : knownPeers) {
    if (memcmp(peer.data(), mac, 6) == 0) {
      portEXIT_CRITICAL(&peersMutex);
      return; // Already known
    }
  }
  std::array<uint8_t,6> peerMac;
  memcpy(peerMac.data(), mac, 6);
  knownPeers.push_back(peerMac);

  // Add to ESP-NOW peer list
  esp_now_peer_info_t peerInfo{};
  memcpy(peerInfo.peer_addr, mac, 6);
  peerInfo.channel = WIFI_CHANNEL;
  peerInfo.encrypt = false;
  esp_now_add_peer(&peerInfo);

  Serial.print("Added new peer: ");
  Serial.println(formatMac(mac));
  portEXIT_CRITICAL(&peersMutex);
}

void onDataRecv(const esp_now_recv_info *recvInfo, const uint8_t *data, int len) {
  if (len != sizeof(esp_now_message_t)) {
    return;
  }
  esp_now_message_t incomingMessage;
  memset(&incomingMessage, 0, sizeof(esp_now_message_t));
  memcpy(&incomingMessage, data, sizeof(esp_now_message_t));
  incomingMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0';

  // Detect and add peer MAC if new
  addPeerIfNew(incomingMessage.originalSenderMac);

  if (isMessageSeen(incomingMessage.messageID, incomingMessage.originalSenderMac)) {
    addOrUpdateMessageToSeen(incomingMessage.messageID, incomingMessage.originalSenderMac, incomingMessage);
    return;
  }
  
  addOrUpdateMessageToSeen(incomingMessage.messageID, incomingMessage.originalSenderMac, incomingMessage);

  totalMessagesReceived++;
  if (String(incomingMessage.content).indexOf("Urgent: ") != -1) {
      totalUrgentMessages++;
  }

  if (incomingMessage.ttl == 0) {
      return; 
  }

  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  if (xQueueSendFromISR(messageQueue, &incomingMessage, &xHigherPriorityTaskWoken) != pdPASS) {
    // Message dropped
  }
  if (xHigherPriorityTaskWoken == pdTRUE) {
    portYIELD_FROM_ISR();
  }
}

// Send to all known peers except self and original sender
void sendToAllPeers(esp_now_message_t message) {
  uint8_t currentMacBytes[6];
  memcpy(currentMacBytes, ourMacBytes, 6);

  if (message.ttl > 0) { 
      message.ttl--; 
  } else {
      Serial.println("Attempted to re-broadcast message with TTL 0. Skipping.");
      return;
  }

  portENTER_CRITICAL(&peersMutex);
  for (const auto& peer : knownPeers) {
    if (memcmp(peer.data(), message.originalSenderMac, 6) != 0 && memcmp(peer.data(), currentMacBytes, 6) != 0) {
      esp_now_send(peer.data(), (uint8_t*)&message, sizeof(esp_now_message_t));
    }
  }
  portEXIT_CRITICAL(&peersMutex);
}

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(0)); 

  publicMessagingEnabled = false;

  messageQueue = xQueueCreate(QUEUE_SIZE, sizeof(esp_now_message_t));
  if (messageQueue == NULL) {
    Serial.println("Failed to create message queue!");
    while(true) { delay(100); }
  }

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

  WiFi.softAPConfig(apIP, apIP, netMsk); 
  WiFi.softAP(ssid.c_str(), nullptr, WIFI_CHANNEL);
  IP = WiFi.softAPIP();
  server.begin();

  dnsServer.start(53, "*", apIP);
  Serial.println("DNS server started, redirecting all domains to: " + apIP.toString());

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
  displayChatLogMode(22);
#endif

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    while(true) { delay(100); }
  }

  // Add self as peer for completeness (optional, but will be skipped in send)
  addPeerIfNew(ourMacBytes);

  esp_now_register_recv_cb(onDataRecv);

  esp_now_message_t autoMessage;
  memset(&autoMessage, 0, sizeof(autoMessage)); 
  autoMessage.messageID = esp_random();
  memcpy(autoMessage.originalSenderMac, ourMacBytes, 6);
  autoMessage.ttl = MAX_TTL_HOPS;
  
  char msgContentBuf[MAX_MESSAGE_CONTENT_LEN];
  snprintf(msgContentBuf, sizeof(msgContentBuf), "Node %s initializing", MAC_suffix_str.c_str()); 
  
  strncpy(autoMessage.content, msgContentBuf, sizeof(autoMessage.content));
  autoMessage.content[sizeof(autoMessage.content) - 1] = '\0';

  String formattedMessage = "Node " + MAC_suffix_str + " - " + String(autoMessage.content);
  addOrUpdateMessageToSeen(autoMessage.messageID, autoMessage.originalSenderMac, autoMessage);

  serialBuffer = formattedMessage + "\n" + serialBuffer;
  Serial.println("Sending (Auto): " + formattedMessage);
  totalMessagesSent++;
  counter++;
  if (serialBuffer.length() > 4000)
    serialBuffer = serialBuffer.substring(0, 4000);
  sendToAllPeers(autoMessage);

  lastRebroadcast = millis();
}

void loop() {
  dnsServer.processNextRequest();

  esp_now_message_t receivedMessage;
  bool messageProcessed = false;
  while (xQueueReceive(messageQueue, &receivedMessage, 0) == pdPASS) {
    receivedMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0';
    String incomingContent = String(receivedMessage.content);
    String originalSenderMacSuffix = getMacSuffix(receivedMessage.originalSenderMac);

    if (incomingContent.startsWith(CMD_PREFIX)) {
        if (incomingContent.equals(CMD_PUBLIC_ON)) {
            if (!publicMessagingEnabled) {
                publicMessagingEnabled = true;
                Serial.println("Received command: ENABLE public messaging.");
                webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging was ENABLED by an organizer.</p>";
            }
        } else if (incomingContent.equals(CMD_PUBLIC_OFF)) {
            if (publicMessagingEnabled) {
                publicMessagingEnabled = false;
                Serial.println("Received command: DISABLE public messaging.");
                webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging was DISABLED by an organizer.</p>";
            }
        }
    }

    String formattedIncoming = "Node " + originalSenderMacSuffix + " - " + incomingContent;
    
    serialBuffer = formattedIncoming + "\n" + serialBuffer;
    if (serialBuffer.length() > 4000)
      serialBuffer = serialBuffer.substring(0, 4000);
    Serial.println("Message received from queue: " + formattedIncoming);
    messageProcessed = true;
    
    if (receivedMessage.ttl > 0) {  
        sendToAllPeers(receivedMessage);
    } else {
        Serial.println("Message reached TTL limit, not re-broadcasting.");
    }
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

    for (const auto& msg : messagesToRebroadcast) {
      sendToAllPeers(msg);
      addOrUpdateMessageToSeen(msg.messageID, msg.originalSenderMac, msg);
    }
  }

  WiFiClient client = server.available();
  if (client) {
    String currentLine = "";
    String postBody = "";
    bool isPost = false;
    unsigned long clientTimeout = millis();
    int contentLength = 0;
    String requestedPath = "/";

    while (client.connected() && (millis() - clientTimeout < 2000)) {
      if (client.available()) {
        clientTimeout = millis();
        char c = client.read();
        if (c == '\n') {
          if (currentLine.length() == 0) {
            String sessionTokenParam = "";
            bool isOrganizerRequest = false;

            // --- GET/POST and request path parsing ---
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
                int tokenStart = requestedPath.indexOf("session_token=");
                if (tokenStart != -1) {
                    sessionTokenParam = requestedPath.substring(tokenStart + 14);
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
                      client.println();
                      client.stop();
                      return;
                    } else if (lowerPath == "/hotspot-detect.html" || lowerPath == "/ncsi.txt" || lowerPath == "/connecttest.txt" || lowerPath == "/success.txt") {
                      client.println(F("HTTP/1.1 200 OK"));
                      client.println(F("Content-Type: text/plain"));
                      client.println(F("Connection: close"));
                      client.println();
                      client.println("Success");
                      client.stop();
                      return;
                    } else {
                      client.println(F("HTTP/1.1 200 OK"));
                      client.println(F("Content-Type: text/html"));
                      client.println(F("Connection: close"));
                      client.println();
                      client.println(F("<html><head><title>Success</title></head><body>Success</body></html>"));
                      client.stop();
                      return;
                    }
                  }
                }
                // --- END: Connectivity Check Response Patch ---
                // Handle captive portal redirect for non-root GETs
                if (requestedPath != "/" && requestedPath.indexOf("?show_public") == -1 && tokenStart == -1) {
                    Serial.println("Intercepted non-root GET request for: " + requestedPath + ". Redirecting to captive portal.");
                    client.println(F("HTTP/1.1 302 Found"));
                    client.println(F("Location: http://192.168.4.1/"));
                    client.println(F("Connection: close"));
                    client.println();
                    client.stop();
                    return;
                }
            }

            isOrganizerRequest = isOrganizerSessionValid(sessionTokenParam);

            if (isPost) {
              String messageParam = "", passwordParam = "", urgentParam = "", actionParam = "";
              int messageStart = postBody.indexOf("message=");
              if (messageStart != -1) {
                int messageEnd = postBody.indexOf('&', messageStart);
                if (messageEnd == -1) messageEnd = postBody.length();
                messageParam = postBody.substring(messageStart + 8, messageEnd);
              }
              int passwordStart = postBody.indexOf("password=");
              if (passwordStart != -1) {
                int passwordEnd = postBody.indexOf('&', passwordStart);
                if (passwordEnd == -1) passwordEnd = postBody.length();
                passwordParam = postBody.substring(passwordStart + 9, passwordEnd);
              }
              if (postBody.indexOf("urgent=on") != -1) { urgentParam = "on"; }
              int actionStart = postBody.indexOf("action=");
              if (actionStart != -1) {
                int actionEnd = postBody.indexOf('&', actionStart);
                if (actionEnd == -1) actionEnd = postBody.length();
                actionParam = postBody.substring(actionStart + 7, actionEnd);
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
              
              if (actionParam == "enterOrganizer") {
                  if (lockoutTime > 0 && millis() < lockoutTime) {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Too many failed attempts. Try again later.</p>";
                  } else {
                      if (lockoutTime > 0 && millis() >= lockoutTime) {
                          lockoutTime = 0;
                          loginAttempts = 0;
                      }
                      if (passwordParam == WEB_PASSWORD) {
                          loginAttempts = 0;
                          organizerSessionToken = String(esp_random()) + String(esp_random());
                          sessionTokenTimestamp = millis();
                          webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer Mode activated.</p>";
                          client.println(F("HTTP/1.1 303 See Other"));
                          client.println("Location: /?session_token=" + organizerSessionToken);
                          client.println(F("Connection: close"));
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
                      }
                  }
              } else if (actionParam == "exitOrganizer") {
                  if (isOrganizerRequest) {
                      organizerSessionToken = "";
                  }
                  webFeedbackMessage = "<p class='feedback' style='color:blue;'>Exited Organizer Mode.</p>";
              } else if (actionParam == "togglePublic") {
                  if (isOrganizerRequest) {
                      sessionTokenTimestamp = millis();
                      publicMessagingEnabled = !publicMessagingEnabled;
                      webFeedbackMessage = "<p class='feedback' style='color:blue;'>Public messaging has been " + String(publicMessagingEnabled ? "ENABLED" : "DISABLED") + ".</p>";
                      esp_now_message_t commandMessage;
                      memset(&commandMessage, 0, sizeof(commandMessage));
                      commandMessage.messageID = esp_random();
                      memcpy(commandMessage.originalSenderMac, ourMacBytes, 6);
                      commandMessage.ttl = MAX_TTL_HOPS;
                      const char* command = publicMessagingEnabled ? CMD_PUBLIC_ON : CMD_PUBLIC_OFF;
                      strncpy(commandMessage.content, command, MAX_MESSAGE_CONTENT_LEN);
                      commandMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0';
                      addOrUpdateMessageToSeen(commandMessage.messageID, commandMessage.originalSenderMac, commandMessage);
                      sendToAllPeers(commandMessage);
                      totalMessagesSent++;
                      serialBuffer = String("Node ") + MAC_suffix_str + " - " + command + "\n" + serialBuffer;
                      if (serialBuffer.length() > 4000) serialBuffer = serialBuffer.substring(0, 4000);
                      messageProcessed = true;
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Invalid or expired session.</p>";
                  }
              } else if (actionParam == "sendMessage") {
                  if (isOrganizerRequest) {
                      sessionTokenTimestamp = millis();
                      if (decodedMessage.length() == 0) {
                          webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>";
                      } else {
                          if (urgentParam == "on") { decodedMessage = "Urgent: " + decodedMessage; }
                          if (decodedMessage.length() >= MAX_MESSAGE_CONTENT_LEN) {
                              decodedMessage = decodedMessage.substring(0, MAX_MESSAGE_CONTENT_LEN - 1);
                          }
                          userMessageBuffer = decodedMessage;
                          webFeedbackMessage = "<p class='feedback' style='color:green;'>Organizer message queued!</p>";
                      }
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Invalid or expired session.</p>";
                  }
              } else if (actionParam == "sendPublicMessage") {
                  if (!publicMessagingEnabled) {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Public messaging is disabled.</p>";
                  } else if (decodedMessage.length() == 0) {
                      webFeedbackMessage = "<p class='feedback' style='color:orange;'>Please enter a message.</p>";
                  } else {
                      decodedMessage = "Public: " + decodedMessage;
                      if (decodedMessage.length() >= MAX_MESSAGE_CONTENT_LEN) {
                          decodedMessage = decodedMessage.substring(0, MAX_MESSAGE_CONTENT_LEN - 1);
                      }
                      userMessageBuffer = decodedMessage;
                      webFeedbackMessage = "<p class='feedback' style='color:green;'>Public message queued!</p>";
                  }
              } else if (actionParam == "rebroadcastCache") {
                  if (isOrganizerRequest) {
                      sessionTokenTimestamp = millis();
                      int rebroadcastedCount = 0;
                      portENTER_CRITICAL(&seenMessagesMutex);
                      std::vector<esp_now_message_t> toRebroadcast;
                      for (const auto& seenMsg : seenMessages) { if (seenMsg.messageData.ttl > 0) toRebroadcast.push_back(seenMsg.messageData); }
                      portEXIT_CRITICAL(&seenMessagesMutex);
                      for (const auto& msg : toRebroadcast) {
                          sendToAllPeers(msg);
                          addOrUpdateMessageToSeen(msg.messageID, msg.originalSenderMac, msg);
                          rebroadcastedCount++;
                      }
                      webFeedbackMessage = "<p class='feedback' style='color:green;'>Re-broadcasted " + String(rebroadcastedCount) + " messages!</p>";
                  } else {
                      webFeedbackMessage = "<p class='feedback' style='color:red;'>Error: Invalid or expired session.</p>";
                  }
              }

              client.println(F("HTTP/1.1 303 See Other"));
              String redirectUrl = "/";
              if (isOrganizerRequest) {
                  redirectUrl += "?session_token=" + sessionTokenParam;
              }
              client.println("Location: " + redirectUrl);
              client.println(F("Connection: close"));
              client.println();
              client.stop();
              return;
            }

            std::map<String, unsigned long> uniqueRecentMacsMap; 
            portENTER_CRITICAL(&seenMessagesMutex);
            for (const auto& seenMsg : seenMessages) {
                String fullMacStr = formatMac(seenMsg.originalSenderMac);
                if (uniqueRecentMacsMap.find(fullMacStr) == uniqueRecentMacsMap.end() || seenMsg.timestamp > uniqueRecentMacsMap[fullMacStr]) {
                    uniqueRecentMacsMap[fullMacStr] = seenMsg.timestamp;
                }
            }
            portEXIT_CRITICAL(&seenMessagesMutex);
            std::vector<std::pair<String, unsigned long>> sortedUniqueMacs;
            for (auto const& [macStr, timestamp] : uniqueRecentMacsMap) { sortedUniqueMacs.push_back({macStr, timestamp}); }
            std::sort(sortedUniqueMacs.begin(), sortedUniqueMacs.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

            String detectedNodesHtmlContent = "<div class='recent-senders-display-wrapper'><span class='detected-nodes-label'>Senders:</span><div class='detected-nodes-mac-list'>";
            int count = 0;
            for (const auto& macPair : sortedUniqueMacs) {
                if (count >= 4) break;
                uint8_t macBytes[6];
                sscanf(macPair.first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", (unsigned int*)&macBytes[0], (unsigned int*)&macBytes[1], (unsigned int*)&macBytes[2], (unsigned int*)&macBytes[3], (unsigned int*)&macBytes[4], (unsigned int*)&macBytes[5]);
                detectedNodesHtmlContent += "<span class='detected-node-item-compact'>" + formatMaskedMac(macBytes) + "</span>";
                count++;
            }
            if (count == 0) { detectedNodesHtmlContent += "<span class='detected-node-item-compact'>None</span>"; }
            detectedNodesHtmlContent += "</div></div>";

            client.println(F("HTTP/1.1 200 OK"));
            client.println(F("Content-type:text/html"));
            client.println(F("Connection: close"));
            client.println();
            client.println(F("<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Protest Info Node</title><style>"));
            client.println(F("body{font-family:Helvetica,Arial,sans-serif;margin:0;padding:0;background-color:#f8f8f8;color:#333;display:flex;flex-direction:column;min-height:100vh;}"));
            client.println(F("header{background-color:#f0f0f0;padding:10px 15px;border-bottom:1px solid #ddd;text-align:center;}"));
            client.println(F("h1,h2,h3{margin:0;padding:5px 0;color:#333;text-align:center;} h1{font-size:1.4em;} h2{font-size:1.2em;} h3{font-size:1.1em;margin-bottom:10px;}"));
            client.println(F("p{margin:3px 0;font-size:0.9em;text-align:center;} .info-line{font-size:0.8em;color:#666;margin-bottom:10px;}"));
            client.println(F(".content-wrapper{display:flex;flex-direction:column;align-items:center;width:100%;max-width:900px;margin:15px auto;padding:0 10px;flex-grow:1;}"));
            client.println(F(".chat-main-content{flex:1;width:100%;max-width:700px;margin:0 auto;background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);border:1px solid #ddd;}"));
            client.println(F("pre{background:#eee;padding:10px;border-radius:5px;text-align:left;max-width:100%;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;font-size:0.85em;border:1px solid #ccc;min-height:200px;}"));
            client.println(F("details, .form-container{background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);max-width:450px;margin:15px auto;border:1px solid #ddd;}"));
            client.println(F("summary{font-size:1.1em;font-weight:bold;cursor:pointer;padding:5px 0;text-align:center;}"));
            client.println(F("form{display:flex;flex-direction:column;align-items:center;margin-top:10px;}"));
            client.println(F("label{font-size:0.9em;margin-bottom:5px;align-self:flex-start;width:80%;}"));
            client.println(F("input[type=text],input[type=password]{width:80%;max-width:350px;padding:8px;margin-bottom:10px;border-radius:4px;border:1px solid #ccc;font-size:0.9em;}"));
            client.println(F("input[type=submit], .button-link{background-color:#007bff;color:white!important;padding:8px 15px;border:none;border-radius:4px;cursor:pointer;font-size:1em;transition:background-color 0.3s ease;text-decoration:none;display:inline-block;}"));
            client.println(F("input[type=submit]:hover, .button-link:hover{background-color:#0056b3;}"));
            client.println(F(".button-link.secondary{background-color:#6c757d;} .button-link.secondary:hover{background-color:#5a6268;}"));
            client.println(F("p.feedback{font-weight:bold;margin:10px auto;padding:8px;border-radius:5px;border:1px solid;max-width:90%;text-align:center;font-size:0.9em;}"));
            client.println(F("p.feedback[style*='color:green']{background-color:#e6ffe6;border-color:#00cc00;} p.feedback[style*='color:red']{background-color:#ffe6e6;border-color:#cc0000;}"));
            client.println(F("p.feedback[style*='color:orange']{background-color:#fff8e6;border-color:#ff9900;} p.feedback[style*='color:blue']{background-color:#e6f7ff;border-color:#007bff;}"));
            client.println(F(".recent-senders-display-wrapper{display:flex;flex-direction:column;align-items:center;width:100%;max-width:450px;background:#e6f7ff;border:1px solid #cceeff;border-radius:12px;padding:10px 15px;font-size:0.75em;color:#0056b3;margin:15px auto;}"));
            client.println(F(".detected-nodes-label{font-weight:bold;margin-bottom:5px;color:#003366;}"));
            client.println(F(".detected-nodes-mac-list{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;width:100%;}"));
            client.println(F("</style></head><body><header><h1>Protest Information Node</h1>"));
            client.printf("<p class='info-line'><strong>IP:</strong> %s | <strong>MAC:</strong> %s</p></header>", IP.toString().c_str(), MAC_suffix_str.c_str());
            client.println(F("<div class='content-wrapper'><div class='chat-main-content'>"));
            
            if (webFeedbackMessage.length() > 0) { client.println(webFeedbackMessage); webFeedbackMessage = ""; }
            
            bool showPublicView = (requestedPath.indexOf("?show_public=true") != -1);
            String displayedBuffer;
            String tempBuffer = serialBuffer;
            int lineStart = 0;
            while(lineStart < tempBuffer.length()){
                int lineEnd = tempBuffer.indexOf('\n', lineStart);
                if(lineEnd == -1) lineEnd = tempBuffer.length();
                String line = tempBuffer.substring(lineStart, lineEnd);
                if(line.indexOf("- Public: ") != -1 && !showPublicView) { /* skip */ }
                else { 
                    displayedBuffer += escapeHtml(line) + "\n"; 
                }
                lineStart = lineEnd + 1;
            }
            client.println(F("<h2>Serial Data Log:</h2><pre>"));
            client.print(displayedBuffer);
            client.println(F("</pre>"));

            client.println(F("<div style='text-align:center; margin: 15px;'>"));
            String publicLink = showPublicView ? "/" : "/?show_public=true";
            if (isOrganizerRequest) { publicLink += (showPublicView ? "?" : "&") + String("session_token=") + sessionTokenParam; }
            client.print("<a href='" + publicLink + "' class='button-link" + (showPublicView ? " secondary" : "") + "'>");
            client.print(showPublicView ? "Hide Public Messages" : "Show Public Messages");
            client.println("</a></div>");

            if(isOrganizerRequest) {
                client.println(F("<details open><summary>Organizer Controls</summary>"));
                client.println(F("<div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                client.println(F("<h3>Send Organizer Message:</h3><form action='/' method='POST'><input type='hidden' name='action' value='sendMessage'>"));
                client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                client.println(F("<label for='msg_input'>Message:</label><input type='text' id='msg_input' name='message' required maxlength='226'>"));
                client.println(F("<div style='display:flex;align-items:center;justify-content:center;width:80%;margin-bottom:10px;'><input type='checkbox' id='urgent_input' name='urgent' value='on' style='margin-right:8px;'><label for='urgent_input' style='margin-bottom:0;'>Urgent</label></div>"));
                client.println(F("<input type='submit' value='Send Message'></form></div>"));
                
                client.println(F("<div class='form-container' style='box-shadow:none;border:none;padding-top:5px;margin-top:5px;'><h3>Admin Actions</h3>"));
                client.println(F("<form action='/' method='POST' style='flex-direction:row;justify-content:center;gap:10px;'>"));
                client.println(F("<input type='hidden' name='action' value='rebroadcastCache'>"));
                client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                client.println(F("<input type='submit' value='Re-broadcast Cache'></form>"));
                client.println(F("<form action='/' method='POST' style='flex-direction:row;justify-content:center;gap:10px;margin-top:10px;'>"));
                client.println(F("<input type='hidden' name='action' value='togglePublic'>"));
                client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                client.print(F("<input type='submit' value='"));
                client.print(publicMessagingEnabled ? "Disable Public Msgs" : "Enable Public Msgs");
                client.println(F("'></form>"));
                client.println(F("<form action='/' method='POST' style='margin-top:10px;'><input type='hidden' name='action' value='exitOrganizer'>"));
                client.printf("<input type='hidden' name='session_token' value='%s'>", sessionTokenParam.c_str());
                client.println(F("<input type='submit' value='Exit Organizer Mode' class='button-link secondary' style='background-color:#dc3545;'></form>"));
                client.println(F("</div></details>"));
            } else {
                client.println(F("<details><summary>Enter Organizer Mode</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                client.println(F("<form action='/' method='POST'><input type='hidden' name='action' value='enterOrganizer'>"));
                client.println(F("<label for='pass_input'>Password:</label><input type='password' id='pass_input' name='password' required>"));
                client.println(F("<input type='submit' value='Enter Mode'></form></div></details>"));
                if(publicMessagingEnabled) {
                    client.println(F("<details><summary>Send a Public Message</summary><div class='form-container' style='box-shadow:none;border:none;padding-top:5px;'>"));
                    client.println(F("<h3>Message (no password required):</h3><form action='/' method='POST'><input type='hidden' name='action' value='sendPublicMessage'>"));
                    client.println(F("<label for='pub_msg_input'>Message:</label><input type='text' id='pub_msg_input' name='message' required maxlength='226'>"));
                    client.println(F("<input type='submit' value='Send Public Message'></form></div></details>"));
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
              if (contentLength > 2048) {
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

  if (userMessageBuffer.length() > 0) {
    esp_now_message_t userEspNowMessage;
    memset(&userEspNowMessage, 0, sizeof(userEspNowMessage)); 
    userEspNowMessage.messageID = esp_random();
    memcpy(userEspNowMessage.originalSenderMac, ourMacBytes, 6);
    userEspNowMessage.ttl = MAX_TTL_HOPS;
    
    strncpy(userEspNowMessage.content, userMessageBuffer.c_str(), MAX_MESSAGE_CONTENT_LEN);
    userEspNowMessage.content[MAX_MESSAGE_CONTENT_LEN - 1] = '\0';

    if (userMessageBuffer.startsWith("Urgent: ") || userMessageBuffer.startsWith("Public: Urgent: ")) { 
        totalUrgentMessages++; 
    }
    
    String messageToSendFormatted = "User via Node " + MAC_suffix_str + " - " + userMessageBuffer;
    
    addOrUpdateMessageToSeen(userEspNowMessage.messageID, userEspNowMessage.originalSenderMac, userEspNowMessage);

    serialBuffer = messageToSendFormatted + "\n" + serialBuffer;
    Serial.println("Broadcasting (User): " + messageToSendFormatted);
    totalMessagesSent++;
    if (serialBuffer.length() > 4000)
      serialBuffer = serialBuffer.substring(0, 4000);
    sendToAllPeers(userEspNowMessage);
    messageProcessed = true;
    userMessageBuffer = "";
  }

#if USE_DISPLAY
  if (digitalRead(TFT_TOUCH_IRQ_PIN) == LOW && (millis() - lastTouchTime > TOUCH_DEBOUNCE_MS)) {
    lastTouchTime = millis();
    Serial.println("Touch detected! Switching display mode.");

    if (currentDisplayMode == MODE_CHAT_LOG) {
      currentDisplayMode = MODE_URGENT_ONLY;
      displayUrgentOnlyMode(22);
    } else if (currentDisplayMode == MODE_URGENT_ONLY) {
      currentDisplayMode = MODE_DEVICE_INFO;
      displayDeviceInfoMode();
    } else if (currentDisplayMode == MODE_DEVICE_INFO) {
      currentDisplayMode = MODE_STATS_INFO;
      displayStatsInfoMode();
    }
    else {
      currentDisplayMode = MODE_CHAT_LOG;
      displayChatLogMode(22);
    }
  }

  if (messageProcessed) {
    if (currentDisplayMode == MODE_CHAT_LOG) {
      displayChatLogMode(22);
    } else if (currentDisplayMode == MODE_URGENT_ONLY) {
      displayUrgentOnlyMode(22);
    } else if (currentDisplayMode == MODE_STATS_INFO) {
      displayStatsInfoMode();
    } else if (currentDisplayMode == MODE_DEVICE_INFO) {
        displayDeviceInfoMode();
    }
  }
#endif
}

#if USE_DISPLAY
void displayChatLogMode(int numLines) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString());
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: All Messages");
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  int linesPrinted = 0;
  int lineStart = 0;
  while (linesPrinted < numLines && lineStart < serialBuffer.length()) {
    int lineEnd = serialBuffer.indexOf('\n', lineStart);
    if (lineEnd == -1) lineEnd = serialBuffer.length();
    String line = serialBuffer.substring(lineStart, lineEnd);
    tft.println(line);
    lineStart = lineEnd + 1;
    linesPrinted++;
  }
}

void displayUrgentOnlyMode(int numLines) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString());
  tft.setTextColor(TFT_GREEN);        tft.println("Mode: Urgent Only");
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  
  int linesPrinted = 0;
  int lineStart = 0;
  while (linesPrinted < numLines && lineStart < serialBuffer.length()) {
    int lineEnd = serialBuffer.indexOf('\n', lineStart);
    if (lineEnd == -1) lineEnd = serialBuffer.length();
    String line = serialBuffer.substring(lineStart, lineEnd);
    
    if (line.indexOf("Urgent: ") != -1) {
      tft.println(line);
      linesPrinted++;
    }
    lineStart = lineEnd + 1;
  }
}

void displayDeviceInfoMode() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString());
  tft.setTextColor(TFT_GREEN);      tft.println("Mode: Device Info");
  
  tft.setTextColor(TFT_WHITE);     tft.println("----------------------");
  tft.println("Nearby Nodes (Last Seen):");

  std::map<String, unsigned long> uniqueRecentMacsMap; 
  uint8_t selfMacBytes[6]; 
  memcpy(selfMacBytes, ourMacBytes, 6);

  portENTER_CRITICAL(&seenMessagesMutex);
  for (const auto& seenMsg : seenMessages) {
      if (memcmp(seenMsg.originalSenderMac, selfMacBytes, 6) != 0) {
          String fullMacStr = formatMac(seenMsg.originalSenderMac);
          if (uniqueRecentMacsMap.find(fullMacStr) == uniqueRecentMacsMap.end() || seenMsg.timestamp > uniqueRecentMacsMap[fullMacStr]) {
              uniqueRecentMacsMap[fullMacStr] = seenMsg.timestamp;
          }
      }
  }
  portEXIT_CRITICAL(&seenMessagesMutex);

  std::vector<std::pair<String, unsigned long>> sortedUniqueMacs;
  for (auto const& [macStr, timestamp] : uniqueRecentMacsMap) { sortedUniqueMacs.push_back({macStr, timestamp}); }

  std::sort(sortedUniqueMacs.begin(), sortedUniqueMacs.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

  int linesPrinted = 0;
  const int MAX_NODES_TO_DISPLAY = 15; 
  if (sortedUniqueMacs.empty()) {
    tft.println("  No other nodes detected yet.");
  } else {
    for (const auto& macPair : sortedUniqueMacs) {
        if (linesPrinted >= MAX_NODES_TO_DISPLAY) break;
        uint8_t macBytes[6];
        sscanf(macPair.first.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", (unsigned int*)&macBytes[0], (unsigned int*)&macBytes[1], (unsigned int*)&macBytes[2], (unsigned int*)&macBytes[3], (unsigned int*)&macBytes[4], (unsigned int*)&macBytes[5]);
        
        tft.printf("  %s (seen %lu s ago)\n", formatMaskedMac(macBytes).c_str(), (millis() - macPair.second) / 1000);
        linesPrinted++;
    }
  }
}

void displayStatsInfoMode() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_GREEN);      tft.println("MAC: " + MAC_full_str);
  tft.setTextColor(TFT_GREEN);     tft.println("IP: " + IP.toString());
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
}
#endif
