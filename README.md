This is a working prototype without encryption and a reduced but still real echo problem. 6/22/25.

Project Goals:
Produce a secure way to spread information in high human density conditions. 
Obvious applications include protests and events where centralized infrastructure (eg. cell phone service) is unavailable or undesirable. Density of human requirement depends on speed information needs to spread. 
In a protest with a device every hundred feet it would be reliable and fast. If it's more dependant on people moving about it will be slower and less reliable. 
Could be a terrific way of spreading information in environments where cell phone use is discouraged but event communication is still required. 

How to use: 
When a properly installed ESP32 is powered on, it goes into AP mode and broadcasts a wireless network SSID called Protest_[last4ofMAC]
If one connects to this with any device and goes to 192.168.4.1 they will see recent meshnet communications and be allowed to send communications if they have a credential
If the particular ESP32 in question happens to have a screen (only tested with "The Cheap Yellow Display" 2.8" varient, for others, match pin-out of CYD) recent events are displayed here.
With this variation, things like a cell phone or laptop are not required to see information. If only supporting the meshnet a basic ESP32 will also do to help move along information. 
Outbound communications require going to any node's website and inputting a message. This would be for organizers. MAC filter could be removed in certain contexts and I'll try to eventually have both types. 

Tested hardware: 
Cheap Yellow Display (CYD) Model ESP32-2432S028
ESP32-WROM-32D (this is about as generic as they come, most any base ESP32 should work)

To write: 
Flashing the sketch
Troubleshooting
Desired Features
Known issues
