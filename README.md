Protest Information Node — User Guide
Overview
The Protest Information Node is a self-contained mesh device that lets participants share and view text messages, monitor network health, and detect jamming or infiltration attempts—all via a simple captive-portal web interface and onboard TFT display.

Getting Started
Power the node (5 V via USB or VIN).

The node boots into a Wi-Fi SoftAP named ProtestInfo_<XXYY> (last two bytes of its MAC).

Connect your phone or laptop to that SSID—no password required.

Open any web browser; you’ll be redirected to the node’s web UI (http://192.168.4.1).

Web Interface
Header & Status
IP & MAC: Shown at the top.

Non-Violence Reminder: Always displayed.

Public Warning: If public messaging is enabled, a “Public messages are unmoderated” alert appears.

Jamming/Infiltration Alerts: Red or amber banners show when the mesh detects interference or conflicting password updates.

Message Log & Filters
Serial Data Log: Scrollable area showing the most recent messages (newest at the top).

Show/Hide Public: Toggle display of Public: messages.

Only Urgent/Show All: Filter for messages prefixed with Urgent:.

Hide/Show System: Organizer-only control to hide system-generated entries.

Organizer Mode
Initial Setup
On first boot the organizer password is set to the default "password".

You may immediately enter Organizer Mode and choose a new mesh-wide password.

Entering Organizer Mode
Expand Enter Organizer Mode.

Submit the current organizer password.

Once authenticated, you’ll see Organizer Controls.

Organizer Controls
Send Organizer Message

Enter text (max 214 chars).

Check Urgent to prefix with Urgent:.

Click Send Message to broadcast.

Admin Actions

Re-broadcast Cache: Flood the mesh with recent messages still under TTL.

Enable/Disable Public Msgs: Toggle and lock public messaging across the mesh.

Security & Password

View total jamming incidents, checksum failures, and infiltration attempts since boot.

Expand logs for recent failure IDs and MACs of suspicious password updates.

Set/Reset Organizer Password (once only per boot): Choose and confirm a new password. After setting, the default is permanently locked until reboot, and the new password propagates mesh-wide.

Exit Organizer Mode: Log out to return to the public view.

Public Messaging
If organizers have enabled public messaging, anyone can send public messages without logging in:

Expand Send a Public Message.

Enter text (max 214 chars).

Click Send Public Message.

Detected Nodes
At the bottom of the main page you’ll see up to four of the most recently seen peers, masked as xxxx.xxxx.xxxx.<suffix>. This updates in real time as mesh devices discover one another.

TFT Display (Touch-Enabled--optional, non-screen devices work fine)
Touch the screen to cycle through four modes:

All Messages: Scrolls the full chat log.

Urgent Only: Displays only messages beginning with Urgent:.

Device Info: Lists nearby nodes and seconds since last seen.

Stats Info: Shows uptime, total sent/received, urgent count, cache size, AP clients, public-messaging status, and security counters.

The display refreshes every 10 seconds; touch events are debounced at 500 ms.

Mesh Behavior & Diagnostics
Automatic Discovery: Every 15 s a discovery broadcast resets the peer list.

Auto-Rebroadcast: Every 30 s, messages still under TTL are re-flooded.

Jamming Detection: If no messages arrive from any peer for 60 s, a jamming alert logs locally and broadcasts a JAMMING_ALERT.

Infiltration Detection: Conflicting password updates within 5 minutes trigger an infiltration alert and log the offending MAC.

Checksum Logging: Failed decrypt/checksum events increment a counter and store details in NVS for forensic review.
