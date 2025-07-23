Protest Information Node Troubleshooting
This page provides solutions to common issues you might encounter while using your Protest Information Node. This guide focuses on actions an organizer can take.

Common Issues and Solutions
1. Cannot Connect to Node's Wi-Fi
Symptom: The ProtestInfo_XXXX Wi-Fi network is not visible.
Solution:

Ensure the node is powered on.

Wait a minute or two after powering on for the Wi-Fi to initialize.

Try moving closer to the node.

If still not visible, try rebooting the node (power off, then on).

Symptom: Can see the Wi-Fi network but cannot connect.
Solution:

Ensure you are selecting the correct ProtestInfo_XXXX network. There is no password for the Wi-Fi connection itself.

Try forgetting the network on your device and reconnecting.

Reboot your device (phone/computer) and then try connecting again.

2. Cannot Access the Web Interface
Symptom: The captive portal page does not open automatically after connecting to Wi-Fi.
Solution:

Open a web browser (Chrome, Firefox, Safari, etc.) and try to navigate to any website, such as http://example.com. If the automatic redirection doesn't work, directly type http://192.168.4.1 into your browser's address bar. This should redirect you to the node's web interface.

Ensure your device's Wi-Fi is connected to the ProtestInfo_XXXX network and not another network.

Clear your browser's cache or try a different browser.

Symptom: The web page loads, but looks broken or incomplete.
Solution:

Try refreshing the page multiple times.

Clear your browser's cache and cookies.

If the issue persists, reboot the node.

3. Messages Not Sending or Receiving
Symptom: Public messages cannot be sent.
Solution:

Public messaging is off by default. An organizer must enable it through the "Organizer Mode" section of the web interface.

If an organizer has previously "locked" public messaging off, it cannot be re-enabled without rebooting the board. Check the organizer page for status.

Symptom: Organizer messages cannot be sent.
Solution:

Ensure you are logged into "Organizer Mode."

The node's organizer password must be set (non-default). If it's a new node, set the initial organizer password first. If it was reset to 'password' after a reboot, you may need to re-log in or re-set it if it's the only node in the mesh.

Symptom: Messages are not appearing in the log or not spreading to other nodes.
Solution:

Ensure there are other nodes powered on and within range. The mesh relies on multiple nodes to spread messages.

Messages have a "Time-To-Live" (TTL). Very old messages or messages that have traveled many hops may expire.

Organizer messages are generally more reliably re-broadcast. Try sending an organizer message.

An organizer can initiate a "Re-broadcast Cache" action from the "Organizer Mode" to push out all cached messages again.

4. Organizer Mode Problems
Symptom: Cannot log in to Organizer Mode (incorrect password).
Solution:

Double-check the password. Remember it is case-sensitive.

If the password was recently changed on another node, this node might not have received the update yet. Wait a few minutes or try rebooting this node.

If you have made too many failed attempts, the login might be temporarily locked. Wait for the lockout period to expire (indicated on the page).

If you've forgotten the password, you must reboot the board to reset the organizer password to its default ('password').

Symptom: Cannot change the organizer password after initial setup.
Solution:

Once the organizer password is set on a node, it is locked for that session and cannot be changed via the web interface. This is a security feature.

To truly reset the organizer password to a new value across an entire mesh, all boards must be powered off first. Then, power on a single board, set the new password, and then power on the remaining boards.

To reset a single board's organizer password to the default 'password', you must physically reboot the board.

General Troubleshooting Tips
Reboot the Node: A simple power cycle (unplugging and re-plugging the power) can resolve many temporary issues.

Check Power Supply: Ensure the node has a stable power supply.

Monitor Serial Output: If you have the node connected to your computer via USB, open the Serial Monitor in Arduino IDE (set to 115200 baud) to see diagnostic messages. This is useful for advanced debugging.
