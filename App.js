import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  View,
  SafeAreaView,
  Platform,
  StatusBar,
  Text,
  Modal,
  Pressable,
  ActivityIndicator,
  Linking,
  Image,
  ScrollView,
  Alert,
} from 'react-native';
import { WebView } from 'react-native-webview';
import AsyncStorage from '@react-native-async-storage/async-storage';

// --- Configuration ---
const DEVICE_URL_SECURE = 'https://192.168.4.1:1984';
const DEVICE_URL_INSECURE = 'http://192.168.4.1:80';
const GUIDE_STORAGE_KEY = '@guide_dismissed';
const TRUSTED_CERTS_KEY = '@trusted_certificates';
const USE_INSECURE_KEY = '@use_insecure_connection';
// ---------------------

const LoadingIndicator = () => (
  <View style={styles.loadingContainer}>
    <ActivityIndicator size="large" color="#007bff" />
    <Text style={styles.loadingText}>Connecting to device...</Text>
    <Text style={styles.loadingSubText}>
      Make sure you are on the "ProtestInfo_..." Wi-Fi
    </Text>
  </View>
);

export default function App() {
  const [isGuideVisible, setGuideVisible] = useState(false);
  const [isHelpVisible, setHelpVisible] = useState(false);
  const [isMenuVisible, setMenuVisible] = useState(false);
  const [webViewKey, setWebViewKey] = useState(0);
  const [certDialogVisible, setCertDialogVisible] = useState(false);
  const [pendingCert, setPendingCert] = useState(null);
  const [trustedCerts, setTrustedCerts] = useState({});
  const [hasError, setHasError] = useState(false);
  const [useInsecure, setUseInsecure] = useState(false);
  const [insecureDialogVisible, setInsecureDialogVisible] = useState(false);
  const [sslErrorCount, setSslErrorCount] = useState(0);

  const currentUrl = useInsecure ? DEVICE_URL_INSECURE : DEVICE_URL_SECURE;

  useEffect(() => {
    const checkGuideStatus = async () => {
      try {
        const value = await AsyncStorage.getItem(GUIDE_STORAGE_KEY);
        if (value === null) {
          setGuideVisible(true);
        }
      } catch (e) {
        console.error('Failed to read AsyncStorage', e);
        setGuideVisible(true);
      }
    };
    
    const loadTrustedCerts = async () => {
      try {
        const stored = await AsyncStorage.getItem(TRUSTED_CERTS_KEY);
        if (stored) {
          setTrustedCerts(JSON.parse(stored));
        }
      } catch (e) {
        console.error('Failed to load trusted certs', e);
      }
    };

    const loadInsecureSetting = async () => {
      try {
        const stored = await AsyncStorage.getItem(USE_INSECURE_KEY);
        if (stored === 'true') {
          setUseInsecure(true);
        }
      } catch (e) {
        console.error('Failed to load insecure setting', e);
      }
    };
    
    checkGuideStatus();
    loadTrustedCerts();
    loadInsecureSetting();
  }, []);

  const saveTrustedCerts = async (certs) => {
    try {
      await AsyncStorage.setItem(TRUSTED_CERTS_KEY, JSON.stringify(certs));
      setTrustedCerts(certs);
    } catch (e) {
      console.error('Failed to save trusted certs', e);
    }
  };

  const saveInsecureSetting = async (value) => {
    try {
      await AsyncStorage.setItem(USE_INSECURE_KEY, value.toString());
      setUseInsecure(value);
    } catch (e) {
      console.error('Failed to save insecure setting', e);
    }
  };

  const dismissGuide = async () => {
    try {
      await AsyncStorage.setItem(GUIDE_STORAGE_KEY, 'true');
      setGuideVisible(false);
    } catch (e) {
      console.error('Failed to save to AsyncStorage', e);
      setGuideVisible(false);
    }
  };

  const openWifiSettings = () => {
    if (Platform.OS === 'ios') {
      Linking.openURL('App-Prefs:WIFI');
    } else {
      Linking.sendIntent('android.settings.WIFI_SETTINGS');
    }
  };

  const getCertFingerprint = (cert) => {
    // In a real implementation, this would parse the cert and get SHA256 fingerprint
    // For now, we'll use a simplified version based on cert properties
    if (!cert) return null;
    
    // Android WebView provides cert info in nativeEvent.certificate
    const certData = cert.subject + cert.issuer + cert.notBefore + cert.notAfter;
    return certData; // In production, hash this with SHA256
  };

  const handleWebViewError = (syntheticEvent) => {
    const { nativeEvent } = syntheticEvent;
    console.warn('WebView error: ', nativeEvent);
    setHasError(true);
    
    // Check if it's an SSL error
    if (nativeEvent.code === -1200 || // iOS SSL error
        nativeEvent.description?.includes('SSL') ||
        nativeEvent.description?.includes('certificate') ||
        nativeEvent.description?.includes('HTTPS')) {
      
      // Increment SSL error count
      const newCount = sslErrorCount + 1;
      setSslErrorCount(newCount);

      // After 2 SSL errors, offer to switch to HTTP
      if (newCount >= 2 && !useInsecure) {
        setInsecureDialogVisible(true);
        return;
      }

      // Extract certificate info if available
      const cert = nativeEvent.certificate || {
        subject: nativeEvent.url || DEVICE_URL_SECURE,
        issuer: 'Self-signed',
        notBefore: new Date().toISOString(),
        notAfter: new Date(Date.now() + 365*24*60*60*1000).toISOString(),
      };
      
      const fingerprint = getCertFingerprint(cert);
      
      // Check if we've already trusted this cert
      if (trustedCerts[fingerprint]) {
        // Cert is trusted, reload WebView
        setWebViewKey(prevKey => prevKey + 1);
        return;
      }
      
      // Show cert verification dialog
      setPendingCert({ ...cert, fingerprint });
      setCertDialogVisible(true);
    }
  };

  const handleCertTrust = async (trustLevel) => {
    if (!pendingCert) return;
    
    if (trustLevel === 'always') {
      const newTrustedCerts = {
        ...trustedCerts,
        [pendingCert.fingerprint]: {
          cert: pendingCert,
          trustedAt: new Date().toISOString(),
        }
      };
      await saveTrustedCerts(newTrustedCerts);
    }
    
    if (trustLevel !== 'no') {
      // Trust this time or always - reload WebView
      setCertDialogVisible(false);
      setPendingCert(null);
      setHasError(false);
      setWebViewKey(prevKey => prevKey + 1);
    } else {
      // User rejected cert
      setCertDialogVisible(false);
      setPendingCert(null);
      Alert.alert(
        'Connection Rejected',
        'The certificate was not trusted. Cannot connect to the device.',
        [{ text: 'OK' }]
      );
    }
  };

  const handleInsecureChoice = async (choice) => {
    if (choice === 'yes') {
      await saveInsecureSetting(true);
      setInsecureDialogVisible(false);
      setHasError(false);
      setSslErrorCount(0);
      setWebViewKey(prevKey => prevKey + 1);
    } else {
      setInsecureDialogVisible(false);
      Alert.alert(
        'Secure Connection Required',
        'The app will continue to use HTTPS. Please ensure your device has a valid certificate.',
        [{ text: 'OK' }]
      );
    }
  };

  const switchToSecure = async () => {
    Alert.alert(
      'Switch to HTTPS',
      'This will switch back to the secure HTTPS connection. You may need to trust the certificate again.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Switch to HTTPS',
          onPress: async () => {
            await saveInsecureSetting(false);
            setSslErrorCount(0);
            setWebViewKey(prevKey => prevKey + 1);
          },
        },
      ]
    );
  };

  const clearTrustedCerts = async () => {
    Alert.alert(
      'Clear Trusted Certificates',
      'This will remove all trusted device certificates. You will need to verify them again on next connection.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear All',
          style: 'destructive',
          onPress: async () => {
            await saveTrustedCerts({});
            Alert.alert('Success', 'All trusted certificates have been cleared.');
          },
        },
      ]
    );
  };

  const resetApp = async () => {
    Alert.alert(
      'Reset App',
      'This will clear all settings and trusted certificates. The welcome guide will show again.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Reset',
          style: 'destructive',
          onPress: async () => {
            try {
              await AsyncStorage.removeItem(GUIDE_STORAGE_KEY);
              await AsyncStorage.removeItem(TRUSTED_CERTS_KEY);
              await AsyncStorage.removeItem(USE_INSECURE_KEY);
              setTrustedCerts({});
              setUseInsecure(false);
              setSslErrorCount(0);
              setGuideVisible(true);
              setMenuVisible(false);
              setWebViewKey(prevKey => prevKey + 1);
            } catch (e) {
              console.error('Failed to reset app', e);
            }
          },
        },
      ]
    );
  };

  const formatDate = (dateStr) => {
    try {
      return new Date(dateStr).toLocaleDateString();
    } catch {
      return dateStr;
    }
  };

  const retryConnection = () => {
    setHasError(false);
    setWebViewKey(prevKey => prevKey + 1);
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#333" />

      {/* Header with Menu Button */}
      <View style={styles.header}>
        <Image
          source={require('./icon.png')}
          style={styles.headerLogo}
          resizeMode="contain"
        />
        <View style={styles.headerTitleContainer}>
          <Text style={styles.headerTitle}>ProtestInfo Organizer</Text>
          {useInsecure && (
            <View style={styles.insecureBadge}>
              <Text style={styles.insecureBadgeText}>⚠️ HTTP</Text>
            </View>
          )}
        </View>
        <Pressable
          style={styles.menuButton}
          onPress={() => setMenuVisible(true)}
        >
          <Text style={styles.menuButtonText}>☰</Text>
        </Pressable>
      </View>

      <WebView
        key={webViewKey}
        style={styles.webview}
        source={{ uri: currentUrl }}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        pullToRefreshEnabled={true}
        startInLoadingState={true}
        renderLoading={LoadingIndicator}
        onError={handleWebViewError}
        onHttpError={handleWebViewError}
        onRefresh={() => setWebViewKey(prevKey => prevKey + 1)}
        onShouldStartLoadWithRequest={(request) => true}
        onLoadEnd={() => setHasError(false)}
        ignoreSslError={false}
        allowsInlineMediaPlayback={true}
        mediaPlaybackRequiresUserAction={false}
      />

      {/* Error Overlay */}
      {hasError && !certDialogVisible && !insecureDialogVisible && (
        <View style={styles.errorOverlay}>
          <Text style={styles.errorIcon}>⚠️</Text>
          <Text style={styles.errorTitle}>Connection Error</Text>
          <Text style={styles.errorText}>
            Unable to connect to the ProtestInfo device.
          </Text>
          <Text style={styles.errorSubText}>
            Make sure you're connected to the ProtestInfo_... Wi-Fi network.
          </Text>
          <Pressable style={styles.errorButton} onPress={retryConnection}>
            <Text style={styles.errorButtonText}>Retry Connection</Text>
          </Pressable>
          <Pressable style={styles.errorButtonSecondary} onPress={openWifiSettings}>
            <Text style={styles.errorButtonSecondaryText}>Open Wi-Fi Settings</Text>
          </Pressable>
        </View>
      )}

      {/* Menu Modal */}
      <Modal
        animationType="slide"
        transparent={true}
        visible={isMenuVisible}
        onRequestClose={() => setMenuVisible(false)}
      >
        <View style={styles.menuModalView}>
          <View style={styles.menuContent}>
            <View style={styles.menuHeader}>
              <Text style={styles.menuTitle}>Menu</Text>
              <Pressable onPress={() => setMenuVisible(false)}>
                <Text style={styles.menuClose}>✕</Text>
              </Pressable>
            </View>

            <ScrollView style={styles.menuItems} contentContainerStyle={{paddingBottom: 20}}>
              <Pressable
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  setGuideVisible(true);
                }}
              >
                <Text style={styles.menuItemIcon}>📖</Text>
                <Text style={styles.menuItemText}>Show Welcome Guide</Text>
              </Pressable>

              <Pressable
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  setHelpVisible(true);
                }}
              >
                <Text style={styles.menuItemIcon}>❓</Text>
                <Text style={styles.menuItemText}>Help & Usage Guide</Text>
              </Pressable>

              <Pressable
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  retryConnection();
                }}
              >
                <Text style={styles.menuItemIcon}>🔄</Text>
                <Text style={styles.menuItemText}>Reload Connection</Text>
              </Pressable>

              <Pressable
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  openWifiSettings();
                }}
              >
                <Text style={styles.menuItemIcon}>📶</Text>
                <Text style={styles.menuItemText}>Wi-Fi Settings</Text>
              </Pressable>

              <View style={styles.menuDivider} />

              <View style={styles.menuSection}>
                <Text style={styles.menuSectionTitle}>Security</Text>
                <Text style={styles.menuSectionSubtitle}>
                  Connection: {useInsecure ? 'HTTP (Insecure)' : 'HTTPS (Secure)'}
                </Text>
                <Text style={styles.menuSectionSubtitle}>
                  {Object.keys(trustedCerts).length} trusted certificate(s)
                </Text>
              </View>

              {useInsecure && (
                <Pressable
                  style={styles.menuItem}
                  onPress={() => {
                    setMenuVisible(false);
                    switchToSecure();
                  }}
                >
                  <Text style={styles.menuItemIcon}>🔒</Text>
                  <Text style={styles.menuItemText}>Switch to HTTPS</Text>
                </Pressable>
              )}

              <Pressable
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  clearTrustedCerts();
                }}
              >
                <Text style={styles.menuItemIcon}>🔓</Text>
                <Text style={styles.menuItemText}>Clear Trusted Certificates</Text>
              </Pressable>

              <View style={styles.menuDivider} />

              <Pressable
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  resetApp();
                }}
              >
                <Text style={styles.menuItemIcon}>⚠️</Text>
                <Text style={[styles.menuItemText, styles.menuItemDanger]}>
                  Reset App
                </Text>
              </Pressable>
            </ScrollView>

            <View style={styles.menuFooter}>
              <Text style={styles.menuFooterText}>ProtestInfo Organizer v1.0</Text>
            </View>
          </View>
        </View>
      </Modal>

      {/* Insecure Connection Dialog */}
      <Modal
        animationType="fade"
        transparent={true}
        visible={insecureDialogVisible}
        onRequestClose={() => handleInsecureChoice('no')}
      >
        <View style={styles.modalCenteredView}>
          <View style={styles.certModalView}>
            <Text style={styles.certModalTitle}>⚠️ HTTPS Connection Failed</Text>
            <Text style={styles.certModalText}>
              Unable to establish a secure HTTPS connection to the device.
            </Text>
            
            <View style={styles.certWarning}>
              <Text style={styles.certWarningText}>
                ⚠️ WARNING: Using HTTP (unencrypted) connections exposes your data to potential interception.
                Only proceed if you trust the network you're on.
              </Text>
            </View>

            <Text style={styles.insecureExplanation}>
              Do you want to fall back to an insecure HTTP connection?
            </Text>

            <View style={styles.certButtonContainer}>
              <Pressable
                style={[styles.certButton, styles.certButtonNo]}
                onPress={() => handleInsecureChoice('no')}
              >
                <Text style={styles.certButtonText}>No, Stay Secure</Text>
              </Pressable>
              
              <Pressable
                style={[styles.certButton, styles.insecureButton]}
                onPress={() => handleInsecureChoice('yes')}
              >
                <Text style={styles.certButtonText}>Yes, Use HTTP</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Certificate Verification Dialog */}
      <Modal
        animationType="fade"
        transparent={true}
        visible={certDialogVisible}
        onRequestClose={() => handleCertTrust('no')}
      >
        <View style={styles.modalCenteredView}>
          <View style={styles.certModalView}>
            <Text style={styles.certModalTitle}>⚠️ Unknown Certificate</Text>
            <Text style={styles.certModalText}>
              This device is using a certificate that hasn't been verified before.
            </Text>
            
            <ScrollView style={styles.certDetails}>
              <Text style={styles.certDetailLabel}>Subject:</Text>
              <Text style={styles.certDetailValue}>{pendingCert?.subject}</Text>
              
              <Text style={styles.certDetailLabel}>Issuer:</Text>
              <Text style={styles.certDetailValue}>{pendingCert?.issuer}</Text>
              
              <Text style={styles.certDetailLabel}>Valid From:</Text>
              <Text style={styles.certDetailValue}>{formatDate(pendingCert?.notBefore)}</Text>
              
              <Text style={styles.certDetailLabel}>Valid Until:</Text>
              <Text style={styles.certDetailValue}>{formatDate(pendingCert?.notAfter)}</Text>
            </ScrollView>

            <View style={styles.certWarning}>
              <Text style={styles.certWarningText}>
                ⚠️ Only trust this certificate if you're connecting to your own ProtestInfo device.
                Unknown certificates could indicate a man-in-the-middle attack.
              </Text>
            </View>

            <View style={styles.certButtonContainer}>
              <Pressable
                style={[styles.certButton, styles.certButtonAlways]}
                onPress={() => handleCertTrust('always')}
              >
                <Text style={styles.certButtonText}>Always Trust</Text>
              </Pressable>
              
              <Pressable
                style={[styles.certButton, styles.certButtonOnce]}
                onPress={() => handleCertTrust('once')}
              >
                <Text style={styles.certButtonText}>Trust This Time</Text>
              </Pressable>
              
              <Pressable
                style={[styles.certButton, styles.certButtonNo]}
                onPress={() => handleCertTrust('no')}
              >
                <Text style={styles.certButtonText}>Don't Trust</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Welcome Guide Modal */}
      <Modal
        animationType="slide"
        transparent={true}
        visible={isGuideVisible}
        onRequestClose={dismissGuide}
      >
        <View style={styles.modalCenteredView}>
          <View style={styles.modalView}>
            <View style={styles.logoContainer}>
              <Text style={styles.logoPlaceholder}>ℹ️</Text>
            </View>

            <Text style={styles.modalTitle}>Welcome!</Text>
            <Text style={styles.modalText}>
              To use this app, you must connect your phone directly to the
              ProtestInfo device's Wi-Fi network.
            </Text>

            <View style={styles.modalSteps}>
              <Text style={styles.modalStep}>1. Go to your phone's Wi-Fi Settings.</Text>
              <Text style={styles.modalStep}>
                2. Connect to the network named:{'\n'}
                <Text style={styles.modalHighlight}>ProtestInfo_XXXX</Text>
              </Text>
              <Text style={styles.modalStep}>3. Return to this app.</Text>
              <Text style={styles.modalStep}>
                4. When prompted, verify and trust the device's certificate.
              </Text>
            </View>

            <View style={styles.modalButtonContainer}>
              <Pressable
                style={[styles.modalButton, styles.buttonWifi]}
                onPress={openWifiSettings}
              >
                <Text style={styles.modalButtonText}>Open Wi-Fi Settings</Text>
              </Pressable>
              <Pressable
                style={[styles.modalButton, styles.buttonClose]}
                onPress={dismissGuide}
              >
                <Text style={styles.modalButtonText}>I'm Connected</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Help Modal */}
      <Modal
        animationType="slide"
        transparent={true}
        visible={isHelpVisible}
        onRequestClose={() => setHelpVisible(false)}
      >
        <View style={styles.modalCenteredView}>
          <ScrollView style={styles.helpScrollView} contentContainerStyle={styles.helpContent}>
            <View style={styles.helpHeader}>
              <Text style={styles.helpTitle}>Help & Usage Guide</Text>
              <Pressable onPress={() => setHelpVisible(false)}>
                <Text style={styles.menuClose}>✕</Text>
              </Pressable>
            </View>

            <Text style={styles.helpSectionTitle}>🔐 Security Modes</Text>
            <Text style={styles.helpText}>
              <Text style={styles.helpBold}>Secure Mode (Recommended):</Text> Devices are pre-configured with a unique encryption key at build time using a secure flashing tool. This mode provides the highest security as the encryption key is never transmitted over the air.
            </Text>
            <Text style={styles.helpText}>
              • On first use, set your organizer password directly{'\n'}
              • This password is for web login only{'\n'}
              • The mesh encryption key is already set and cannot be changed{'\n'}
              • Changing your password only affects how YOU log in{'\n'}
              • All secure nodes with the same flashed key can communicate
            </Text>

            <Text style={styles.helpText} style={[styles.helpText, {marginTop: 10}]}>
              <Text style={styles.helpBold}>Compatibility Mode (Less Secure):</Text> Devices start with a default factory key and use a bootstrap process to establish a shared password. While functional, this mode is inherently less secure.
            </Text>
            <Text style={styles.helpText}>
              • On first use, set your organizer password directly{'\n'}
              • This password is distributed to ALL devices in the mesh{'\n'}
              • It's used for BOTH web login AND mesh encryption{'\n'}
              • All devices will eventually receive and adopt this password{'\n'}
              • Everyone uses the same password for everything
            </Text>

            <Text style={styles.helpSectionTitle}>📱 First Time Setup</Text>
            <Text style={styles.helpStep}>1. Connect to Device Wi-Fi</Text>
            <Text style={styles.helpText}>
              Connect your phone to the ProtestInfo_XXXX network (where XXXX is the device's unique identifier).
            </Text>

            <Text style={styles.helpStep}>2. Trust the Certificate</Text>
            <Text style={styles.helpText}>
              When connecting via HTTPS, you'll be prompted to trust a self-signed certificate. This is normal and expected. Only trust certificates when connecting to your own devices.
            </Text>

            <Text style={styles.helpStep}>3. Set Organizer Password (First Time)</Text>
            <Text style={styles.helpText}>
              On first connection, you'll see a prompt to set your organizer password. This is required before you can send messages.{'\n\n'}
              <Text style={styles.helpBold}>Secure Mode:</Text> Your password will be used for web login only. The mesh encryption key is already set and secure.{'\n\n'}
              <Text style={styles.helpBold}>Compatibility Mode:</Text> Your password will be distributed across the mesh and used for both web login AND mesh encryption. All devices must receive the same password.
            </Text>

            <Text style={styles.helpStep}>4. Login for Future Sessions</Text>
            <Text style={styles.helpText}>
              After setting your password, you'll need to log in using "Enter Organizer Mode" with the password you created. Your session will remain active for 15 minutes.
            </Text>

            <Text style={styles.helpSectionTitle}>💬 Using the System</Text>
            <Text style={styles.helpStep}>View Messages</Text>
            <Text style={styles.helpText}>
              • All messages are displayed in the main log{'\n'}
              • Use "Show Public" to include public messages{'\n'}
              • Use "Only Urgent" to filter for urgent messages only{'\n'}
              • Messages automatically refresh
            </Text>

            <Text style={styles.helpStep}>Send Organizer Messages</Text>
            <Text style={styles.helpText}>
              1. Enter Organizer Mode with your password{'\n'}
              2. Type your message (max 184 characters){'\n'}
              3. Check "Urgent Message" if needed{'\n'}
              4. Tap "Send Message"
            </Text>

            <Text style={styles.helpStep}>Public Messaging</Text>
            <Text style={styles.helpText}>
              Organizers can enable public messaging to allow anyone connected to send messages. This should be used with caution as public messages are unmoderated.
            </Text>

            <Text style={styles.helpSectionTitle}>⚙️ Advanced Features</Text>
            <Text style={styles.helpStep}>Re-broadcast Cache</Text>
            <Text style={styles.helpText}>
              Manually retransmit all cached messages to help ensure delivery across the mesh network.
            </Text>

            <Text style={styles.helpStep}>Security Monitoring</Text>
            <Text style={styles.helpText}>
              The system monitors for:{'\n'}
              • Jamming attempts (RF interference){'\n'}
              • Authentication failures (wrong passwords){'\n'}
              • Infiltration attempts (conflicting passwords){'\n\n'}
              Check the Security & Password section in Organizer Mode for detailed logs.
            </Text>

            <Text style={styles.helpSectionTitle}>🔒 Security Notes</Text>
            <Text style={styles.helpText}>
              • Always use HTTPS when possible{'\n'}
              • Only fall back to HTTP if HTTPS repeatedly fails{'\n'}
              • Choose a strong organizer password (12+ characters recommended){'\n'}
              • Never share your organizer password publicly{'\n'}
              • Monitor security logs regularly for suspicious activity{'\n'}
              • Passwords cannot be changed after initial setup (reboot required to reset){'\n\n'}
              <Text style={styles.helpBold}>Secure Mode:</Text> Your mesh is protected by a pre-configured key. Changing your web password doesn't affect mesh security.{'\n\n'}
              <Text style={styles.helpBold}>Compatibility Mode:</Text> Your password IS the mesh security. If it's compromised, reboot all devices and set a new password immediately.
            </Text>

            <Text style={styles.helpSectionTitle}>⚠️ Troubleshooting</Text>
            <Text style={styles.helpText}>
              <Text style={styles.helpBold}>Cannot connect:</Text> Ensure you're on the correct Wi-Fi network and within range.{'\n\n'}
              <Text style={styles.helpBold}>Certificate errors:</Text> Make sure to trust the certificate when prompted. If issues persist, try switching to HTTP.{'\n\n'}
              <Text style={styles.helpBold}>Messages not sending:</Text> Verify you've set an organizer password. The interface will show a notice if the node isn't configured yet.{'\n\n'}
              <Text style={styles.helpBold}>Mesh not communicating (Compat Mode):</Text> Ensure all devices have received the same password. It may take a few minutes to propagate through the mesh.{'\n\n'}
              <Text style={styles.helpBold}>Password forgotten:</Text> The device must be rebooted to reset the password. This is a security feature.
            </Text>

            <Pressable
              style={[styles.modalButton, styles.buttonClose, {marginTop: 20}]}
              onPress={() => setHelpVisible(false)}
            >
              <Text style={styles.modalButtonText}>Close Help</Text>
            </Pressable>
          </ScrollView>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#333',
    paddingTop: Platform.OS === 'android' ? StatusBar.currentHeight : 0,
  },
  header: {
    backgroundColor: '#333',
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 15,
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#444',
  },
  headerLogo: {
    width: 30,
    height: 30,
    marginRight: 10,
  },
  headerTitleContainer: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
  },
  headerTitle: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
    marginRight: 8,
  },
  insecureBadge: {
    backgroundColor: '#ff6b6b',
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  insecureBadgeText: {
    color: '#fff',
    fontSize: 10,
    fontWeight: 'bold',
  },
  menuButton: {
    padding: 5,
  },
  menuButtonText: {
    color: '#fff',
    fontSize: 28,
    lineHeight: 28,
  },
  webview: {
    flex: 1,
  },
  loadingContainer: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#ffffff',
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    marginTop: 10,
    fontSize: 16,
    color: '#333',
  },
  loadingSubText: {
    marginTop: 8,
    fontSize: 12,
    color: '#666',
  },
  errorOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#ffffff',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 30,
  },
  errorIcon: {
    fontSize: 60,
    marginBottom: 20,
  },
  errorTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 10,
  },
  errorText: {
    fontSize: 16,
    color: '#666',
    textAlign: 'center',
    marginBottom: 5,
  },
  errorSubText: {
    fontSize: 14,
    color: '#999',
    textAlign: 'center',
    marginBottom: 30,
  },
  errorButton: {
    backgroundColor: '#007bff',
    paddingHorizontal: 30,
    paddingVertical: 12,
    borderRadius: 10,
    marginBottom: 10,
    width: '80%',
  },
  errorButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
    textAlign: 'center',
  },
  errorButtonSecondary: {
    paddingHorizontal: 30,
    paddingVertical: 12,
    borderRadius: 10,
    width: '80%',
  },
  errorButtonSecondaryText: {
    color: '#007bff',
    fontSize: 16,
    textAlign: 'center',
  },
  menuModalView: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
  },
  menuContent: {
    marginTop: 'auto',
    backgroundColor: 'white',
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    height: '80%',
    display: 'flex',
    flexDirection: 'column',
  },
  menuHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  menuTitle: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  menuClose: {
    fontSize: 30,
    color: '#666',
  },
  menuItems: {
    flex: 1,
    width: '100%',
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#f0f0f0',
  },
  menuItemIcon: {
    fontSize: 24,
    marginRight: 15,
    width: 30,
  },
  menuItemText: {
    fontSize: 16,
    color: '#333',
  },
  menuItemDanger: {
    color: '#dc3545',
  },
  menuDivider: {
    height: 8,
    backgroundColor: '#f8f9fa',
  },
  menuSection: {
    padding: 15,
    backgroundColor: '#f8f9fa',
  },
  menuSectionTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#666',
    textTransform: 'uppercase',
  },
  menuSectionSubtitle: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  menuFooter: {
    padding: 15,
    borderTopWidth: 1,
    borderTopColor: '#eee',
    alignItems: 'center',
  },
  menuFooterText: {
    fontSize: 12,
    color: '#999',
  },
  modalCenteredView: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
  },
  modalView: {
    margin: 20,
    backgroundColor: 'white',
    borderRadius: 20,
    padding: 25,
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 4,
    elevation: 5,
    width: '90%',
  },
  logoContainer: {
    width: 80,
    height: 80,
    marginBottom: 10,
    justifyContent: 'center',
    alignItems: 'center',
  },
  logoPlaceholder: {
    fontSize: 60,
  },
  modalTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 15,
  },
  modalText: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 15,
    lineHeight: 22,
  },
  modalSteps: {
    width: '100%',
    alignItems: 'flex-start',
    marginBottom: 20,
  },
  modalStep: {
    fontSize: 15,
    textAlign: 'left',
    marginBottom: 10,
  },
  modalHighlight: {
    fontWeight: 'bold',
    color: '#007bff',
  },
  modalButtonContainer: {
    width: '100%',
  },
  modalButton: {
    borderRadius: 10,
    padding: 12,
    elevation: 2,
    width: '100%',
    marginBottom: 10,
  },
  buttonWifi: {
    backgroundColor: '#007bff',
  },
  buttonClose: {
    backgroundColor: '#6c757d',
  },
  modalButtonText: {
    color: 'white',
    fontWeight: 'bold',
    textAlign: 'center',
    fontSize: 16,
  },
  // Certificate Dialog Styles
  certModalView: {
    margin: 20,
    backgroundColor: 'white',
    borderRadius: 20,
    padding: 25,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 4,
    elevation: 5,
    width: '90%',
    maxHeight: '80%',
  },
  certModalTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 15,
    textAlign: 'center',
    color: '#ff6b6b',
  },
  certModalText: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 15,
    lineHeight: 22,
  },
  certDetails: {
    width: '100%',
    backgroundColor: '#f8f9fa',
    borderRadius: 10,
    padding: 15,
    marginBottom: 15,
    maxHeight: 200,
  },
  certDetailLabel: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#666',
    marginTop: 8,
    marginBottom: 2,
  },
  certDetailValue: {
    fontSize: 14,
    color: '#333',
    marginBottom: 8,
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
  },
  certWarning: {
    backgroundColor: '#fff3cd',
    borderRadius: 10,
    padding: 12,
    marginBottom: 15,
    borderWidth: 1,
    borderColor: '#ffc107',
  },
  certWarningText: {
    fontSize: 13,
    color: '#856404',
    textAlign: 'center',
    lineHeight: 18,
  },
  insecureExplanation: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 20,
    color: '#333',
  },
  certButtonContainer: {
    width: '100%',
  },
  certButton: {
    borderRadius: 10,
    padding: 12,
    elevation: 2,
    width: '100%',
    marginBottom: 10,
  },
  certButtonAlways: {
    backgroundColor: '#28a745',
  },
  certButtonOnce: {
    backgroundColor: '#007bff',
  },
  certButtonNo: {
    backgroundColor: '#dc3545',
  },
  insecureButton: {
    backgroundColor: '#ff9800',
  },
  certButtonText: {
    color: 'white',
    fontWeight: 'bold',
    textAlign: 'center',
    fontSize: 16,
  },
  // Help Modal Styles
  helpScrollView: {
    flex: 1,
    width: '100%',
    backgroundColor: 'white',
    borderRadius: 20,
    margin: 20,
  },
  helpContent: {
    padding: 25,
    paddingBottom: 40,
  },
  helpHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  helpTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
  },
  helpSectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#007bff',
    marginTop: 20,
    marginBottom: 10,
  },
  helpStep: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 12,
    marginBottom: 4,
  },
  helpText: {
    fontSize: 14,
    color: '#555',
    lineHeight: 20,
    marginBottom: 8,
  },
  helpBold: {
    fontWeight: 'bold',
    color: '#333',
  },
});