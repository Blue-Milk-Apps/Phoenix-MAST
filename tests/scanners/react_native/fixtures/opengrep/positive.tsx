import AsyncStorage from "@react-native-async-storage/async-storage";
import { Clipboard, NativeModules } from "react-native";
import { WebView } from "react-native-webview";
import "@notifee/react-native";
import "@react-native-camera-roll/camera-roll";
import "@react-native-community/geolocation";
import "@react-native-community/netinfo";
import "@react-native-firebase/messaging";
import "@stripe/stripe-react-native";
import "expo-audio";
import "expo-calendar";
import "expo-camera";
import "expo-contacts";
import "expo-image-picker";
import "expo-local-authentication";
import "expo-media-library";
import "expo-sensors";
import "expo-sms";
import "react-native-background-fetch";
import "react-native-ble-plx";
import "react-native-callkeep";
import "react-native-device-admin";
import "react-native-fingerprint-scanner";
import "react-native-get-random-values";
import "react-native-health";
import "react-native-iap";
import "react-native-ir-manager";
import "react-native-keychain";
import "react-native-keystore";
import "react-native-maps";
import "react-native-nearby-api";
import "react-native-nfc-manager";
import "react-native-usb";

const token = "example";
const endpoint = "http://api.example.com/session";
const tokenNonce = Math.random();
const sha1Digest = createHash("sha1").update(token).digest("hex");
const weakDerivedKey = pbkdf2Sync("password", "salt", 1000, 32, "sha256");
const weakRsaKey = generateKeyPairSync("rsa", { modulusLength: 1024 });
const weakBlowfish = createCipheriv("bf-cbc", iv, Buffer.from("short-key"));
const authDeviceToken = DeviceInfo.getUniqueId();
const ftpBackup = "ftp://files.example.com/mobile";
const tlsOptions = { minVersion: "TLSv1.0" };
document.cookie = "session=value";
const clearAdvertiser = "http://api.example.com/device?advertising_id=value";
const clearImei = "http://api.example.com/device?imei=value";
const clearLatitude = "http://api.example.com/device?latitude=value";
const clearLongitude = "http://api.example.com/device?longitude=value";
const clearToken = "http://api.example.com/device?token=value";
const clearWifiMac = "http://api.example.com/device?wifi_mac=value";
const secureImei = "https://api.example.com/device?imei=value";
const secureLatitude = "https://api.example.com/device?latitude=value";
const secureLongitude = "https://api.example.com/device?longitude=value";
const secureToken = "https://api.example.com/device?token=value";
const secureWifiMac = "https://api.example.com/device?wifi_mac=value";
const configuredEndpoint = process.env.API_URL;
const apiClient = axios.create({ baseURL: API_BASE });

console.log("auth token", token);
console.log("advertising_id", advertiserId);
console.log("imei", imei);
console.log("location", location);
console.log("wifi_mac", wifiMac);
AsyncStorage.setItem("session_token", token);
AsyncStorage.setItem("api_key", "literal-api-key");
AsyncStorage.setItem("password", "literal-password");
AsyncStorage.setItem("advertising_id", advertiserId);
AsyncStorage.setItem("imei", imei);
AsyncStorage.setItem("location", location);
AsyncStorage.setItem("wifi_ip_address", wifiIpAddress);
DefaultPreference.set("session_token", token);
Clipboard.setString(token);
RNFS.writeFile("secret_token.txt", token);
RNFS.writeFile("public.txt", token, { mode: 0o777 });
database.executeSql(`SELECT * FROM users WHERE token = '${token}'`);
CryptoJS.MD5(token);
CryptoJS.DES.encrypt(token, "example-key");
eval(token);
const agent = { rejectUnauthorized: false };
const legacyKeychain = { accessible: ACCESSIBLE.ALWAYS };
const unlockedKeychain = { accessible: ACCESSIBLE.AFTER_FIRST_UNLOCK };
NativeModules.Payments.deleteCredential(token);
Location.startGeofencingAsync("region", []);
const insecurePasswordInput = (
  <TextInput accessibilityLabel="password" secureTextEntry={false} />
);

export const Example = () => (
  <WebView
    source={{ uri: endpoint }}
    originWhitelist={["*"]}
    mixedContentMode="always"
    onMessage={() => token}
  />
);
