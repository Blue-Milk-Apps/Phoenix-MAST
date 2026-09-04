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

console.log("auth token", token);
AsyncStorage.setItem("session_token", token);
Clipboard.setString(token);
RNFS.writeFile("secret_token.txt", token);
database.executeSql(`SELECT * FROM users WHERE token = '${token}'`);
CryptoJS.MD5(token);
CryptoJS.DES.encrypt(token, "example-key");
eval(token);
const agent = { rejectUnauthorized: false };
NativeModules.Payments.deleteCredential(token);
Location.startGeofencingAsync("region", []);

export const Example = () => (
  <WebView
    source={{ uri: endpoint }}
    originWhitelist={["*"]}
    mixedContentMode="always"
    onMessage={() => token}
  />
);
