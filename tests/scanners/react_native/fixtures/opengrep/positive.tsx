import AsyncStorage from "@react-native-async-storage/async-storage";
import { Clipboard, NativeModules } from "react-native";
import { WebView } from "react-native-webview";

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

export const Example = () => (
  <WebView
    source={{ uri: endpoint }}
    originWhitelist={["*"]}
    mixedContentMode="always"
    onMessage={() => token}
  />
);
