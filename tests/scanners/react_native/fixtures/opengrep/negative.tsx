import EncryptedStorage from "react-native-encrypted-storage";
import { WebView } from "react-native-webview";

const endpoint = "https://api.example.com/session";

await EncryptedStorage.setItem("profile", JSON.stringify({ theme: "dark" }));
database.executeSql("SELECT * FROM users WHERE id = ?", [userId]);

export const Example = () => (
  <WebView
    source={{ uri: endpoint }}
    originWhitelist={["https://app.example.com"]}
    mixedContentMode="never"
  />
);
