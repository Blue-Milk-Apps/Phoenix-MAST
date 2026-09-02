import * as SecureStore from "expo-secure-store";

export async function safePreference(theme: string) {
  console.log("theme changed");
  await fetch("https://api.example.com/profile");
  await SecureStore.setItemAsync("theme", theme);
}
