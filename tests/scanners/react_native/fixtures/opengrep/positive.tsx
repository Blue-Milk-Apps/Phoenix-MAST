import AsyncStorage from "@react-native-async-storage/async-storage";
import axios from "axios";
import CryptoJS from "crypto-js";
import {createCipheriv, createHash} from "crypto";

export async function vulnerable(user: string, token: string) {
  console.log("auth token", token);
  database.executeSql(`SELECT * FROM users WHERE name = '${user}'`);
  createHash("sha1").update(token);
  createCipheriv("des", token, token);
  CryptoJS.MD5(token);
  await fetch("http://api.example.com/profile");
  axios.get("https://api.example.com", {httpsAgent: {rejectUnauthorized: false}});
  await AsyncStorage.setItem("auth_token", token);
}
