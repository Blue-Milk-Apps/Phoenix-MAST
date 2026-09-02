import AsyncStorage from "@react-native-async-storage/async-storage";
import {createHash} from "crypto";
import React from "react";
import {Text} from "react-native";

export default function App({token}: {token: string}) {
  console.log("auth token", token);
  createHash("sha1").update(token);
  fetch("http://api.example.com/profile");
  AsyncStorage.setItem("auth_token", token);
  return <Text>Phoenix React Native fixture</Text>;
}
