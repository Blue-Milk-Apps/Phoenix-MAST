# The Unsigned Build Process

To build an iOS app unsigned when you have the source code available, use the following steps.  macOS is required.

## Archive it with `xcodebuild`

```bash
xcodebuild archive \
  -project MyProject.xcodeproj \
  -scheme MyScheme \
  -configuration Release \
  -archivePath ./build/MyProject.xcarchive \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGN_ENTITLEMENTS=""
  ```

## Create an Xcode Config Plist for Exporting

```xml
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://apple.com"> <plistversion="1.0"> <dict> <key>method</key> <string>development</string> <key>signingStyle</key> <string>manual</string> <key>compileBitcode</key> <false/> </dict> </plist>
```

## Export to IPA

```bash
xcodebuild -exportArchive \
  -archivePath ./build/MyProject.xcarchive \
  -exportPath ./build/ExportedApp \
  -exportOptionsPlist ExportOptions.plist \
  CODE_SIGNING_ALLOWED=NO
```
