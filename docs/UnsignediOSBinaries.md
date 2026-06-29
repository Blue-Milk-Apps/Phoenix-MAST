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

## Rename the .app to .ipa

- Create a folder called `Payload`
- Copy the newly built .app and contents into `Payload`. At the end of the build process, you can find the path to the .app that was created (unless you specified a path for it).
- Zip the `Payload` folder and call it <yourapp>.ipa
