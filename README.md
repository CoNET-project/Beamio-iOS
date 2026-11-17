# Beamio for iOS

This repository contains the native iOS shell for **Beamio: Onchain Rewards** (`com.beamio.beamio`). The app loads the Beamio consumer PWA from a bundled ZIP and provides iOS integrations for wallet flows, push notifications, deep links, and chat and calls through the [CoNET iOS Chat SDK](https://github.com/CoNET-project/chat-sdk-ios).

## Build locally

1. Install Xcode with an iOS SDK compatible with the project's deployment target. Xcode 27.2 was used for build 105.
2. Open `CashTrees_iOS.xcodeproj` and select the `CashTrees_iOS` scheme. Xcode resolves ZIPFoundation and the CoNET Chat SDK through Swift Package Manager.
3. Run on an iOS simulator or a provisioned device. Hardware features such as push notifications and CallKit should be verified on a physical device. An App Store archive requires authorized signing for the application's bundle identifier.

```sh
xcodebuild -resolvePackageDependencies -project CashTrees_iOS.xcodeproj -scheme CashTrees_iOS
```

## Embedded PWA and updates

- Package exactly one consumer PWA archive, `CashTrees_iOS/SilentPassUI.zip`. The ZIP version and SHA-256 should match the reviewed release record. Verify the archived `.app` also contains exactly one copy with that name.
- The shell launches the bundled PWA offline. It checks `https://beamio.ca/app/update.json` and downloads versioned archives from `https://beamio.ca/app/`. Verify that an update activates only after staging succeeds and that a cold launch preserves the existing wallet state and local data.
- For a release, use a specific commit from this repository. Record the iOS version and build number, embedded ZIP SHA-256, and signed artifact SHA-256 with the test results. TestFlight uploads and public App Store releases are separate steps.

Keep device captures, test-account recovery material, provisioning profiles, and signing credentials out of this repository.

## Verify the release archive

Use the approved PWA version and SHA-256 from the release record. Run the post-build check outside the Xcode build sandbox so it can scan the complete app bundle, including frameworks and other resources.

```sh
scripts/verify-ios-single-zip.sh pre --ver "$PWA_VERSION" --sha256 "$PWA_ZIP_SHA256"
scripts/verify-ios-single-zip.sh post --ver "$PWA_VERSION" --sha256 "$PWA_ZIP_SHA256" "$IOS_ARCHIVE_PATH"
```

The initial `1.5.8 (105)` source import carries PWA `0.52.933`, SHA-256 `f0aa310315164d1edf646b583665fccaa35febdd35cc87572ea3dd0f352c288d`.
