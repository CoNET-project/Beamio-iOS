#!/usr/bin/env bash
# Stub cases for verify-ios-passcode-no-logging.sh: the real tree passes; planted log lines fail. Uses a temporary copy only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"; ROOT="$(cd "$HERE/.." && pwd -P)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; total=0
check() { total=$((total + 1)); if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"; else echo "FAIL $1 (exit $2, want $3)"; fi; }
"$HERE/verify-ios-passcode-no-logging.sh" "$ROOT" >/dev/null && rc=0 || rc=$?; check "real tree passes" "$rc" 0
mk() { rm -rf "$TMP/t"; mkdir -p "$TMP/t/CashTrees_iOS"; cp "$ROOT"/CashTrees_iOS/{PwaWalletSyncBridge,PwaWalletSyncSdkEngine,ContentView}.swift "$TMP/t/CashTrees_iOS/"; }
mkother() { mk; printf '%s\n' "$1" > "$TMP/t/CashTrees_iOS/Other.swift"; }
mk; echo '    func x(_ p: String) { NSLog("p=%@", p) }' >> "$TMP/t/CashTrees_iOS/PwaWalletSyncBridge.swift"
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "NSLog in the gate fails" "$rc" 1
mk; echo '    func y() { print("x") }' >> "$TMP/t/CashTrees_iOS/PwaWalletSyncSdkEngine.swift"
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "print in the adapter fails" "$rc" 1
mk; echo '        NSLog("msg %@", body)' >> "$TMP/t/CashTrees_iOS/ContentView.swift"
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "ContentView logging a whole body fails" "$rc" 1
mk; echo '        print("cmd \(command)")' >> "$TMP/t/CashTrees_iOS/ContentView.swift"
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "ContentView interpolating a command fails" "$rc" 1
mk; echo '    // NSLog("commented out")' >> "$TMP/t/CashTrees_iOS/PwaWalletSyncBridge.swift"
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "a commented-out log line passes" "$rc" 0
mkother '        NSLog("restore %@", recoveryPhrase)'
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "SC-05: NSLog of a phrase elsewhere fails" "$rc" 1
mkother '        print("pin=\(userPasscode)")'
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "SC-05: interpolated passcode elsewhere fails" "$rc" 1
mkother '        logger.info("key \(wallet.privateKeyHex, privacy: .public)")'
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "SC-05: Logger with a private key fails" "$rc" 1
mkother '        NSLog("[X] missing Chat PGP secrets in Keychain")'
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "SC-05: a fixed text mentioning secrets passes" "$rc" 0
mkother '        NSLog("ok=%@", ok ? "true" : "false")'
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "SC-05: a boolean result passes" "$rc" 0
mkother $'        NSLog(\n            "restore %@ for %@",\n            account, mnemonicText\n        )'
"$HERE/verify-ios-passcode-no-logging.sh" "$TMP/t" >/dev/null && rc=0 || rc=$?; check "SC-05: a multi-line NSLog passing a mnemonic fails" "$rc" 1
echo "$pass/$total passed"; [[ "$pass" == "$total" ]]
