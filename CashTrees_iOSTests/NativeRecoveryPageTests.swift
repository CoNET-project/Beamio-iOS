import Foundation
import Testing
import UIKit
@testable import ConetChatSDK
@testable import CashTrees_iOS

// The native recovery page (106 CashTreesNativeRecovery, ported): presented by the SDK hook onRecoveryRequired, with
// the two formal entries only (BeamioTag plus password, and the recovery code). Synthetic values from the shared vectors
// (SHA256 817957b9bb63fd31de9bb82f739405260ca998752b3fe7afc660601604c12b80); production KDF; fixture registry.
// Synthetic recovery code from the native-recovery-vectors.v1 vectors (gen-native-recovery-vectors.mjs, CODE_A_OK, 22 chars). Not a QA account code.
private let codePathA = "3kRz8mQ2vLpN7wXy1sTcFh"
private let namePathB = "syn_recover_0001"
private let passwordPathB = "SYN-pin-2026"
private let accountA = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
private let fixturePathA = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXh4VVpZbnl5a0RsSm84eHI1L1g5OFArQVRBK3dFeW10WEZDZVlmZThjTlYvTnE2QVI4U3BBc2pWUUIxRDNtckd1Y1NNRlhTVG1qcGxHczYvbk5xRVBXLzdaWDkrQitsODBpbk0vamhWREpoS0hMRlBGUU9KTHkwVlNlSUFJZ2xOSENvMzViMFU3MFNHeVRnbEpnRG1ibmdmWmlhYlprTFlLYmNMbzE2VTUwdStiWVdkZ2VpUFU0blZxWE53PSJ9"
private let fixturePathB = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXgvOFBHRUR1b1FPK0FBVEo0MWRwZC9EL2pZbU5WOTNYNnpqeHBUM0g0QTlibTRzTE1UL1dyL2RzUXYzNnlQR3QvTmxtbDB2Zk1senhRWXg3d0p4MjdwdXZ2QzNrZDBsZHBkQXJQNk9WQzV1QmlSTWdHNVI5UFVaNThnN21DZUU5WndrMnN0N0FYNDUzd1M3UnpxQlVYeDR0T2xDOHpBZlFKallrQ21LRnlyOXd4N2xjZEtGQ0JpdHUya3FvPSJ9"

private struct PageFixtureRegistry: BeamioRecoveryRegistryReading {
    func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
        let hex = "0x" + nameHash.map { String(format: "%02x", $0) }.joined()
        return hex == "0xc994c0e53eb8fa2986fd8ef845c5cf46067a6440b22e0fb2e3554a421b6ef173" ? .success(fixturePathA) : .success("")
    }
    func recordByAccountName(_ name: String) -> Result<String, Error> { name == namePathB ? .success(fixturePathB) : .success("") }
    func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .success("") }
}

private final class PageMemoryPinAttempts: BeamioNativeRecovery.PinAttemptStoring {
    private var failures = 0
    private var last: Date?
    func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
    func save(failures: Int, lastFailure: Date?) { self.failures = failures; self.last = lastFailure }
}

/// Records the requests the page hands to the engine and answers with a scripted code.
private final class RecordingRecoveryEngine: CashTreesRecoveryEngine {
    private(set) var requests: [String] = []
    func submit(_ request: CashTreesRecoveryRequest, done: @escaping (CashTreesRecoveryCode, Int?) -> Void) {
        switch request {
        case .code(let bytes): requests.append("code:" + String(decoding: bytes, as: UTF8.self))
        case .account(let name, _): requests.append("account:" + name)
        }
        done(.ok, nil)
    }
    func pageClosed(hadResult: Bool) {}
}

private func textFields(in view: UIView) -> [UITextField] {
    var out: [UITextField] = []
    if let t = view as? UITextField { out.append(t) }
    for sub in view.subviews { out += textFields(in: sub) }
    return out
}

private func labelTexts(in view: UIView) -> [String] {
    var out: [String] = []
    if let l = view as? UILabel, let t = l.text { out.append(t) }
    for sub in view.subviews { out += labelTexts(in: sub) }
    return out
}

extension SdkStateSuite {
@MainActor
@Suite(.serialized)
struct NativeRecoveryPageTests {
    init() {
        BeamioNativeAccountPointer.clear()
        BeamioNativeKeySnapshot.invalidate()
    }

    private func clearDevice() -> () -> Void {
        let savedItems = BeamioChatWalletTestMemory.items
        let savedStore = BeamioNativeWallet.keyStore
        let savedRegistry = BeamioNativeRecovery.registry
        let savedAttempts = BeamioNativeRecovery.attempts
        BeamioChatWalletTestMemory.items = [:]
        // the product store (BeamioPasscodeWalletStore): an account restored with its mnemonic is the no-passcode set and its key is
        // derived from the set on read (iOS SDK behaviour). The raw store holds no key record for it.
        BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
        BeamioNativeRecovery.registry = PageFixtureRegistry()
        BeamioNativeRecovery.attempts = PageMemoryPinAttempts()
        BeamioNativeAccountPointer.clear()
        return {
            BeamioChatWalletTestMemory.items = savedItems
            BeamioNativeWallet.keyStore = savedStore
            BeamioNativeRecovery.registry = savedRegistry
            BeamioNativeRecovery.attempts = savedAttempts
        }
    }

    @Test func sdkHookPresentsTheRecoveryPage() {
        CashTreesNativeRecoveryRoute.installOnce()
        #expect(BeamioNativeRecovery.onRecoveryRequired != nil, "the shell installs the SDK recovery hook")
        let presented = BeamioNativeRecovery.onRecoveryRequired?(accountA) ?? false
        #expect(presented, "onRecoveryRequired presents the page")
        let shown = topMostController()
        #expect(shown is CashTreesNativeRecoveryViewController, "the presented controller is the recovery page")
        shown?.dismiss(animated: false)
    }

    @Test func pageHasNoMnemonicOrPrivateKeyInput() {
        let vc = CashTreesNativeRecoveryViewController(copy: .forLanguages(["en"]), engine: RecordingRecoveryEngine())
        vc.loadViewIfNeeded()
        let fields = textFields(in: vc.view)
        #expect(fields.count == 3, "the page has the recovery code, the account name and the password, and nothing else")
        let forbidden = ["mnemonic", "phrase", "private", "助记词", "私钥"]
        for f in fields {
            let text = ((f.placeholder ?? "") + " " + (f.accessibilityLabel ?? "")).lowercased()
            #expect(!forbidden.contains { text.contains($0) }, "no field asks for a phrase or a key")
        }
        #expect(fields.filter { $0.isSecureTextEntry }.count == 2, "the code and the password are secure fields")
    }

    @Test func bothEntriesReachTheEngineFromThePage() {
        let engine = RecordingRecoveryEngine()
        let vc = CashTreesNativeRecoveryViewController(copy: .forLanguages(["en"]), engine: engine)
        vc.loadViewIfNeeded()
        let fields = textFields(in: vc.view)
        // Path A: the recovery code.
        vc.show(path: "A")
        fields.first { $0.isSecureTextEntry && $0.placeholder?.contains("Recovery") == true }?.text = codePathA
        vc.submit()
        // Path B: BeamioTag (account name) and password.
        vc.show(path: "B")
        fields.first { $0.placeholder == "Account name" }?.text = namePathB
        fields.first { $0.isSecureTextEntry && $0.placeholder == "Password" }?.text = passwordPathB
        vc.submit()
        #expect(engine.requests == ["code:" + codePathA, "account:" + namePathB], "each entry reaches the engine as its own request")
    }

    @Test func recoveryCodeEntryRestoresTheOriginalAccountThroughTheSdk() async {
        let restore = clearDevice()
        defer { restore() }
        let secret = Array(codePathA.utf8)
        let code: CashTreesRecoveryCode = await withCheckedContinuation { cont in
            CashTreesSdkRecoveryEngine().submit(.code(secret: secret)) { code, _ in cont.resume(returning: code) }
        }
        #expect(code == .ok, "the recovery code entry restores through the SDK")
        #expect(BeamioNativeWallet.keyStore.read(eoa: accountA)?.count == 32, "the derived account holds the restored key, read through the product store")
    }

    @Test func beamioTagAndPasswordEntryRestoresTheOriginalAccountThroughTheSdk() async {
        let restore = clearDevice()
        defer { restore() }
        let code: CashTreesRecoveryCode = await withCheckedContinuation { cont in
            CashTreesSdkRecoveryEngine().submit(.account(name: namePathB, password: Array(passwordPathB.utf8))) { code, _ in
                cont.resume(returning: code)
            }
        }
        #expect(code == .ok, "the BeamioTag and password entry restores through the SDK")
        #expect(BeamioNativeWallet.keyStore.read(eoa: accountA)?.count == 32, "the derived account holds the restored key, read through the product store")
    }

    @Test func aNameThatIsNotAPwaBeamioTagIsRefusedWithoutAQuery() {
        let engine = RecordingRecoveryEngine()
        let vc = CashTreesNativeRecoveryViewController(copy: .forLanguages(["en"]), engine: engine)
        vc.loadViewIfNeeded()
        let fields = textFields(in: vc.view)
        let bad = ["ab", String(repeating: "a", count: 27), "bad name", "名字", "a!b", "@@", "syn-recover"]
        for name in bad {
            vc.show(path: "B")
            fields.first { $0.placeholder == "Account name" }?.text = name
            fields.first { $0.isSecureTextEntry && $0.placeholder == "Password" }?.text = passwordPathB
            vc.submit()
            #expect(engine.requests.isEmpty, "\(name): the SDK is not queried")
            #expect(labelTexts(in: vc.view).contains("Use 3–26 letters, numbers, dots, or underscores"),
                    "\(name): the PWA message for the BeamioTag rule is shown")
        }
    }

    @Test func aBeamioTagIsNormalisedAsThePwaDoesAndReachesTheEngine() {
        let engine = RecordingRecoveryEngine()
        let vc = CashTreesNativeRecoveryViewController(copy: .forLanguages(["en"]), engine: engine)
        vc.loadViewIfNeeded()
        let fields = textFields(in: vc.view)
        // "@" removed, trimmed, NFKC, zero-width removed; case kept; 3 to 26 characters of [a-zA-Z0-9_.].
        let inputs = ["syn_recover_0001", "  @Syn.Recover  ", "ｓｙｎ_recover", "syn\u{200B}_rec", "Ab.c_9"]
        for name in inputs {
            vc.show(path: "B")
            fields.first { $0.placeholder == "Account name" }?.text = name
            fields.first { $0.isSecureTextEntry && $0.placeholder == "Password" }?.text = passwordPathB
            vc.submit()
        }
        #expect(engine.requests == ["account:syn_recover_0001", "account:Syn.Recover", "account:syn_recover",
                                    "account:syn_rec", "account:Ab.c_9"],
                "each valid BeamioTag reaches the engine once, normalised as the PWA does")
    }
}
}

@MainActor
private func topMostController() -> UIViewController? {
    let windows = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }
    var top = (windows.first(where: { $0.isKeyWindow }) ?? windows.first)?.rootViewController
    while let p = top?.presentedViewController { top = p }
    return top
}
