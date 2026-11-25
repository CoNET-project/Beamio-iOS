import Foundation
import Testing
import UIKit
@testable import CashTrees_iOS

// Onboarding recovery on the PWA page: the source rule of nativeRecoverySubmit / nativeRecoveryCancel (each check on its own), the background timeout of
// the headless session, and the G0 app-switcher shield. No secret is used here.

private final class CountingEngine: CashTreesRecoveryEngine {
    private(set) var restores = 0
    private(set) var finishes: [String] = []
    func restore(_ request: CashTreesRecoveryRequest) -> (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) {
        restores += 1
        return (.notFound, nil, nil)
    }
    func finish(_ code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) { finishes.append(code.rawValue) }
}

@MainActor
struct NativeRecoveryTrustTests {
    @Test func everySourceCheckIsRequired() {
        func ok(_ main: Bool = true, _ scheme: String = "cashtrees-local", _ host: String = "localhost", _ port: Int = 0, _ bundle: Bool = true) -> Bool {
            CashTreesRecoveryBridge.isTrustedSource(isMainFrame: main, scheme: scheme, host: host, port: port, bundleTrusted: bundle)
        }
        #expect(ok(), "main frame, fixed local origin, bundle trusted")
        #expect(ok(true, "CASHTREES-LOCAL", "LocalHost"), "scheme and host compare case-insensitively")
        #expect(!ok(false), "a sub-frame is refused")
        #expect(!ok(true, "cashtrees-local", "localhost", 0, false), "the bundle trust is required")
        for (scheme, host) in [("https", "localhost"), ("https", "beamio.ca"), ("file", ""), ("data", ""), ("blob", "localhost"),
                               ("javascript", ""), ("cashtrees-local", "localhost.evil.com"), ("cashtrees-local", "evil-localhost"),
                               ("cashtrees-local", ""), ("cashtrees-localx", "localhost"), ("about", "")] {
            #expect(!ok(true, scheme, host), "\(scheme)://\(host) is refused")
        }
        #expect(!ok(true, "cashtrees-local", "localhost", 8080), "a port is refused")
    }

    @Test func anUntrustedSourceGetsOriginRefusedAndNoEngineRuns() {
        let engine = CountingEngine()
        let s = CashTreesRecoverySession(engine: engine)
        s.work = { $0() }
        s.main = { $0() }
        _ = s.open()
        let trusted = CashTreesRecoveryBridge.isTrustedSource(isMainFrame: false, scheme: "cashtrees-local", host: "localhost", port: 0, bundleTrusted: true)
        let answer = CashTreesRecoveryBridge.answer(action: "nativeRecoverySubmit", body: ["path": "code", "code": "x"], trusted: trusted, session: s)
        #expect(answer["error"] as? String == "origin_refused")
        #expect(engine.restores == 0 && engine.finishes.isEmpty && s.isOpen)
    }

    @Test func aLongBackgroundEndsTheSessionAndAShortOneDoesNot() {
        let engine = CountingEngine()
        let s = CashTreesRecoverySession(engine: engine)
        s.work = { $0() }
        s.main = { $0() }
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(CashTreesRecoverySession.backgroundTimeout == 300, "300 seconds, the same as Android")
        _ = s.open()
        s.noteDidEnterBackground(now: t0)
        s.noteWillEnterForeground(now: t0.addingTimeInterval(120))
        #expect(s.isOpen && engine.finishes.isEmpty, "two minutes (for example in a password manager) keep the session")
        s.noteDidEnterBackground(now: t0)
        s.noteWillEnterForeground(now: t0.addingTimeInterval(CashTreesRecoverySession.backgroundTimeout - 1))
        #expect(s.isOpen && engine.finishes.isEmpty, "a short background keeps the session")
        s.noteDidEnterBackground(now: t0)
        s.noteWillEnterForeground(now: t0.addingTimeInterval(CashTreesRecoverySession.backgroundTimeout))
        #expect(!s.isOpen && engine.finishes == ["cancelled"], "a long background ends it with cancelled")
        s.noteWillEnterForeground(now: t0.addingTimeInterval(10_000))
        #expect(engine.finishes == ["cancelled"], "a foreground without a background does nothing")
    }

    @Test func theG0ShieldCoversOnlyWithoutANativeAccount() {
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        window.isHidden = false
        let shield = CashTreesG0PrivacyShield()
        shield.windows = { [window] }
        var g0 = true
        shield.isG0 = { g0 }
        shield.cover()
        #expect(shield.isCovered)
        #expect(window.subviews.contains { $0.accessibilityIdentifier == CashTreesG0PrivacyShield.shieldIdentifier })
        shield.uncover()
        #expect(!shield.isCovered && !window.subviews.contains { $0.accessibilityIdentifier == CashTreesG0PrivacyShield.shieldIdentifier })
        g0 = false
        shield.cover()
        #expect(!shield.isCovered, "with a native account nothing is covered")
    }
}
