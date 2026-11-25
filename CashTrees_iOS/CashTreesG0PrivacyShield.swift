import ConetChatSDK
import UIKit

/// Covers the app while it is inactive when the device has no native account yet (G0: `beamio.native.account.v1` is empty),
/// so the app-switcher snapshot does not show the onboarding recovery page. With an account the app is not
/// covered (a signed-in user may want the switcher to show, for example, a receive code), except while the page asks for it
/// (`secureScreen`, the new account's recovery code). iOS cannot block screenshots;
/// that stays a recorded residual risk.
final class CashTreesG0PrivacyShield {
    static let shared = CashTreesG0PrivacyShield()

    /// Whether the device is at G0. Tests replace it.
    var isG0: () -> Bool = { BeamioNativeAccountPointer.get().isEmpty }
    /// The windows to cover. Tests replace it.
    var windows: () -> [UIWindow] = {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }
    }

    static let shieldIdentifier = "beamio.g0.privacyShield"

    /// The page's request (`secureScreen {on}`) while it shows the recovery code of a new account, when the device is no longer
    /// at G0. Process memory only, so a cold start clears it; it also ends by itself after `secureScreenLimit`.
    static let secureScreenLimit: TimeInterval = 600
    var now: () -> Date = { Date() }
    private var secureUntil: Date?

    /// A repeated on:true while the request is active keeps the first deadline (the 10 minutes are not restarted).
    func setSecureScreen(_ on: Bool) {
        guard on else { secureUntil = nil; return }
        if secureScreenActive { return }
        secureUntil = now().addingTimeInterval(Self.secureScreenLimit)
    }

    var secureScreenActive: Bool {
        guard let until = secureUntil else { return false }
        if now() >= until { secureUntil = nil; return false }
        return true
    }
    private var shields: [UIView] = []
    private var observers: [NSObjectProtocol] = []

    func installOnce() {
        guard observers.isEmpty else { return }
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.cover()
        })
        observers.append(nc.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.uncover()
        })
    }

    var isCovered: Bool { !shields.isEmpty }

    func cover() {
        guard shields.isEmpty, isG0() || secureScreenActive else { return }
        for window in windows() where !window.isHidden {
            let v = UIView(frame: window.bounds)
            v.backgroundColor = .systemBackground
            v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            v.accessibilityIdentifier = Self.shieldIdentifier
            window.addSubview(v)
            shields.append(v)
        }
    }

    func uncover() {
        shields.forEach { $0.removeFromSuperview() }
        shields.removeAll()
    }
}
