import Foundation
import UIKit

/// External links from the page (`CashTreesIOS.openURL({ url })`).
///
/// The `openURL` action is not gated by the bundle trust check (`NativeBridgeTrust`) and has no scheme allowlist: any URL the
/// page gives is handed to the system as-is, so the page can open any app's URL scheme. Only a basic parse check applies: after
/// trimming surrounding whitespace the value is not empty, `URL(string:)` parses it and it has a scheme. Every other bridge
/// action keeps the trust check unchanged (`BeamioBridgeRoute`).
enum BeamioExternalURL {
    /// The URL to open for a raw page value, or nil when it is empty, does not parse or has no scheme.
    static func urlToOpen(_ raw: String?) -> URL? {
        let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !trimmed.isEmpty, let url = URL(string: trimmed), let scheme = url.scheme, !scheme.isEmpty else { return nil }
        return url
    }

    /// Opens the raw page value through `opener` when `urlToOpen` accepts it. Returns whether `opener` was called.
    @discardableResult
    static func open(_ raw: String?, opener: (URL) -> Void) -> Bool {
        guard let url = urlToOpen(raw) else { return false }
        opener(url)
        return true
    }

    /// The system opener used by the shell.
    static let systemOpener: (URL) -> Void = { url in
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
}

/// How the bridge handles one page action given the bundle trust result.
enum BeamioBridgeRoute: Equatable {
    /// `openURL`: handed to `BeamioExternalURL` whatever the trust result.
    case openExternal
    /// A trusted action: the normal dispatch.
    case dispatch
    /// An untrusted action other than `openURL`: refused (as before).
    case refuse

    static func route(action: String, trusted: Bool) -> BeamioBridgeRoute {
        if action == "openURL" { return .openExternal }
        return trusted ? .dispatch : .refuse
    }
}
