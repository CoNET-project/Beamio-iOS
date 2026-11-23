//
//  ChatApiBaseOverride.swift
//  CashTrees_iOS
//
//  The chat SDK (ConetChatSDK) defaults `apiBaseUrl` to https://beamio.ca/api and takes its value from the `init`
//  payload (`payload.apiBaseUrl`) when one is given. This shell sets the value explicitly on every `init` it forwards,
//  so a page value can never point native chat requests at another host.
//  Per the project decision, the 105 build moves its native requests to beamio.ca.
//

import Foundation

enum ChatApiBaseOverride {
    static let apiBaseUrl = "https://beamio.ca/api"

    /// Returns the command to forward. For `init`, `payload.apiBaseUrl` is set to beamio.ca whatever the page sent
    /// (or omitted). Other commands are returned unchanged.
    static func apply(_ command: [String: Any]) -> [String: Any] {
        guard (command["type"] as? String) == "init", var payload = command["payload"] as? [String: Any] else {
            return command
        }
        payload["apiBaseUrl"] = apiBaseUrl
        var out = command
        out["payload"] = payload
        return out
    }
}
