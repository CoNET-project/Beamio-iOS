//
//  BeamioHostRules.swift
//  CashTrees_iOS
//
//  Exact or subdomain match for Beamio hosts (beamio.ca, beamio.app). A substring match would also accept lookalikes
//  such as beamio.ca.evil.example; this rule does not.
//

import Foundation

enum BeamioHostRules {
    static let beamioHosts: Set<String> = ["beamio.ca", "beamio.app"]

    static func isBeamioHost(_ host: String) -> Bool {
        let h = host.lowercased()
        if beamioHosts.contains(h) { return true }
        return beamioHosts.contains { h.hasSuffix("." + $0) }
    }
}
