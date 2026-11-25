//
//  CashTreesPWAOtaTestSupport.swift
//  CashTrees_iOSTests
//
//  Test-only helpers: an Ed25519 test signer generated in memory per test (never written to disk, never in a key
//  table of the app), payload v2 and signed-object builders, and bundle fixtures.
//

import CryptoKit
import Foundation
import ZIPFoundation
@testable import CashTrees_iOS

struct OtaTestSigner {
    let key = Curve25519.Signing.PrivateKey()

    var publicKey: CashTreesPWAOtaPublicKey {
        let raw = key.publicKey.rawRepresentation
        return CashTreesPWAOtaPublicKey(keyId: CashTreesPWAOtaVerifier.keyId(of: raw), publicKeyBase64: raw.base64EncodedString())
    }

    /// payload v2 bytes in the fixed field order.
    static func payload(
        ver: String, filename: String, sha256: String, size: Int64, contentDigest: String,
        minIos: Int64 = 0, v: Int = 2, contentAlg: String = "beamio-tree-v1"
    ) -> Data {
        let json = #"{"type":"beamio-pwa-ota","v":\#(v),"ver":"\#(ver)","filename":"\#(filename)","sha256":"\#(sha256)","size":\#(size),"contentAlg":"\#(contentAlg)","contentDigest":"\#(contentDigest)","minShell":{"ios":\#(minIos),"android":0},"issuedAt":1795000000}"#
        return Data(json.utf8)
    }

    func signature(_ payload: Data, domain: String = CashTreesPWAOtaVerifier.signDomain) -> Data {
        try! key.signature(for: Data(domain.utf8) + payload)
    }

    /// The `signed` object of update.json.
    func signedDict(_ payload: Data, keyId: String? = nil, signature: Data? = nil) -> [String: Any] {
        [
            "payload": payload.base64EncodedString(),
            "signatures": [["keyId": keyId ?? publicKey.keyId, "sig": (signature ?? self.signature(payload)).base64EncodedString()]],
        ]
    }

    /// A full update.json.
    func updateJson(_ payload: Data, ver: String, filename: String, signed: [String: Any]? = nil) -> Data {
        let doc: [String: Any] = ["ver": ver, "filename": filename, "signed": signed ?? signedDict(payload)]
        return try! JSONSerialization.data(withJSONObject: doc, options: [.sortedKeys])
    }

    /// The stored object ota-signed/<digest>.json.
    func storedObject(_ payload: Data, ver: String, filename: String) -> Data {
        var obj = signedDict(payload)
        obj["updateVer"] = ver
        obj["updateFilename"] = filename
        return try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
    }
}

struct OtaBundleFixture {
    let dir: URL
    let zip: URL
    let tree: String
    let zipSha: String
    let size: Int64
    let ver: String
    var filename: String { "SilentPassUI-\(ver).zip" }

    /// Everything these tests write goes under `<tmp>/beamio-ota-tests/<run UUID>/`. Created once per test process;
    /// at that moment the other run directories (left by earlier runs) are removed, and nothing of this process exists
    /// yet, so nothing in use is touched.
    static let runRoot: URL = {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("beamio-ota-tests", isDirectory: true)
        for name in (try? fm.contentsOfDirectory(atPath: base.path)) ?? [] {
            try? fm.removeItem(at: base.appendingPathComponent(name))
        }
        let run = base.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? fm.createDirectory(at: run, withIntermediateDirectories: true)
        return run
    }()

    static func tempDir(_ prefix: String = "ota") throws -> URL {
        let url = runRoot.appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static func writeTree(_ dir: URL, index: String, ver: String) throws {
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("static/js"), withIntermediateDirectories: true)
        try Data(index.utf8).write(to: dir.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"\(ver)\",\"filename\":\"SilentPassUI-\(ver).zip\"}".utf8).write(to: dir.appendingPathComponent("update.json"))
        try Data("console.log('\(index)')".utf8).write(to: dir.appendingPathComponent("static/js/main.js"))
    }

    static func make(index: String, ver: String) throws -> OtaBundleFixture {
        let src = try tempDir("otasrc")
        try writeTree(src, index: index, ver: ver)
        let zip = src.deletingLastPathComponent().appendingPathComponent("ota-\(UUID().uuidString).zip")
        // Canonical form: file entries only (no directory entries), deflate.
        let archive = try Archive(url: zip, accessMode: .create)
        for name in ["index.html", "static/js/main.js", "update.json"] {
            try archive.addEntry(with: name, relativeTo: src, compressionMethod: .deflate)
        }
        let unz = try tempDir("otaunz")
        try FileManager.default.unzipItem(at: zip, to: unz)
        let size = (try FileManager.default.attributesOfItem(atPath: zip.path)[.size] as? NSNumber)?.int64Value ?? 0
        return OtaBundleFixture(
            dir: unz, zip: zip, tree: CashTreesPWASameVersionRule.treeDigest(at: unz) ?? "",
            zipSha: CashTreesPWASameVersionRule.fileSHA256(at: zip) ?? "", size: size, ver: ver
        )
    }

    var facts: CashTreesPWAEmbeddedFacts { CashTreesPWAEmbeddedFacts(ver: ver, zipSha256: zipSha, treeDigest: tree) }

    func payload(minIos: Int64 = 0) -> Data {
        OtaTestSigner.payload(ver: ver, filename: filename, sha256: zipSha, size: size, contentDigest: tree, minIos: minIos)
    }

    /// Places this bundle as a signed staging (as a completed download would) under `root`.
    func placeSignedStaging(root: URL, signer: OtaTestSigner) throws {
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        try? FileManager.default.removeItem(at: staging)
        try FileManager.default.copyItem(at: dir, to: staging)
        try writeSignedObject(root: root, signer: signer)
    }

    /// Places this bundle as an OTA-activated active tree (signed) under `root`.
    func placeSignedActive(root: URL, signer: OtaTestSigner) throws {
        let active = root.appendingPathComponent("active", isDirectory: true)
        try? FileManager.default.removeItem(at: active)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: dir, to: active)
        try writeSignedObject(root: root, signer: signer)
    }

    func writeSignedObject(root: URL, signer: OtaTestSigner) throws {
        let signedDir = root.appendingPathComponent("ota-signed", isDirectory: true)
        try FileManager.default.createDirectory(at: signedDir, withIntermediateDirectories: true)
        try signer.storedObject(payload(), ver: ver, filename: filename).write(to: signedDir.appendingPathComponent("\(tree).json"))
    }
}
