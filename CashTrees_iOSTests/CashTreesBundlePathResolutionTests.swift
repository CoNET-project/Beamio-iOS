import Foundation
import Testing
@testable import CashTrees_iOS

extension SdkStateSuite {
    @Suite(.serialized)
    struct CashTreesBundlePathResolutionTests {
        @Test func servesInRootFileAndRejectsDotTraversal() throws {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let page = root.appendingPathComponent("index.html")
            try Data("ok".utf8).write(to: page)

            #expect(CashTreesPWABundleStore.resolveContainedFile(root: root, requestPath: "/") == page)
            #expect(CashTreesPWABundleStore.resolveContainedFile(root: root, requestPath: "/%2e%2e/secret") == nil)
            #expect(CashTreesPWABundleStore.resolveContainedFile(root: root, requestPath: "/..%2fsecret") == nil)
            #expect(CashTreesPWABundleStore.resolveContainedFile(root: root, requestPath: "/%252e%252e/secret") == nil)
            #expect(CashTreesPWABundleStore.resolveContainedFile(root: root, requestPath: "/%00secret") == nil)
        }

        @Test func symlinkCannotEscapeActiveRoot() throws {
            let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
            let root = base.appendingPathComponent("active", isDirectory: true)
            let outside = base.appendingPathComponent("outside", isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: base) }
            try Data("outside".utf8).write(to: outside.appendingPathComponent("secret.txt"))
            try FileManager.default.createSymbolicLink(
                at: root.appendingPathComponent("escape"),
                withDestinationURL: outside
            )

            #expect(CashTreesPWABundleStore.resolveContainedFile(root: root, requestPath: "/escape/secret.txt") == nil)
        }
    }
}
