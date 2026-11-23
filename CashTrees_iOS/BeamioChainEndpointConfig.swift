import ConetChatSDK
import Foundation

/// The shell's native build configuration for the CoNET L1 RPC endpoints used by the AddressPGP chain reads. The values are
/// never read from a page payload. The first endpoint is the registered CoNET L1 RPC that the shell already uses.
enum BeamioChainEndpointConfig {
    static let shellEndpointURL = URL(string: "https://rpc1.conet.network")

    /// Reserved. The client uses a single RPC and needs no second, independent endpoint
    /// (single-RPC design). It stays nil. Read failures still judge `chain` unknown (fail closed).
    static let shellEndpointSecondURL: URL? = nil

    /// Sets the SDK endpoint once, at launch, before any chain read.
    static func apply() {
        AddressPGPChain.shellEndpoint = shellEndpointURL
    }
}
