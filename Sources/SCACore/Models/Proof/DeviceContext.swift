/// Device identity sent with every proof submission.
///
/// The server uses `deviceId` to look up trust in its own registry.
/// The client's `claimsTrustedStatus` is just a hint — the server
/// never trusts it blindly.
///
/// Built by `DefaultSCAService.buildDeviceContext()` from `SecureStorage`
/// at the start of every `authenticate(challenge:)` call.
public struct DeviceContext: Codable, Sendable {
    
    /// UUID persisted in Keychain on first launch.
    /// This is the **only** field the server uses for device identity.
    public let deviceId: String
    
    /// Client's local claim — NOT authoritative.
    ///
    /// `true`: Keychain has a valid trust record.
    /// `false`: No trust record, or it expired locally.
    ///
    /// Named `claims...` (not `is...`) to make the advisory nature
    /// explicit to anyone reading the API surface.
    public let claimsTrustedStatus: Bool
    
    public init(
        deviceId: String,
        claimsTrustedStatus: Bool
    ) {
        self.deviceId = deviceId
        self.claimsTrustedStatus = claimsTrustedStatus
    }
}
