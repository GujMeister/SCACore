/// (2) What the client assembles after the user authenticates.
///
/// For each factor the service collects, it builds one of these and
/// sends it to the server via `SCAProvider.verify(proof:)`.
/// The server responds with `VerificationStepResult` — either
/// `.partial` (keep going) or `.complete` (here's your token).
///
/// Based on FIDO2 assertion and OAuth proof-of-possession patterns.
import Foundation

public struct AuthenticationProof: Sendable {
    
    /// Links this proof back to the originating `SCAChallenge.challengeId`.
    public let challengeId: String
    
    /// Which method was used — the server validates that this method
    /// was actually listed in the original challenge.
    public let method: AuthenticationMethod
    
    /// The raw credential, format depends on method category:
    /// - Knowledge: password hash or PIN
    /// - Possession: 6-digit OTP code (e.g. `"384291"`)
    /// - Inherence: `"biometric_success"` token from local auth
    ///
    /// In production, knowledge credentials are hashed before transmission.
    public let credential: String
    
    /// When this proof was generated — server may reject stale proofs.
    public let timestamp: Date
    
    /// Device info for server-side risk assessment and trust verification.
    /// See `DeviceContext.claimsTrustedStatus` for why this is a *claim*, not a fact.
    public let deviceContext: DeviceContext?
    
    public init(
        challengeId: String,
        method: AuthenticationMethod,
        credential: String,
        timestamp: Date = Date(),
        deviceContext: DeviceContext? = nil
    ) {
        self.challengeId = challengeId
        self.method = method
        self.credential = credential
        self.timestamp = timestamp
        self.deviceContext = deviceContext
    }
}
