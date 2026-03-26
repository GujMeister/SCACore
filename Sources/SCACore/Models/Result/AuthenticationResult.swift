/// (3) What the server returns once all factors are satisfied.
///
/// After the final `SCAProvider.verify(proof:)` returns `.complete`,
/// `DefaultSCAService` stores tokens via `SecureStorage`, optionally
/// prompts for device trust, and hands this back to the caller.
///
/// Token lifecycle:
/// 1. Client completes SCA → server returns this
/// 2. Client attaches `authenticationToken` to protected requests
/// 3. Token expires → `refreshIfNeeded` uses `refreshToken` silently
/// 4. Refresh token also expired → full SCA restart
///
/// Modeled after OAuth 2.0 token response.
import Foundation

public struct AuthenticationResult: Sendable {
    
    /// Short-lived access token attached to protected requests.
    /// Typically 300s for SCA — intentionally shorter than session tokens.
    public let authenticationToken: String
    
    /// Almost always `"Bearer"`. Included for OAuth 2.0 compliance.
    public let tokenType: String
    
    /// Access token lifetime in seconds.
    public let expiresIn: Int
    
    /// Longer-lived token for silent renewal (24–72h).
    ///
    /// Single-use with rotation: server invalidates on use and issues a new one.
    /// Must be stored in Keychain, never UserDefaults.
    ///
    /// `nil` when the server requires full re-auth every time
    /// (e.g. high-value transfers).
    public let refreshToken: String?
    
    /// What this token authorizes — maps 1:1 to `ChallengeReason`.
    ///
    /// A `.payment` token cannot be used for `.settingsChange`.
    /// Server encodes this as a JWT claim and enforces on every request.
    public let scope: ChallengeReason
    
    /// Which methods completed the challenge — for audit trails.
    public let usedMethods: [AuthenticationMethod]
    
    /// Server timestamp of issuance.
    public let createdAt: Date
    
    public init(
        authenticationToken: String,
        tokenType: String = "Bearer",
        expiresIn: Int,
        refreshToken: String? = nil,
        scope: ChallengeReason,
        usedMethods: [AuthenticationMethod],
        createdAt: Date = Date()
    ) {
        self.authenticationToken = authenticationToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.scope = scope
        self.usedMethods = usedMethods
        self.createdAt = createdAt
    }
}

// MARK: - Token Validity

public extension AuthenticationResult {
    
    var expiresAt: Date {
        createdAt.addingTimeInterval(TimeInterval(expiresIn))
    }
    
    /// `false` once `expiresAt` has passed — caller should try `refreshIfNeeded`.
    var isValid: Bool {
        expiresAt > Date()
    }
    
    var timeRemaining: TimeInterval {
        max(0, expiresAt.timeIntervalSinceNow)
    }
    
    /// Ready to drop into `URLRequest.setValue(_:forHTTPHeaderField: "Authorization")`.
    var authorizationHeader: String {
        "\(tokenType) \(authenticationToken)"
    }
}

// MARK: - Factor Analysis

public extension AuthenticationResult {
    
    /// Distinct PSD2 categories used.
    /// Password + PIN = 1 (both knowledge). Password + SMS = 2.
    var factorCount: Int {
        Set(usedMethods.map { $0.category }).count
    }
    
    /// True SCA: 2+ different PSD2 categories were satisfied.
    var isMultiFactor: Bool {
        factorCount >= 2
    }
}

// MARK: - Refresh & Scope

public extension AuthenticationResult {
    
    /// Access token expired but refresh token exists — can attempt silent renewal
    /// via `SCAService.refreshIfNeeded` instead of full re-auth.
    var canRefresh: Bool {
        !isValid && refreshToken != nil
    }
    
    /// Client-side scope check. Server enforces this too,
    /// but checking locally avoids a wasted network round-trip.
    func isAuthorized(for reason: ChallengeReason) -> Bool {
        isValid && scope == reason
    }
}
