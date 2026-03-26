/// (1) Entry point of every SCA flow.
///
/// When a protected operation is requested, the client calls
/// `SCAProvider.startChallenge(for:context:)` and the server responds
/// with this struct describing what authentication is required.
///
/// Next step → (2) `DefaultSCAService.authenticate(challenge:)` reads this
/// and begins resolving methods + collecting proofs.
///
///  Based on PSD2 and OAuth 2.0 step-up authentication patterns.
import Foundation

public struct SCAChallenge: Sendable {
    
    /// Server-generated identifier linking all proofs back to this challenge.
    public let challengeId: String
    
    /// Methods the server says the user can authenticate with.
    ///
    /// Each method belongs to exactly one `PSD2Category`.
    /// The service iterates these to pick the best option automatically
    /// (see `DefaultSCAService.resolveMethod`).
    public let availableMethods: [AuthenticationMethod]
    
    /// How many **distinct PSD2 categories** must be satisfied.
    ///
    /// For anything calling itself SCA, this is at minimum 2
    /// (e.g. knowledge + possession, or inherence + possession).
    /// Device trust can implicitly cover one category (possession),
    /// reducing the number of explicit user interactions needed.
    public let minimumFactorsNeeded: Int
    
    /// Why authentication is needed — drives UI messaging
    /// and scopes the resulting token.
    public let reason: ChallengeReason
    
    /// Server-set expiration, typically 5 minutes.
    /// The service checks `isValid` before starting authentication.
    public let expiresAt: Date
    
    public init(
        challengeId: String,
        availableMethods: [AuthenticationMethod],
        minimumFactorsNeeded: Int = 2,
        reason: ChallengeReason,
        expiresAt: Date
    ) {
        self.challengeId = challengeId
        self.availableMethods = availableMethods
        self.minimumFactorsNeeded = minimumFactorsNeeded
        self.reason = reason
        self.expiresAt = expiresAt
    }
}

// MARK: - Derived Properties

public extension SCAChallenge {
    
    /// Distinct PSD2 categories present across `availableMethods`.
    var availableCategories: Set<PSD2Category> {
        Set(availableMethods.map { $0.category })
    }
    
    /// Whether this challenge is satisfiable from its method list alone.
    ///
    /// Note: doesn't account for device trust — `DefaultSCAService`
    /// adds implicit possession before checking satisfiability.
    var canBeSatisfied: Bool {
        availableCategories.count >= minimumFactorsNeeded
    }
}

// MARK: - Expiration

public extension SCAChallenge {
    
    /// `false` once `expiresAt` has passed — service will throw `.challengeExpired`.
    var isValid: Bool {
        expiresAt > Date()
    }
    
    var timeRemaining: TimeInterval {
        max(0, expiresAt.timeIntervalSinceNow)
    }
    
    /// Formatted as `"4:32"` — ready for countdown UI.
    var timeRemainingFormatted: String {
        let remaining = Int(timeRemaining)
        let minutes = remaining / 60
        let seconds = remaining % 60
        return String(format: "%d:%02d", minutes, seconds)
    }
}
