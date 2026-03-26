/// Hardware abstraction over Face ID / Touch ID.
///
/// `DefaultSCAService` checks `isAvailable` during method resolution
/// and calls `authenticate(reason:)` when collecting an inherence factor.
/// If biometrics fail or are unavailable, the service skips inherence
/// and falls back to the next priority category.
///
/// The app injects either:
/// - A real implementation wrapping `LAContext` (production)
/// - A mock returning configurable results (testing/demo)
public protocol BiometricProvider: Sendable {
    
    /// Whether biometrics can be used right now.
    ///
    /// Checks hardware presence, enrollment, and lockout status.
    /// Called by `resolveMethod` before committing to inherence.
    var isAvailable: Bool { get async }
    
    /// Which biometric the device supports, if any.
    ///
    /// Useful for UI — showing a Face ID icon vs Touch ID icon.
    /// `nil` when biometrics are unavailable.
    var biometricType: BiometricType? { get async }
    
    /// Prompt the user for biometric authentication.
    ///
    /// - Parameter reason: Localized string shown on the system prompt
    ///   (e.g. `"Confirm payment of $500"`). Maps from `ChallengeReason.rawValue`.
    /// - Returns: `true` on success
    /// - Throws: `BiometricError` on failure or cancellation —
    ///   the service catches this and skips to the next category.
    func authenticate(reason: String) async throws -> Bool
}

public enum BiometricType: Sendable {
    case faceID
    case touchID
}

public enum BiometricError: Error {
    case userCancelled
    case authenticationFailed
    case biometricsLocked
    case notEnrolled
    case notAvailable
}
