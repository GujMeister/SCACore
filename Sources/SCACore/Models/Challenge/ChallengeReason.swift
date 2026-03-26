/// Why authentication is being requested.
///
/// Sent with the challenge request and embedded in the resulting token's scope.
/// A token scoped to `.payment` cannot authorize `.settingsChange`
public enum ChallengeReason: String, Sendable, Codable, CaseIterable {
    case login
    case payment
    case settingsChange
    case sessionExpired
    case riskAssessment
}
