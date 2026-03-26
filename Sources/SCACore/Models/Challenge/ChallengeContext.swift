
/// Additional context sent alongside a challenge request.
///
/// Lets the server apply risk-based decisions — a $10 transfer
/// might require fewer factors than a $10,000 one.
///
/// Usage:
/// ```swift
/// let context = ChallengeContext(amount: 5000, recipientId: "IBAN-123")
/// let challenge = try await provider.startChallenge(for: .payment, context: context)
/// ```

import Foundation

public struct ChallengeContext: Sendable {
    
    /// User's email, if relevant (e.g. email-change confirmation).
    public let email: String?
    
    /// Transaction amount for payments/transfers — server uses this for risk scoring.
    public let amount: Decimal?
    
    /// Recipient identifier for transfers.
    public let recipientId: String?
    
    /// Free-form metadata for cases the fixed fields don't cover.
    public let metadata: [String: String]?
    
    public init(
        email: String? = nil,
        amount: Decimal? = nil,
        recipientId: String? = nil,
        metadata: [String: String]? = nil
    ) {
        self.email = email
        self.amount = amount
        self.recipientId = recipientId
        self.metadata = metadata
    }
}
