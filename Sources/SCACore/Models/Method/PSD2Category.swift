/// PSD2 requires that SCA uses factors from at least two
/// **distinct** categories. Two knowledge factors (password + PIN)
/// count as one — the categories must differ.
///
/// `DefaultSCAService` tracks satisfied categories as a `Set<PSD2Category>`
/// and loops until the set size meets `SCAChallenge.minimumFactorsNeeded`.
public enum PSD2Category: String, Codable, Sendable {
    /// Something the user knows (password, PIN).
    case knowledge
    
    /// Something the user has (phone for OTP, trusted device).
    case possession
    
    /// Something the user is (Face ID, Touch ID, fingerprint).
    case inherence
}
