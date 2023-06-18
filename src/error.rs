#[derive(Debug)]
pub enum Error {
    /// Error on issuer valdiation
    IssuerError,
    /// Error on audience validation
    AudienceError,
    /// Error while decoding token
    DecodeError(base64::DecodeError),
    /// Error while decoding to utf8
    Utf8Error(std::str::Utf8Error),
    /// Error while using serde to deserialize
    SerdeError(serde_json::Error),
    /// Error while reading request header 'Authorization'
    HeaderError,
    /// Error while deserializing header from jwt
    JWTHeaderError(serde_json::Error),
    /// Error because of lack of configuration
    JWTConfig,
    /// Error when no sign algorithm coincides with the ones implemented
    NoAlgorithm,
    /// Error secret not provided or is unusable
    SecretKeyError,
    /// Alg from jwt and server config do not match
    AlgorithmMatch,
    /// Key store does not exists or is unreachable
    KeyStoreError,
    /// Reqwest error. URL for key store may be unreachable
    ReqwestError(reqwest::Error),
    /// Error while constructing jwt rs256 public key
    KeyLenght,
    PayloadError,
    UnprotectedJWT,
    VerificationError(ring::error::Unspecified),
    JWTParts,
    NoInternalKey,
    Custom(String)
}

impl std::fmt::Display for Error {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        let writing = match self {
            Error::IssuerError => format!("An audience must be provided before constructing the JTW middleware structure!"),
            Error::AudienceError => format!("An issuer must be provided before constructing the JWT middleware structure!"),
            Error::DecodeError(e) => format!("An error occurred while decoding b64 JWT: {}",e),
            Error::Utf8Error(e) => format!("An error occurred while utf8 parsing: {}",e),
            Error::SerdeError(e) => format!("A serde error has occurred: {}",e),
            Error::HeaderError => format!("Authorization or authorization header not found!"),
            Error::JWTHeaderError(e) => format!("Could not deserialize JWT header into Header struct: {}",e),
            Error::JWTConfig => format!("Server lacks JWT configuration!"),
            Error::NoAlgorithm => format!("No algorithm implemented matches the one provided!"),
            Error::SecretKeyError => format!("No secret key or URL provided to verify signature or is unusable!"),
            Error::AlgorithmMatch => format!("Signing algorithm from jwt and server do not match!"),
            Error::KeyStoreError => format!("Key store string is empty"),
            Error::ReqwestError(e) => format!("Reqwest error: {}",e),
            Error::KeyLenght => format!("There is more than one key with same id present in JWKS or no key at all"),
            Error::PayloadError => format!("To string conversion failed for payload!"),
            Error::UnprotectedJWT => format!("Could not for unprotected JWT for validation!"),
            Error::VerificationError(e) => format!("Verification failed for JWT! {}",e),
            Error::Custom(s) => format!("{}",s),
            Error::JWTParts => format!("Parts on jwt token are more or less than three! (format should be 'a.b.c')"),
            Error::NoInternalKey => format!("Internal key was not specified when struct was created")
        };

        write!(f,"{}",writing)

    }
    

}