use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum JWTError {
    JWTParts,
    Header,
    JWKS,
    PayloadField,
    HeaderField,
    MissingKey,
    WrongAlgorithm,
    NoAlgorithm,
}

#[derive(Debug)]
pub enum KeyError {
    Verification(ring::error::Unspecified),
    Rejected(ring::error::KeyRejected),
    KeyType,
    Kid,
}

#[derive(Debug)]
pub enum ConstructionError {
    Aud,
    Iss,
    Keys
}

#[derive(Debug)]
pub enum Error {
    JWT(JWTError),
    Key(KeyError),
    File(std::io::Error),
    Decode(base64::DecodeError),
    Serde(serde_json::Error),
    Construction(ConstructionError),
    UTF8(std::str::Utf8Error),
    OpenSSL(ErrorStack),
    Reqwest(reqwest::Error),
    Cataclysm(cataclysm::Error)
}

impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Error::Decode(value)
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(value: ring::error::Unspecified) -> Self {
        Error::Key(KeyError::Verification(value))
    }
}

impl From<ring::error::KeyRejected> for Error {
    fn from(value: ring::error::KeyRejected) -> Self {
        Error::Key(KeyError::Rejected(value))
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::File(value)
    }
}

impl From<ErrorStack> for Error {
    fn from(value: ErrorStack) -> Self {
        Error::OpenSSL(value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::Reqwest(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::Serde(value)
    }
}

impl From<cataclysm::Error> for Error {
    fn from(value: cataclysm::Error) -> Self {
        Error::Cataclysm(value)
    }
}