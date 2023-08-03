use std::fmt::Display;

#[derive(Debug)]
/// Sub error for JWT
pub enum JWTError {
    /// Occurs when JWT can be divided in more or less than three
    JWTParts,
    /// Happens when Header 'authorization' or 'Authorization is not present'
    Header,
    /// Happens when jwt payload is unable to be decoded or obtained.
    PayloadField,
    /// Happens when jwt header is unable to be decoded or obtained.
    HeaderField,
    /// Happens when no audience is in header and lax-security is not enabled.
    NoAudience,
    /// Happens when wrong audience was found on token and lax-security is not enabled.
    WrongAudience,
    /// Happens when no issuer was fopund on jwt
    NoIss,
    /// Happens when issuer differs from the one expected
    WrongIss,
    /// When algorithm does not match the one expected by the server
    WrongAlgorithm,
    /// When no algorithm was found on jwt
    NoAlgorithm,
    /// When jwt has expired
    Expired,
    /// When no expiration date was found
    NoExp,
    /// When iat or nbf comprises a time window that is yet ro happen
    ToBeValid,
    /// No iat was found on jwt
    NoIat,
    /// No nbf was found on jwt
    NoNbf
}

#[derive(Debug)]
/// Sub error for Keys creation and verification
pub enum KeyError {
    /// Error when trying to verify symmetric signature
    Verification(ring::error::Unspecified),
    /// Error when trying to verify assymmetric signature
    RSASignature(rsa::signature::Error),
    /// Error from RSA crate when trying to create a public key from modulus 'n' and exponent 'e'
    RSA(rsa::Error),
    /// Unable to convert JWK field to string
    JWKField,
    /// Did not find keys field on JWKS array
    KeyField,
    /// Kid not present on JWK
    KidField,
    /// Did not find key with kid specified
    Kid,
    /// Could not find primitive exponent 'e' on JWK
    E,
    /// Could not find primitive exponent 'n' on JWK
    N
}

#[derive(Debug)]
/// Sub error for creating session
pub enum ConstructionError {
    /// Did not find audience on JWTSession
    Aud,
    /// Did not find issuer on JWTSession
    Iss,
    /// Could not 
    Keys
}

#[derive(Debug)]
/// Main error
pub enum Error {
    /// Unable to parse timestamp for 'nbf', 'iat' or 'exp' fields
    ParseTimestamp,
    /// JWT sub error
    JWT(JWTError),
    /// Key sub error
    Key(KeyError),
    /// Parse error while converting 'nbf', 'iat' or 'exp' to integers to parse to timestamp
    Parse(std::num::ParseIntError),
    /// Decode base64 url safe error while parsing JWT
    Decode(base64::DecodeError,&'static str),
    /// Serde error while deserializing JWT parts into HashMaps
    Serde(serde_json::Error),
    /// Construction sub error
    Construction(ConstructionError),
    /// UTF8 error while decoding JWT from base64
    UTF8(std::str::Utf8Error),
    /// Reqwest error while trying to obtain JWK array (JWKS)
    Reqwest(reqwest::Error),
}

impl Display for Error {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string_to_write = match self {
            Error::JWT(jwte) => {
                match jwte {
                    JWTError::JWTParts => String::from("JWT has more or less than three parts!"),
                    JWTError::Header => String::from("Unable to find 'Authorization' header on request!"),
                    JWTError::HeaderField => String::from("Unable to decode header field into string!"),
                    JWTError::NoAlgorithm => String::from("Unable to determine algorithm based on header"),
                    JWTError::PayloadField => String::from("Unable to decode jwt payload field to string!"),
                    JWTError::WrongAlgorithm => String::from("Algorithm on verification key and algorithm on jwt do not match!"),
                    JWTError::NoAudience => String::from("No Audience found on payload!"),
                    JWTError::WrongAudience => String::from("Audience on payload and audience on server do not match!"),
                    JWTError::NoIss => String::from("No Issuer found on payload!"),
                    JWTError::WrongIss => String::from("Issuer on payload and issuer on server do not match!"),
                    JWTError::Expired => String::from("Token expired"),
                    JWTError::NoExp => String::from("No exp found on payload!"),
                    JWTError::ToBeValid => String::from("validation time Window not valid yet!"),
                    JWTError::NoIat => String::from("No iat found on payload!"),
                    JWTError::NoNbf => String::from("No nbf found on payload!"),
                }
            },
            Error::Decode(e,s) => {
                format!("Decoding error: {}, With detail: {}",e,s)
            },
            Error::Key(ke) => {
                match ke {
                    KeyError::RSA(e) => format!("Unable to create public key from primitives 'n' and 'e'! {}",e),
                    KeyError::Verification(e) => format!("Verification error! {}",e),
                    KeyError::JWKField => String::from("Unable to decode jwk field!"),
                    KeyError::KidField => String::from("Unable to find 'kid' field"),
                    KeyError::KeyField => String::from("Unable to obtain 'key' field on jwk"),
                    KeyError::E => String::from("Unable to obtain 'e' field on jwk"),
                    KeyError::N => String::from("Unable to obtain 'n' field on jwk"),
                    KeyError::Kid => String::from("Unable to find key with 'kid' provided"),
                    KeyError::RSASignature(e) => format!("Error while verifying jwt with public key! {}",e)
                }
            },
            Error::Construction(ce) => {
                match ce {
                    ConstructionError::Aud => format!("Missing audience field on constructor!"),
                    ConstructionError::Iss => format!("Missing isuer field on constructor!"),
                    ConstructionError::Keys => format!("Missing keys on constructor!")
                }
            }
            Error::Reqwest(e) => format!("Reqest error while retrieving jwks! {}",e),
            Error::Serde(e) => format!("Serde error! {}",e),
            Error::Parse(e) => format!("Parseint error!° {}",e),
            Error::ParseTimestamp => String::from("Unable to get timestamp from 'exp', 'iat' or 'nbf' fields!"),
            Error::UTF8(e) => format!("UTF8 error! Unable to parse jwt into utf8 {}",e)
        };

        write!(f,"{}",string_to_write)
    }

}

impl From<ring::error::Unspecified> for Error {
    fn from(value: ring::error::Unspecified) -> Self {
        Error::Key(KeyError::Verification(value))
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

impl From<rsa::Error> for Error {
    fn from(value: rsa::Error) -> Self {
        Error::Key(KeyError::RSA(value))
    }
}

impl From<rsa::signature::Error> for Error {
    fn from(value: rsa::signature::Error) -> Self {
        Error::Key(KeyError::RSASignature(value))
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(value: std::num::ParseIntError) -> Self {
        Error::Parse(value)
    }
}