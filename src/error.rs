use std::fmt::Display;

#[derive(Debug)]
pub enum JWTError {
    JWTParts,
    Header,
    PayloadField,
    HeaderField,
    NoAudience,
    WrongAudience,
    NoIss,
    WrongIss,
    WrongAlgorithm,
    NoAlgorithm,
    Expired,
    NoExp,
    ToBeValid,
    NoIat,
    NoNbf
}

#[derive(Debug)]
pub enum KeyError {
    Verification(ring::error::Unspecified),
    RSASignature(rsa::signature::Error),
    RSA(rsa::Error),
    JWKField,
    KeyField,
    KidField,
    KeyType,
    Kid,
    E,
    N
}

#[derive(Debug)]
pub enum ConstructionError {
    Aud,
    Iss,
    Keys
}

#[derive(Debug)]
pub enum Error {
    ParseTimestamp,
    JWT(JWTError),
    Key(KeyError),
    Parse(std::num::ParseIntError),
    File(std::io::Error),
    Decode(base64::DecodeError,&'static str),
    Serde(serde_json::Error),
    Construction(ConstructionError),
    UTF8(std::str::Utf8Error),
    Reqwest(reqwest::Error),
    Cataclysm(cataclysm::Error),
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
                    KeyError::KeyType => String::from(""),
                    KeyError::RSASignature(e) => format!("Error while verifying jwt with public key! {}",e)
                }
            },
            Error::Cataclysm(e) => format!("Cataclysm error! {}",e),
            Error::Construction(ce) => {
                match ce {
                    ConstructionError::Aud => format!("Missing audience field on constructor!"),
                    ConstructionError::Iss => format!("Missing isuer field on constructor!"),
                    ConstructionError::Keys => format!("Missing keys on constructor!")
                }
            }
            Error::File(e) => format!("File error! {}",e),
            Error::Reqwest(e) => format!("Reqest error while retrieving jwks! {}",e),
            Error::Serde(e) => format!("Serde error! {}",e),
            Error::Parse(e) => format!("Parseint error!° {}",e),
            Error::ParseTimestamp => String::from("Unable to get timestamp from 'exp' field!"),
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

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::File(value)
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