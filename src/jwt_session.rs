use std::{str::FromStr, collections::{BTreeMap, HashMap}};
use base64::{Engine as _, engine::general_purpose};
use jwt_simple::prelude::{HS256Key, RS256PublicKey};
use crate::{Error, Header, jwt::JWK};
use cataclysm::{http::Request, session::Session};

/// Possible signing algorithms for JWT. There are more, but only basic ones are provided.
/// If none is chosen, then no sign validation will be made.
#[derive(PartialEq,Eq)]
pub enum SigningAlgorithm {
    RS256,
    HS256,
    None
}

/// A priori information to valdiate JWT: Who issued it, who is intended to read it and which algorithm was used to preserve information unchanged.
/// Since token is not issued by the same server that validates it, we cannot trust its header which contains this information, rather it needs to be validated.
/// The payload is information that is obtained every time in a session
pub struct JWTAsymmetricSession {
    pub aud: String,
    pub iss: String,
    key_store: Option<Vec<RS256PublicKey>>,
}

pub struct JWTSymmetricSession {
    pub aud: String,
    pub iss: String,
    secret_key: Option<HS256Key>,
}

/// Builder to create a JWTSession easily.
pub struct JWTSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    secret_key: Option<String>,
    public_keys_url: Option<String>,
    sign_algorithm: SigningAlgorithm
}

impl FromStr for SigningAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        
        let return_value = match s {
            "RS256" => SigningAlgorithm::RS256,
            "HS256" => SigningAlgorithm::HS256,
            "none" => SigningAlgorithm::None,
            _ => {
                return Err(Error::NoAlgorithm);
            }
        };

        Ok(return_value)
    }

}

impl JWTSession {
    
    /// Returns a builder
    pub fn builder() -> JWTSessionBuilder {
        JWTSessionBuilder::new()
    }

    /// Does initial validation (sign, issuer and aud)
    pub fn validation(&self) -> bool {
        todo!()
    }

    /// Checks every claim that should be present according to RFC
    fn initial_check(&self, header: Header, signature: String) -> Result<(),Error> {

        // For now we only check the algorithm
        let alg = match &header.alg {
            Some(alg) => {
                SigningAlgorithm::from_str(&alg)?
            },
            None => {
                return Err(Error::NoAlgorithm)
            }
        };

        if alg != self.sign_algorithm {
            return Err(Error::AlgorithmMatch);
        }

        let payload: BTreeMap<String,String> = match self.sign_algorithm {
            SigningAlgorithm::HS256 => {
                
            },
            SigningAlgorithm::RS256 => {

            },
            None => {}
        };

        todo!()
    }

    pub fn build_from_req(&self, req: &Request) -> Result<Option<Session>,Error> {

        let authorization_header = match req.headers.get("Authorization") {
            Some(a) => a,
            None => {
                match req.headers.get("authorization") {
                    Some(a_t) => a_t,
                    None => {
                        return Err(Error::HeaderError);
                    }
                }
            }
        };

        let token: String = authorization_header[0].split(' ').collect::<String>();
        let token_parts: Vec<&str> = token.split('.').collect();

        let signature = match general_purpose::URL_SAFE_NO_PAD.decode(token_parts[2]) {
            Ok(s) => match std::str::from_utf8(&s) {
                Ok(s_s) => s_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        let header_string = match general_purpose::URL_SAFE_NO_PAD.decode(token_parts[0]) {
            Ok(h) => match std::str::from_utf8(&h) {
                Ok(h_s) => h_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        let header: Header = match serde_json::from_str(&header_string) {
            Ok(h) => h,
            Err(e) => {
                return Err(Error::JWTHeaderError(e))
            }
        };

        self.initial_check(header,signature)?;

        let payload = match general_purpose::URL_SAFE_NO_PAD.decode(token_parts[1]) {
            Ok(p) => match std::str::from_utf8(&p) {
                Ok(p_s) => p_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        todo!()

    }
}

impl JWTSessionBuilder {

    /// New default instance
    pub fn new() -> Self {
        JWTSessionBuilder {
            aud: None,
            iss: None,
            secret_key: None,
            public_keys_url: None,
            sign_algorithm: SigningAlgorithm::None
        }
    }

    pub fn audience<A: AsRef<str>>(self,aud: A) -> Self {
        Self {
            aud: Some(aud.as_ref().into()),
            ..self
        }
    }

    pub fn issuer<A: AsRef<str>>(self, iss: A) -> Self {
        Self {
            iss: Some(iss.as_ref().into()),
            ..self
        }
    }

    pub fn hs256_signing_algorithm<A: AsRef<str>>(self, secret_key: A) -> Self {
        Self {
            sign_algorithm: SigningAlgorithm::HS256,
            secret_key: Some(secret_key.as_ref().into()),
            public_keys_url: None,
            ..self
        }
    }

    pub fn rs256_signing_algorithm<A: AsRef<str>>(self, sign_algorithm: SigningAlgorithm, public_keys_url: A) -> Self {
        Self {
            sign_algorithm: SigningAlgorithm::RS256,
            public_keys_url: Some(public_keys_url.as_ref().to_string()),
            secret_key: None,
            ..self
        }
    }

    pub fn no_signing_algorithm(self) -> Self {
        Self {
            sign_algorithm: SigningAlgorithm::None,
            public_keys_url: None,
            secret_key: None,
            ..self
        }
    }

    pub fn build(self) -> Result<JWTSession,Error> {

        let aud = match self.aud {
            None => {
                return Err(Error::AudienceError);
            },
            Some(a) => a
        };

        let iss = match self.iss {
            None => {
                return Err(Error::IssuerError);
            },
            Some(i) => i
        };

        let secret_key = match self.secret_key {
            None => {
                return Err(Error::SecretKeyError);
            },
            Some(sk) => {
                Some(HS256Key::from_bytes(sk.as_bytes()))
            }
        };

        let key_store: Option<Vec<RS256PublicKey>> = match self.public_keys_url {
            None => {
                return Err(Error::KeyStoreError);
            },
            Some(ks) => {

                let body = reqwest::blocking::get(ks).map_err(|e| Error::ReqwestError(e))?.text().map_err(|e| Error::ReqwestError(e))?;
                let public_keys: Vec<JWK> = serde_json::from_str(&body).map_err(|e| Error::SerdeError(e))?;

                Some(public_keys.into_iter().map(|jwk| -> Result<RS256PublicKey,Error> {

                    RS256PublicKey::from_components(jwk.n.as_bytes(),jwk.e.as_bytes()).map_err(|e| Error::RS256PublicKey(e))
                
                }).collect::<Result<Vec<RS256PublicKey>,_>>()?)
            
            }
        };

        Ok(JWTSession {
            aud,    
            iss,
            secret_key,
            key_store,
            sign_algorithm: self.sign_algorithm,
        })
    }

}