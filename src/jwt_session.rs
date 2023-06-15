use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};
use jwt_simple::prelude::{HS256Key, RS256PublicKey, RSAPublicKeyLike, VerificationOptions, NoCustomClaims};
use crate::{Error, Header, jwt::JWK};
use cataclysm::{http::Request, session::Session};

/// Possible signing algorithms for JWT. There are more, but only basic ones are provided.
/// If none is chosen, then no sign validation will be made.
#[derive(PartialEq,Eq)]
pub enum SigningAlgorithm {
    RS256,
    HS256
}

/// A priori information to valdiate JWT: Who issued it, who is intended to read it and which algorithm was used to preserve information unchanged.
/// Since token is not issued by the same server that validates it, we cannot trust its header which contains this information, rather it needs to be validated.
/// The payload is information that is obtained every time in a session
pub struct JWTAsymmetricSession {
    pub aud: String,
    pub iss: String,
    key_store: Vec<(JWK,RS256PublicKey)>,
    verification_options: Option<VerificationOptions>,
}

pub struct JWTSymmetricSession {
    pub aud: String,
    pub iss: String,
    secret_key: HS256Key,
    verification_options: Option<VerificationOptions>,
}

/// Builder to create a JWTSession easily.
pub struct JWTSessionBuilder;

pub struct JWTSymmetricSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    secret_key: Option<String>,
    verification_options: Option<VerificationOptions>,
}

pub struct JWTAsymmetricSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    public_keys_url: Option<String>,
    verification_options: Option<VerificationOptions>,
}

impl JWTSessionBuilder {
    pub fn new_with_hs256_signing() -> JWTSymmetricSessionBuilder {
        JWTSymmetricSessionBuilder {
            aud: None,
            iss: None,
            secret_key: None,
            verification_options: None
        }
    }

    pub fn new_with_rs256_signing() -> JWTAsymmetricSessionBuilder {
        JWTAsymmetricSessionBuilder {
            aud: None,
            iss: None,
            public_keys_url: None,
            verification_options: None
        }
    }
}

impl JWTSymmetricSessionBuilder {

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

    pub fn verification_options(self, verification_options: VerificationOptions) -> Self {
        Self {
            verification_options: Some(verification_options),
            ..self
        }
    }

    pub fn hs256_key<A: AsRef<str>>(self, hs256: A) -> Self {
        Self {
            secret_key: Some(hs256.as_ref().to_string()),
            ..self
        }
    }

    pub fn build(self) -> Result<JWTSymmetricSession,Error> {

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
                HS256Key::from_bytes(sk.as_bytes())
            }
        };

        Ok(JWTSymmetricSession {
            aud,    
            iss,
            secret_key,
            verification_options: self.verification_options
        })

    }


}

impl JWTAsymmetricSessionBuilder {

    pub fn audience<A: AsRef<str>>(self,aud: A) -> Self {
        Self {
            aud: Some(aud.as_ref().into()),
            ..self
        }
    }

    pub fn verification_options(self, verification_options: VerificationOptions) -> Self {
        Self {
            verification_options: Some(verification_options),
            ..self
        }
    }

    pub fn issuer<A: AsRef<str>>(self, iss: A) -> Self {
        Self {
            iss: Some(iss.as_ref().into()),
            ..self
        }
    }

    pub fn jwks<A: AsRef<str>>(self, public_keys_url: A) -> Self {
        Self {
            public_keys_url: Some(public_keys_url.as_ref().to_string()),
            ..self
        }
    }

    pub fn build(self) -> Result<JWTAsymmetricSession,Error> {

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

        let key_store: Vec<(JWK,RS256PublicKey)> = match self.public_keys_url {
            None => {
                return Err(Error::KeyStoreError);
            },
            Some(ks) => {

                let body = reqwest::blocking::get(ks).map_err(|e| Error::ReqwestError(e))?.text().map_err(|e| Error::ReqwestError(e))?;

                serde_json::from_str::<Vec<JWK>>(&body).map_err(|e| Error::SerdeError(e)).into_iter().map(|k| -> Result<(JWK,RS256PublicKey),Error> {

                    let rskey = RS256PublicKey::from_components(k.n.as_bytes(), k.e.as_bytes()).map_err(|e| Error::RS256PublicKey(e))?;
                    Ok((k,rskey))
                
                })?
            
            }
        };

        Ok(JWTAsymmetricSession {
            aud,    
            iss,
            key_store,
            verification_options: self.verification_options
        })
    }

}

pub trait JWTSession {
    
    fn build() -> JWTSessionBuilder {
        JWTSessionBuilder {}
    }

    fn build_session_from_req(&self, req: &Request) -> Result<Option<Session>,Error> {

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

        self.initial_validation(header,&token)?;

        let payload: HashMap<String,String> = match general_purpose::URL_SAFE_NO_PAD.decode(token_parts[1]) {
            Ok(p) => match std::str::from_utf8(&p) {
                Ok(p_s) => serde_json::from_str(p_s).map_err(|e| Error::SerdeError(e))?,
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        return Ok(Some(Session::new_with_values(self.clone(), payload)))
    
    }

    fn initial_validation<A: AsRef<str>>(&self, header: Header, token_str: A) -> Result<(),Error>;

}

impl JWTSession for JWTAsymmetricSession {

    fn initial_validation<A: AsRef<str>>(&self, header: Header, token_str: A) -> Result<(),Error> {
        
        // Check the algorithm
        match header.alg {
            Some(a) => {
                if a.to_uppercase().as_str() != "RS256" {
                    return Err(Error::NoAlgorithm);
                }
            },
            None => {
                return Err(Error::NoAlgorithm);
            }
        }

        // Check key id
        let key = self.key_store.iter().filter(|jwk| {
            header.kid == jwk.kid
        }).map(|jwk| -> Result<RS256PublicKey,Error> {
            RS256PublicKey::from_components(jwk.n.as_bytes(), jwk.e.as_bytes()).map_err(|e| Error::RS256PublicKey(e))
        }).collect::<Result<Vec<RS256PublicKey>,_>>()?;

        if key.len() > 1 || key.len() == 0 {
            return Err(Error::KeyLenght)
        }

        // check signature and use verification options
        key[0].verify_token::<NoCustomClaims>(token_str.as_ref(), self.verification_options.clone()).map_err(|e| Error::VerificationFailed(e)).map(|_| {()})
    }

}

impl JWTSession for JWTSymmetricSession {

    fn initial_validation<A: AsRef<str>>(&self, header: Header, token_str: A) -> Result<(),Error> {
        
        match header.alg {
            Some(a) => {
                if a.to_uppercase().as_str() != "HS256" {
                    return Err(Error::NoAlgorithm);
                }
            },
            None => {
                return Err(Error::NoAlgorithm);
            }
        }

        

        todo!()

    }

}