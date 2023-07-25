mod rs256_session;
mod hs256_session;

pub use rs256_session::JWTRS256Session;
pub use hs256_session::JWTHS256Session;

use crate::{sign_algorithms::RS256, Error, error::{ConstructionError, JWTError, KeyError}, JWT};

use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use std::collections::HashMap;
use cataclysm::{session::{SessionCreator, Session}, http::Request};

trait JWTSession: Clone + SessionCreator {

    fn initial_validation(&self, header: &HashMap<String, String>, jwt: &str) -> Result<(),Error>;

    fn obtain_token_from_req(req: &Request) -> Result<JWT,Error> {

        let authorization_header = match req.headers.get("Authorization") {
            Some(a) => a,
            None => {
                match req.headers.get("authorization") {
                    Some(a_t) => a_t,
                    None => {
                        return Err(Error::JWT(JWTError::Header));
                    }
                }
            }
        };
        
        let token: String = authorization_header[0].split(' ').collect::<Vec<&str>>()[1].to_string();
        let token_parts: Vec<&str> = token.split('.').collect();

        let header = match general_purpose::URL_SAFE_NO_PAD.decode(token_parts[0]) {
            Ok(h) => match std::str::from_utf8(&h) {
                Ok(h_s) => {

                    serde_json::from_str::<HashMap<String,Value>>(h_s).map_err(|e| Error::Serde(e))?.into_iter().map(|(k,v)| -> Result<(String,String),Error> {
                        let v = if v.is_string() {
                            v.as_str().ok_or(Error::JWT(JWTError::HeaderField))?.to_string()
                        } else {
                            v.to_string()
                        };
                        Ok((k,v))
                    }).collect::<Result<HashMap<String,String>,_>>()?

                },
                Err(e) => return Err(Error::UTF8(e))
            },
            Err(e) => return Err(Error::Decode(e, "Unable to decode jwt header into HashMap!"))
        };
        
        let payload: HashMap<String,String> = match general_purpose::URL_SAFE_NO_PAD.decode(token_parts[1]) {
            Ok(p) => match std::str::from_utf8(&p) {
                Ok(p_s) => {

                    serde_json::from_str::<HashMap<String,Value>>(p_s).map_err(|e| Error::Serde(e))?.into_iter().map(|(k,v)| -> Result<(String,String),Error> {
                        let v = if v.is_string() {
                            v.as_str().ok_or(Error::JWT(JWTError::PayloadField))?.to_string()
                        } else {
                            v.to_string()
                        };
                        Ok((k,v))
                    }).collect::<Result<HashMap<String,String>,_>>()?

                },
                Err(e) => return Err(Error::UTF8(e))
            },
            Err(e) => return Err(Error::Decode(e,"Unable to decode jwt payload into HashMap!"))
        };

        let signature = token_parts[2].to_string();
        
        Ok(JWT {
            header,
            payload,
            signature,
            raw_jwt: token
        })
    }

    fn build_from_req(&self, req: &Request) -> Result<HashMap<String,String>, Error>;

}

#[derive(Default)]
pub struct JWTSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    verification_keys: Option<HashMap<String,RS256>>
}

impl JWTSessionBuilder {
    
    pub fn aud<A: AsRef<str>>(self, aud: A) -> Self {
        Self {
            aud: Some(aud.as_ref().to_string()),
            ..self
        }
    }

    pub fn iss<A: AsRef<str>>(self, iss: A) -> Self {
        Self {
            iss: Some(iss.as_ref().to_string()),
            ..self
        }
    }

    pub fn add_verification_key<A: AsRef<str>>(self, key: RS256, kid: A) -> Self {

        let vk = match self.verification_keys {
            Some(mut v) => {
                v.insert(kid.as_ref().to_string(), key);
                v
            },
            None => {
                HashMap::from([(kid.as_ref().to_string(),key)])
            }
        };

        Self {
            verification_keys: Some(vk),
            ..self
        }
    }

    pub async fn add_from_jwks<A: AsRef<str>>(self, url: A) -> Result<Self,Error> {

        let jwks = reqwest::get(url.as_ref()).await?.text().await?;
        
        let jwks_hm = serde_json::from_str::<HashMap<String,Value>>(&jwks)?.into_iter().map(|(k,v)| -> Result<(String,Vec<HashMap<String,String>>),Error> {
            
            let v = v.to_string();

            let jwk = serde_json::from_str::<Vec<HashMap<String,Value>>>(&v)?.into_iter().map(|hm| -> Result<HashMap<String,String>,Error> {
                
                hm.into_iter().map(|(hk,hv)| -> Result<(String,String),Error> {
                    let hv = if hv.is_string() {
                        hv.as_str().ok_or(Error::Key(KeyError::JWKField))?.to_string()
                    } else {
                        hv.to_string()
                    };
                    Ok((hk,hv))
                }).collect::<Result<HashMap<String,String>,Error>>()

            }).collect::<Result<Vec<HashMap<String,String>>,Error>>()?;

            Ok((k,jwk))
        
        }).collect::<Result<HashMap<String,Vec<HashMap<String,String>>>,_>>()?;

        let jwks_vec = jwks_hm.get("keys").ok_or(Error::Key(KeyError::KeyField))?;

        let rs256_hm = jwks_vec.iter().map(|jwk_hm| -> Result<(String,RS256),Error> {

            let kid = match jwk_hm.get("kid") {
                Some(id) => id,
                None => {
                    return Err(Error::Key(KeyError::KidField));
                }
            };

            let e = match jwk_hm.get("e") {
                Some(ee) => ee,
                None => {
                    return Err(Error::Key(KeyError::E));
                }
            };

            let n = match jwk_hm.get("n") {
                Some(nn) => nn,
                None => {
                    return Err(Error::Key(KeyError::N));
                }
            };

            let rs256 = RS256::new_from_primitives(n, e)?;

            Ok((kid.to_string(),rs256))

        }).collect::<Result<HashMap<String,RS256>,Error>>()?;

        Ok(Self {
            verification_keys: Some(rs256_hm),
            ..self
        })

    }

    pub fn build(self) -> Result<JWTRS256Session, Error> {
        
        let aud = match self.aud {
            Some(a) => a,
            None => {
                return Err(Error::Construction(ConstructionError::Aud));
            }
        };

        let iss = match self.iss {
            Some(i) => i,
            None => {
                return Err(Error::Construction(ConstructionError::Iss));
            }
        };

        let verification_keys = match self.verification_keys {
            Some(k) => k,
            None => {
                return Err(Error::Construction(ConstructionError::Keys))
            }
        };
        
        Ok(JWTRS256Session {
            aud,
            iss,
            verification_keys,
        })
    }

}

