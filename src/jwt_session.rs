use cataclysm::{session::{SessionCreator, Session}, http::Request};
use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use std::collections::HashMap;

use crate::{sign_algorithms::JWTAlgorithm, Error, error::{ConstructionError, JWTError}, JWT};

pub struct JWTSession {
    pub aud: String,
    pub iss: String,
    pub keys: HashMap<String,Box<dyn JWTAlgorithm>>
}

#[derive(Default)]
pub struct JWTSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    keys: Option<HashMap<String,Box<dyn JWTAlgorithm>>>
}

impl JWTSessionBuilder {
    
    pub fn audience<A: AsRef<str>>(self, aud: A) -> Self {
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

    pub fn add_keys(self,keys: HashMap<String, Box<dyn JWTAlgorithm>>) -> Self {
        Self {
            keys: Some(keys),
            ..self
        }
    }

    pub fn add_key<A: AsRef<str>>(self, name: A, key: Box<dyn JWTAlgorithm>) -> Self {
        
        let keys = match self.keys {
            Some(mut ks) => {
                ks.insert(name.as_ref().to_string(), key);
                ks
            },
            None => {
                let mut new = HashMap::new();
                new.insert(name.as_ref().to_string(), key);
                new
            }
        };

        Self {
            keys: Some(keys),
            ..self
        }
    }

    pub fn build(self) -> Result<JWTSession, Error> {
        
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

        let keys = match self.keys {
            Some(k) => k,
            None => {
                return Err(Error::Construction(ConstructionError::Keys));
            }
        };
        
        Ok(JWTSession {
            aud,
            iss,
            keys
        })
    }

}

impl JWTSession {
    
    pub fn builder() -> JWTSessionBuilder {
        JWTSessionBuilder::default()
    }

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
            Err(e) => return Err(Error::Decode(e))
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
            Err(e) => return Err(Error::Decode(e))
        };

        let signature = token_parts[2].to_string();
        
        Ok(JWT {
            header,
            payload,
            signature
        })
    }

    fn initial_validation(&self,header: &HashMap<String, String>, signature: &str) -> Result<(),Error> {

        // Check the algorithm
        let signing_key = match header.get("alg") {
            Some(a) => {
                let key = match &self.keys.get("signature") {
                    Some(k) => k,
                    None => {
                        return Err(Error::JWT(JWTError::MissingKey));
                    }
                };
                if a.to_lowercase().as_str() != key.to_string() {
                    return Err(Error::JWT(JWTError::WrongAlgorithm));
                }
                key
            },
            None => {
                return Err(Error::JWT(JWTError::NoAlgorithm));
            }
        };

        

        Ok(())
    }

    fn build_from_req(&self, req: &Request) -> Result<Option<Session>, Error> {
        
        let jwt = Self::obtain_token_from_req(req)?;
        
        self.initial_validation(&jwt.header)?;
        return Ok(Some(Session::new_with_values(self.clone(), jwt.payload)))


    }

}

impl SessionCreator for JWTSession {

    fn apply(&self, values: &HashMap<String, String>, res: cataclysm::http::Response) -> cataclysm::http::Response {
        
    }

    fn create(&self, req: &cataclysm::http::Request) -> Result<cataclysm::session::Session, cataclysm::Error> {
        
    }

}