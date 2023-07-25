use cataclysm::{session::{SessionCreator, Session}, http::Request};
use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use std::collections::HashMap;

use crate::{sign_algorithms::RS256, Error, error::{ConstructionError, JWTError, KeyError}, JWT};

#[derive(Clone)]
pub struct JWTSession {
    pub aud: String,
    pub iss: String,
    pub verification_keys: HashMap<String,RS256>
}

#[derive(Default)]
pub struct JWTSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    pub verification_keys: Option<HashMap<String,RS256>>
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

        let verification_keys = match self.verification_keys {
            Some(k) => k,
            None => {
                return Err(Error::Construction(ConstructionError::Keys))
            }
        };
        
        Ok(JWTSession {
            aud,
            iss,
            verification_keys,
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

    fn initial_validation(&self, header: &HashMap<String, String>, jwt: &str) -> Result<(),Error> {

        // Check the kid
        let kid = match header.get("kid") {
            Some(id) => id,
            None => {
                return Err(Error::Key(KeyError::KidField))
            }
        };

        // Check the algorithm on jwt is the sames as the one on key
        let verification_key = match header.get("alg") {
            Some(a) => {
                let possible_key = self.verification_keys.get(kid);
                let key = match possible_key {
                    Some(k) => k,
                    None => {
                        return Err(Error::Key(KeyError::Kid));
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

        verification_key.verify_jwt(jwt)

    }

    fn build_from_req(&self, req: &Request) -> Result<Option<Session>, Error> {
        
        let jwt = Self::obtain_token_from_req(req)?;

        self.initial_validation(&jwt.header,&jwt.raw_jwt)?;

        return Ok(Some(Session::new_with_values(self.clone(), jwt.payload)))


    }

}

impl SessionCreator for JWTSession {

    fn apply(&self, _values: &HashMap<String, String>, res: cataclysm::http::Response) -> cataclysm::http::Response {
        res
    }

    fn create(&self, req: &cataclysm::http::Request) -> Result<cataclysm::session::Session, cataclysm::Error> {
        match self.build_from_req(req) {
            Ok(Some(s)) => {
                Ok(s)
            },
            Ok(None) => {
                return Err(cataclysm::Error::Custom(String::from("No JWT session found and one cannot be provided by server")))
            }
            Err(_) => {
                return Err(cataclysm::Error::Custom(format!("some error!")));
            }
        }
    }

}

#[cfg(test)]
mod test {

    // use std::io::Read;

    // use crate::{Error, sign_algorithms::{RS256, HS256}, jwt_session::JWTSession};

    // #[test]
    // fn simple_verification_and_signing() -> Result<(),Error> {

    //     let mut public_key_der = std::fs::File::open("./public.der")?;
    //     let mut contents: Vec<u8> = Vec::new();
    //     public_key_der.read_to_end(&mut contents)?;

    //     let key = RS256::new(contents)?;
    //     let signing_key = HS256::new("Perritos");

    //     JWTSession::builder()
    //         .aud("SIMPLE AUD")
    //         .iss("SIMPLE ISSUER")
    //         .add_verification_key(key, "1")
    //         .build()?;

    //     Ok(())

    // }

    // #[tokio::test]
    // async fn jwks_endpoints_verification_and_signing() -> Result<(),Error> {

    //     let signing_key = HS256::new("Perritos");

    //     JWTSession::builder()
    //         .aud("SIMPLE AUD")
    //         .iss("SIMPLE ISSUER")
    //         .add_from_jwks("https://auth.cloudb.sat.gob.mx/nidp/oauth/nam/keys").await?
    //         .build()?;

    //     Ok(())

    // }

}