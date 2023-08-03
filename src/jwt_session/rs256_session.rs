use crate::{Error, error::{JWTError,KeyError,ConstructionError}, sign_algorithms::RS256, jwt_session::JWTSession, JWT};

use std::collections::HashMap;
use serde_json::Value;
use chrono::{NaiveDateTime, DateTime, Utc};
use cataclysm::{session::{SessionCreator, Session}, http::Request};

#[derive(Clone)]
/// Implementation of a RS256 session, or an assymmetric session (the most common at least)
pub struct JWTRS256Session {
    pub aud: String,
    pub iss: String,
    pub verification_keys: HashMap<String,RS256>
}

impl JWTRS256Session {
    
    /// Simple builder function
    pub fn builder() -> JWTRS256Builder {
        JWTRS256Builder::default()
    }

}

impl SessionCreator for JWTRS256Session {

    fn apply(&self, _values: &HashMap<String, String>, res: cataclysm::http::Response) -> cataclysm::http::Response {
        res
    }

    fn create(&self, req: &cataclysm::http::Request) -> Result<cataclysm::session::Session, cataclysm::Error> {
        match self.build_from_req(req) {
            Ok(payload) => {
                return Ok(Session::new_with_values(self.clone(),payload))
            },
            Err(_) => {
                return Err(cataclysm::Error::Custom(format!("Unable to create session!")));
            }
        }
    }

}

impl JWTSession for JWTRS256Session {

    fn initial_validation(&self, jwt: &JWT) -> Result<(),Error> {

        // Check the kid
        let kid = match jwt.header.get("kid") {
            Some(id) => id,
            None => {
                return Err(Error::Key(KeyError::KidField))
            }
        };

        // Check the algorithm on jwt is the sames as the one on key
        let verification_key = match jwt.header.get("alg") {
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

        #[cfg(not(feature = "lax-security"))]
        {
            // Check the audience
            match jwt.payload.get("aud") {
                Some(a) => {
                    if a.as_str() != &self.aud {
                        return Err(Error::JWT(JWTError::WrongAudience));
                    }
                },
                None => {
                    return Err(Error::JWT(JWTError::NoAudience))
                }
            }

            // Check the issuer
            match jwt.payload.get("iss") {
                Some(i) => {
                    if i.as_str() != &self.iss {
                        return Err(Error::JWT(JWTError::WrongIss));
                    }
                },
                None => {
                    return Err(Error::JWT(JWTError::NoIss))
                }
            }

            // Check the expiration time
            match jwt.payload.get("exp") {
                Some(e) => {
                    let num_e = str::parse::<i64>(e)?;
                    let date = NaiveDateTime::from_timestamp_opt(num_e,0).ok_or(Error::ParseTimestamp)?;
                    let date_utc: DateTime<Utc> = DateTime::from_utc(date, Utc);
                    let now = Utc::now();

                    if date_utc < now {
                        return Err(Error::JWT(JWTError::Expired));
                    }
                },
                None => {
                    return Err(Error::JWT(JWTError::NoExp))
                }
            }
            
            // Check the iat
            match jwt.payload.get("iat") {
                Some(ia) => {
                    let num_ia = str::parse::<i64>(ia)?;
                    let date = NaiveDateTime::from_timestamp_opt(num_ia,0).ok_or(Error::ParseTimestamp)?;
                    let date_utc: DateTime<Utc> = DateTime::from_utc(date, Utc);
                    let now = Utc::now();

                    if date_utc > now {
                        return Err(Error::JWT(JWTError::ToBeValid));
                    }
                },
                None => {
                    return Err(Error::JWT(JWTError::NoIat))
                }
            }

            match jwt.payload.get("nbf") {
                Some(nb) => {
                    let num_nb = str::parse::<i64>(nb)?;
                    let date = NaiveDateTime::from_timestamp_opt(num_nb,0).ok_or(Error::ParseTimestamp)?;
                    let date_utc: DateTime<Utc> = DateTime::from_utc(date, Utc);
                    let now = Utc::now();

                    if date_utc > now {
                        return Err(Error::JWT(JWTError::ToBeValid));
                    }
                },
                None => {
                    return Err(Error::JWT(JWTError::NoNbf))
                }
            }

        }

        verification_key.verify_jwt(&jwt.raw_jwt)

    }

    fn build_from_req(&self, req: &Request) -> Result<HashMap<String,String>, Error> {
        
        let jwt = Self::obtain_token_from_req(req)?;

        self.initial_validation(&jwt)?;

        return Ok(jwt.payload)

    }

}

#[derive(Default)]
/// Simple builder for RS256 session
pub struct JWTRS256Builder {
    aud: Option<String>,
    iss: Option<String>,
    verification_keys: Option<HashMap<String,RS256>>,
}

impl JWTRS256Builder {
    
    /// Creates audience
    pub fn aud<A: AsRef<str>>(self, aud: A) -> Self {
        Self {
            aud: Some(aud.as_ref().to_string()),
            ..self
        }
    }

    /// Creates issuer
    pub fn iss<A: AsRef<str>>(self, iss: A) -> Self {
        Self {
            iss: Some(iss.as_ref().to_string()),
            ..self
        }
    }

    /// Adds verification key from prior key `RS256` structure. Mostly used if one has an already known key, but it is better to use the `add_from_jwks` function
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

    /// Uses an endpoint to obtain public keys needed for verification from an array of keys.
    /// Will ignore any key that does not use RS256 as signing algorithm.
    /// Will panic if no key was found with RS256 alg.
    pub async fn add_from_jwks<A: AsRef<str>>(self, url: A) -> Result<Self,Error> {

        // Obtaining response from JWKS endpoint
        let jwks = reqwest::get(url.as_ref()).await?.text().await?;
        
        // Will deserialize it into `{keys: [{...},...]}` HashMap
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

        let jwks_vec: &Vec<HashMap<String,String>> = jwks_hm.get("keys").ok_or(Error::Key(KeyError::KeyField))?;

        let rs256_hm = jwks_vec.iter().filter_map(|jwk_hm: &HashMap<String,String>| -> Option<Result<(String,RS256),Error>> {

            let kty = match jwk_hm.get("kty") {
                Some(ty) => ty,
                None => {
                    return None;
                }
            };
            
            // Key type must be RSA
            // Will ingore otherwise
            if kty != "RSA" {
                return None;
            }

            #[cfg(feature = "jwk-use")]
            {
                let usee = match jwk_hm.get("use") {
                    Some(se) => se,
                    None => {
                        return None;
                    }
                };

                // Use must be signing
                if usee != "sig" {
                    return None;
                }
            }

            #[cfg(feature = "jwk-alg")]
            {
                let alg = match jwk_hm.get("alg") {
                    Some(lg) => lg,
                    None => {
                        return None;
                    }
                };

                // alg must be rs256
                if alg != "RS256" {
                    return None;
                }
            }

            let kid = match jwk_hm.get("kid") {
                Some(id) => id,
                None => {
                    return Some(Err(Error::Key(KeyError::KidField)));
                }
            };

            let e = match jwk_hm.get("e") {
                Some(ee) => ee,
                None => {
                    return Some(Err(Error::Key(KeyError::E)));
                }
            };

            let n = match jwk_hm.get("n") {
                Some(nn) => nn,
                None => {
                    return Some(Err(Error::Key(KeyError::N)));
                }
            };

            let rs256 = match RS256::new_from_primitives(n, e) {
                Ok(r) => r,
                Err(e) => {
                    return Some(Err(e))
                }
            };

            Some(Ok((kid.to_string(),rs256)))

        }).collect::<Result<HashMap<String,RS256>,Error>>()?;

        Ok(Self {
            verification_keys: Some(rs256_hm),
            ..self
        })

    }

    /// Simple building function
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

#[cfg(test)]
mod test {

    // use std::io::Read;

    // use crate::{Error, sign_algorithms::{RS256, HS256}, jwt_session::JWTRS256Session};

    // #[test]
    // fn simple_verification_and_signing() -> Result<(),Error> {

    //     let mut public_key_der = std::fs::File::open("./public.der")?;
    //     let mut contents: Vec<u8> = Vec::new();
    //     public_key_der.read_to_end(&mut contents)?;

    //     let key = RS256::new(contents)?;
    //     let signing_key = HS256::new("Perritos");

    //     JWTRS256Session::builder()
    //         .aud("SIMPLE AUD")
    //         .iss("SIMPLE ISSUER")
    //         .add_verification_key(key, "1")
    //         .build()?;

    //     Ok(())

    // }

    // #[tokio::test]
    // async fn jwks_endpoints_verification_and_signing() -> Result<(),Error> {

    //     let signing_key = HS256::new("Perritos");

    //     JWTRS256Session::builder()
    //         .aud("SIMPLE AUD")
    //         .iss("SIMPLE ISSUER")
    //         .add_from_jwks("https://auth.cloudb.sat.gob.mx/nidp/oauth/nam/keys").await?
    //         .build()?;

    //     Ok(())

    // }

}