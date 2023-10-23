use crate::{Error, error::{JWTError,ConstructionError}, sign_algorithms::HS256, jwt_session::JWTSession, JWT};

use chrono::{NaiveDateTime, DateTime, Utc};
use std::collections::HashMap;
use cataclysm::{session::{SessionCreator, Session}, http::Request};

#[derive(Clone)]
/// Implementation of HS256 session, or symmetric session (the most common at least)
pub struct JWTHS256Session {
    pub aud: String,
    pub iss: String,
    pub verification_key: HS256,
    #[cfg(feature = "delta-start")]
    pub delta_start: Option<i64>,
}

impl JWTHS256Session {

    /// Simple builder function
    pub fn builder() -> JWTHS256Builder {
        JWTHS256Builder::default()
    }

}

impl SessionCreator for JWTHS256Session {

    fn apply(&self, _values: &HashMap<String, String>, res: cataclysm::http::Response) -> cataclysm::http::Response {
        res
    }

    fn create(&self, req: &cataclysm::http::Request) -> Result<cataclysm::session::Session, cataclysm::Error> {
        match self.build_from_req(req) {
            Ok(payload) => {
                return Ok(Session::new_with_values(self.clone(),payload))
            },
            Err(_) => {
                return Err(cataclysm::Error::Custom(format!("Unable to create session!!")));
            }
        }
    }

}

impl JWTSession for JWTHS256Session {

    fn build_from_req(&self, req: &Request) -> Result<HashMap<String,String>, Error> {
        
        let jwt = Self::obtain_token_from_req(req)?;

        self.initial_validation(&jwt)?;

        return Ok(jwt.payload)


    }

    fn initial_validation(&self, jwt: &JWT) -> Result<(),Error> {

        // Check the algorithm on jwt is the same as the one in the key
        match jwt.header.get("alg") {
            Some(a) => {
                if a.to_lowercase().as_str() != self.verification_key.to_string() {
                    return Err(Error::JWT(JWTError::WrongAlgorithm));
                }
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

                    #[cfg(not(feature = "delta-start"))] {
                        if date_utc > now {
                            return Err(Error::JWT(JWTError::ToBeValid));
                        }
                    }

                    #[cfg(feature = "delta-start")] {
                        if let Some(delta) = self.delta_exipration {
                            if date_utc > (now + delta) {
                                return Err(Error::JWT(JWTError::Expired));
                            }
                        } else {
                            if date_utc > now {
                                return Err(Error::JWT(JWTError::Expired));
                            }
                        }
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

                    #[cfg(not(feature = "delta-start"))] {
                        if date_utc > now {
                            return Err(Error::JWT(JWTError::ToBeValid));
                        }
                    }

                    #[cfg(feature = "delta-start")] {
                        if let Some(delta) = self.delta_exipration {
                            if date_utc > (now + delta) {
                                return Err(Error::JWT(JWTError::Expired));
                            }
                        } else {
                            if date_utc > now {
                                return Err(Error::JWT(JWTError::Expired));
                            }
                        }
                    }

                },
                None => {
                    return Err(Error::JWT(JWTError::NoNbf))
                }
            }
            
        }

        self.verification_key.verify_jwt(&jwt.raw_jwt)

    }

}

#[derive(Default)]
/// Simple builder for HS256 session
pub struct JWTHS256Builder {
    aud: Option<String>,
    iss: Option<String>,
    verification_key: Option<HS256>,
    #[cfg(feature = "delta-start")]
    delta_start: Option<i64>,
}

impl JWTHS256Builder {
    
    /// Get audience
    pub fn aud<A: AsRef<str>>(self, aud: A) -> Self {
        Self {
            aud: Some(aud.as_ref().to_string()),
            ..self
        }
    }

    /// Get issuer
    pub fn iss<A: AsRef<str>>(self, iss: A) -> Self {
        Self {
            iss: Some(iss.as_ref().to_string()),
            ..self
        }
    }

    /// Create HS256 key from shared secret
    pub fn add_from_secret<A: AsRef<str>>(self, secret: A) -> Self {
        
        let verification_key = HS256::new(secret);

        Self {
            verification_key: Some(verification_key),
            ..self
        }

    }

    /// Adds a time extension to verify nbf and iat claims.
    /// If the time extension is called 'delta', then the token is valid since (iat - delta) and (nbf - delta).
    /// Even if the feature is enabled, when no time window is passed, the time extension will not be enabled.
    #[cfg(feature = "delta-expiration")]
    pub fn delta_start(self, delta_exipration: i64) -> Self {
        
        Self {
            delta_start: Some(delta_start),
            ..self
        }

    }

    /// Simple builder
    pub fn build(self) -> Result<JWTHS256Session, Error> {
        
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

        let verification_key = match self.verification_key {
            Some(k) => k,
            None => {
                return Err(Error::Construction(ConstructionError::Keys))
            }
        };
        
        Ok(JWTHS256Session {
            aud,
            iss,
            verification_key,
            #[cfg(feature = "delta-start")]
            delta_start
        })
    }
}