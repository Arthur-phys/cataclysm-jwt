mod rs256_session;
mod hs256_session;

pub use rs256_session::{JWTRS256Session, JWTRS256Builder};
pub use hs256_session::{JWTHS256Session, JWTHS256Builder};

use crate::{Error, error::JWTError, JWT};

use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use std::collections::HashMap;
use cataclysm::{session::SessionCreator, http::Request};

/// # Ussage
///
/// Trait employed for HS256 and RS256 session to avoid code repetition and specify what needs to be done to verify JWT correctly
/// The `obtain_token_from_req` function is the same in both cases, since it returns a `JWT` instance
/// This trait is made public in case someone finds it useful.
/// 
pub trait JWTSession: Clone + SessionCreator {

    /// Should perform any kind of validation necessary before reading and manipulating the request
    fn initial_validation(&self, jwt: &JWT) -> Result<(),Error>;

    /// From request extract JWT to manipulate it easier later on
    fn obtain_token_from_req(req: &Request) -> Result<JWT,Error> {

        // Get authorizarion header
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
        
        // Split token
        let token: String = authorization_header[0].split(' ').collect::<Vec<&str>>()[1].to_string();
        let token_parts: Vec<&str> = token.split('.').collect();

        // Get header and convert it to HashMap
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
        
        // Get payload and convert it to HashMap
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

        // Get signature
        let signature = token_parts[2].to_string();
        
        Ok(JWT {
            header,
            payload,
            signature,
            raw_jwt: token
        })
    }

    /// Build session from incoming request. Should return a HashMap with values needed to validate session and possibly receive user information (through jwt)
    fn build_from_req(&self, req: &Request) -> Result<HashMap<String,String>, Error>;

}


/// Empty struct for easier user interface
pub struct JWTSessionBuilder();

impl JWTSessionBuilder {

    /// Return a builder for assymmetric signing
    pub fn with_rs256() -> JWTRS256Builder {
        JWTRS256Builder::default()
    }

    /// Return a builder for symmetric signing
    pub fn with_hs256() -> JWTHS256Builder {
        JWTHS256Builder::default()
    }

}

