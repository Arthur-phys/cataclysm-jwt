mod rs256_session;
mod hs256_session;

pub use rs256_session::JWTRS256Session;
pub use hs256_session::JWTHS256Session;

use crate::{Error, error::JWTError, JWT, jwt_session::{hs256_session::JWTHS256Builder,rs256_session::JWTRS256Builder}};

use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use std::collections::HashMap;
use cataclysm::{session::SessionCreator, http::Request};

trait JWTSession: Clone + SessionCreator {

    fn initial_validation(&self, jwt: &JWT) -> Result<(),Error>;

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

pub struct JWTSessionBuilder();

impl JWTSessionBuilder {

    pub fn with_rs256() -> JWTRS256Builder {
        JWTRS256Builder::default()
    }

    pub fn with_hs256() -> JWTHS256Builder {
        JWTHS256Builder::default()
    }

}

