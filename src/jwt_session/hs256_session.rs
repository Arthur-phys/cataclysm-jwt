use crate::{Error, error::{JWTError,KeyError}, sign_algorithms::HS256, jwt_session::{JWTSession,JWTSessionBuilder}};

use std::collections::HashMap;
use cataclysm::{session::{SessionCreator, Session}, http::Request};

#[derive(Clone)]
pub struct JWTHS256Session {
    pub aud: String,
    pub iss: String,
    pub verification_key: HS256
}

impl JWTHS256Session {

    pub fn builder() -> JWTSessionBuilder {
        JWTSessionBuilder::default()
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
                return Err(cataclysm::Error::Custom(format!("some error!")));
            }
        }
    }

}

impl JWTSession for JWTHS256Session {

    fn build_from_req(&self, req: &Request) -> Result<HashMap<String,String>, Error> {
        
        let jwt = Self::obtain_token_from_req(req)?;

        self.initial_validation(&jwt.header,&jwt.raw_jwt)?;

        return Ok(jwt.payload)


    }

    fn initial_validation(&self, header: &HashMap<String, String>, jwt: &str) -> Result<(),Error> {

        // Check the algorithm on jwt is the same as the one in the key
        match header.get("alg") {
            Some(a) => {
                if a.to_lowercase().as_str() != self.verification_key.to_string() {
                    return Err(Error::JWT(JWTError::WrongAlgorithm));
                }
            },
            None => {
                return Err(Error::JWT(JWTError::NoAlgorithm));
            }
        };

        self.verification_key.verify_jwt(jwt)

    }

}