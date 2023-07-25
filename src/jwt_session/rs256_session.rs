use crate::{Error, error::{JWTError,KeyError}, sign_algorithms::RS256, jwt_session::{JWTSession,JWTSessionBuilder}};

use std::collections::HashMap;
use cataclysm::{session::{SessionCreator, Session}, http::Request};

#[derive(Clone)]
pub struct JWTRS256Session {
    pub aud: String,
    pub iss: String,
    pub verification_keys: HashMap<String,RS256>
}

impl JWTRS256Session {
    
    pub fn builder() -> JWTSessionBuilder {
        JWTSessionBuilder::default()
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
                return Err(cataclysm::Error::Custom(format!("some error!")));
            }
        }
    }

}

impl JWTSession for JWTRS256Session {

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

    fn build_from_req(&self, req: &Request) -> Result<HashMap<String,String>, Error> {
        
        let jwt = Self::obtain_token_from_req(req)?;

        self.initial_validation(&jwt.header,&jwt.raw_jwt)?;

        return Ok(jwt.payload)

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