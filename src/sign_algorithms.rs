mod hs256;
mod rs256;

pub use hs256::HS256;
pub use rs256::RS256;

use crate::Error;

pub trait JWTAlgorithm {

    fn verify_jwt(&self, jwt: &str) -> Result<(),Error>;
    fn sign_jwt(&self, headers: &str, payload: &str) -> Result<String,Error>;

}