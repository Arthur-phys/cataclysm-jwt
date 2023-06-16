use std::collections::HashMap;
use serde::Deserialize;



#[derive(Deserialize, Clone)]
pub struct Header {

    // alg: SigningAlgorithm,
    _jku: Option<String>,
    _jwk: Option<String>,
    pub(crate) kid: Option<String>,
    _typ: Option<String>,
    pub(crate) alg: Option<String>,
    _x5u: Option<String>,
    _x5c: Option<String>,
    _x5t: Option<String>,
    _x5t_hash_s256: Option<String>, 
    _crit: Option<String>,

}

#[derive(Clone)]
pub struct JWT {
    pub header: Header,
    pub payload: HashMap<String,String>,
    pub token: String
}

#[derive(Deserialize, Clone, Debug)]

pub struct JWK {

    pub alg: Option<String>,
    pub kty: Option<String>,
    _use: Option<String>,
    _key_ops: Option<String>,
    pub n: String,
    pub e: String,
    pub kid: Option<String>,
    _x5t: Option<String>,
    _x5c: Option<Vec<String>>,

}