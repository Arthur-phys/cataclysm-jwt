use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Header {

    _jku: Option<String>,
    _jwk: Option<String>,
    _typ: Option<String>,
    pub(crate) kid: Option<String>,
    pub(crate) alg: Option<String>,
    _x5u: Option<String>,
    _x5c: Option<String>,
    _x5t: Option<String>,
    _x5t_hash_s256: Option<String>, 
    _crit: Option<String>,

}

#[derive(Clone, Debug)]
pub struct JWT {
    pub header: Header,
    pub payload: HashMap<String,String>,
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

impl Header {
    pub fn new_quick<A: AsRef<str>,B: AsRef<str>>(kid: A, alg: B) -> Self {
        Self {
            kid: Some(kid.as_ref().to_string()),
            alg: Some(alg.as_ref().to_string()),
            _x5u: None,
            _x5c: None,
            _x5t: None,
            _x5t_hash_s256: None, 
            _crit: None,
            _jku: None,
            _jwk: None,
            _typ: None
        }
    }
}

impl JWT {

    pub fn from_parts(header: Header, payload: HashMap<String,String>) -> Self {

        Self {
            header,
            payload
        }

    }

}