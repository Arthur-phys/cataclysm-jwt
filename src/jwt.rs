use serde::Deserialize;



#[derive(Deserialize)]
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

#[derive(Deserialize)]

pub struct JWK {

    pub alg: Option<String>,
    pub kty: Option<String>,
    r#use: Option<String>,
    key_ops: Option<String>,
    pub n: String,
    pub e: String,
    pub kid: Option<String>,
    x5t: Option<String>,
    x5c: Option<Vec<String>>,

}