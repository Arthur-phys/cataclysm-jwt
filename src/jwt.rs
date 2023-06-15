use std::collections::HashMap;
use serde::Deserialize;
use serde::de::Visitor;

pub struct Payload {

    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: Option<String>,
    additional_claims: HashMap<String,String>
    
}

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

    alg: Option<String>,
    kty: Option<String>,
    r#use: Option<String>,
    key_ops: Option<String>,
    pub(crate) n: String,
    pub(crate) e: String,
    kid: Option<String>,
    x5t: Option<String>,
    x5c: Option<Vec<String>>,

}


impl<'de> Deserialize<'de> for Payload {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {

        enum Field {
            Iss,
            Sub,
            Aud,
            Exp,
            Nbf,
            Iat,
            Jti,
            AdditionalClaims(String)
        }

        impl<'de> Deserialize<'de> for Field {

            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de> {
                
                struct FieldVisitor;
        
                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;
        
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error, {
                        match v {
                            "iss" => Ok(Field::Iss), 
                            "sub" => Ok(Field::Sub), 
                            "aud" => Ok(Field::Aud), 
                            "exp" => Ok(Field::Exp), 
                            "nbf" => Ok(Field::Nbf), 
                            "iat" => Ok(Field::Iat), 
                            "jti" => Ok(Field::Jti),
                            a => Ok(Field::AdditionalClaims(a.to_string())) 
                        }
                    }
        
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("Expecting `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` or any addtional str field")
                    }
                }
            
                deserializer.deserialize_identifier(FieldVisitor)

            }
        }

        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = Payload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct JWTSession")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>, {
                
                    let mut iss = None;
                    let mut sub = None;
                    let mut aud = None;
                    let mut exp = None;
                    let mut nbf = None;
                    let mut iat = None;
                    let mut jti = None;
                    let mut additional_claims = HashMap::new();

                    while let Some(key) = map.next_key()? {
                        match key {
                            Field::Iss => {
                                iss = Some(map.next_value()?)
                            },
                            Field::Sub => {
                                sub = Some(map.next_value()?)
                            },
                            Field::Aud => {
                                aud = Some(map.next_value()?)
                            },
                            Field::Exp => {
                                exp = Some(map.next_value()?)
                            },
                            Field::Nbf => {
                                nbf = Some(map.next_value()?)
                            },
                            Field::Iat => {
                                iat = Some(map.next_value()?)
                            },
                            Field::Jti => {
                                jti = Some(map.next_value()?)
                            },
                            Field::AdditionalClaims(str) => {
                                additional_claims.insert(str,map.next_value()?);
                            }
                        }
                    }

                    Ok(Payload {
                        iss,
                        sub,
                        aud,
                        exp,
                        nbf,
                        iat,
                        jti,
                        additional_claims
                    })
            }
        }

        const FIELDS: &'static [&'static str] = &["iss","sub","aud","exp","nbf","iat","jti","additional_claims"];
        deserializer.deserialize_struct("Payload", FIELDS, PayloadVisitor)

    }

}