use std::collections::HashMap;

use crate::sign_algorithms::JWTAlgorithm;

pub struct JWTSession {
    pub aud: String,
    pub iss: String,
    pub keys: HashMap<String,Box<dyn JWTAlgorithm>>
}

#[derive(Default)]
pub struct JWTSessionBuilder {
    aud: Option<String>,
    iss: Option<String>,
    keys: Option<HashMap<String,Box<dyn JWTAlgorithm>>>
}

impl JWTSessionBuilder {
    
    pub fn audience<A: AsRef<str>>(self, aud: A) -> Self {
        Self {
            aud: Some(aud.as_ref().to_string()),
            ..self
        }
    }

    pub fn iss<A: AsRef<str>>(self, iss: A) -> Self {
        Self {
            iss: Some(iss.as_ref().to_string()),
            ..self
        }
    }

    pub fn add_key<A: AsRef<str>>(self, name: A, key: Box<dyn JWTAlgorithm>) -> Self {
        
        let keys = match self.keys {
            Some(mut ks) => {
                ks.insert(name.as_ref().to_string(), key);
                ks
            },
            None => {
                let mut new = HashMap::new();
                new.insert(name.as_ref().to_string(), key);
                new
            }
        };

        Self {
            keys: Some(keys),
            ..self
        }
    }

}

impl JWTSession {
    fn builder() -> JWTSessionBuilder {
        JWTSessionBuilder::default()
    }
}