use crate::{Error, JWT, Header};

use std::{collections::HashMap, path::Path, io::Read};
use ring::{rand, signature, signature::{UnparsedPublicKey, RsaKeyPair}};
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

pub struct RS256 {
    public_key: UnparsedPublicKey<Vec<u8>>,
    internal_key_pair: Option<RsaKeyPair>,
}

impl RS256 {

    pub fn new<A: AsRef<str>, B: AsRef<Path>>(p_key: A, internal_private_key: B) -> Result<Self,Error> {

        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,p_key.as_ref().as_bytes().to_owned());

        let mut private_key_der = std::fs::File::open(internal_private_key).map_err(|_| Error::Custom("eyy".to_string()))?;
        let mut contents: Vec<u8> = Vec::new();
        private_key_der.read_to_end(&mut contents).map_err(|_| Error::Custom("eyy".to_string()))?;
        let internal_key_pair = Some(RsaKeyPair::from_der(&contents).map_err(|_| Error::Custom("eyy".to_string()))?);
        
        Ok(RS256 {
            public_key,
            internal_key_pair
        })

    }

    pub fn new_simple<A: AsRef<str>>(p_key: A) -> Result<Self,Error> {

        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,p_key.as_ref().as_bytes().to_owned());

        Ok(RS256 {
            public_key,
            internal_key_pair: None
        })

    }

    pub fn verify_jwt<A: AsRef<str>>(&self, jwt: A) -> Result<JWT,Error> {

        // Split jwt by '.'
        let jwt_parts = jwt.as_ref().split('.').collect::<Vec<&str>>();

        if jwt_parts.len() != 3 {
            return Err(Error::JWTParts)
        }

        // Obtain the url_safe b64 parts to not have to refernce the original vector
        let headerb64_str = &jwt_parts[0];
        let payloadb64_str = &jwt_parts[1];
        let signatureb64 = &jwt_parts[2];

        // Create unprotected jwt (i.e. 'a.b' without the signature)
        let unprotected_jwt = format!("{}.{}",headerb64_str,payloadb64_str);
        // Obtain signature without b64 encoding
        let signature = general_purpose::URL_SAFE_NO_PAD.decode(signatureb64).map_err(|e| Error::DecodeError(e))?;

        self.public_key.verify(unprotected_jwt.as_bytes(), &signature).map_err(|e| Error::VerificationError(e))?;

         // Convert header to json string
         let header_str = match general_purpose::URL_SAFE_NO_PAD.decode(headerb64_str) {
            Ok(h) => match std::str::from_utf8(&h) {
                Ok(h_s) => h_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        // Convert payload to json string
        let payload_str =  match general_purpose::URL_SAFE_NO_PAD.decode(payloadb64_str) {
            Ok(p) => match std::str::from_utf8(&p) {
                Ok(p_s) => p_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        // Convert header json string into Header struct
        let header: Header = serde_json::from_str(&header_str).map_err(|e| Error::SerdeError(e))?;

        // Convert payload into hashMap of string-only values
        let payload = serde_json::from_str::<HashMap<String,Value>>(&payload_str).map_err(|e| Error::SerdeError(e))?.into_iter().map(|(k,v)| -> Result<(String,String),Error> {
            let v = if v.is_string() {
                v.as_str().ok_or(Error::PayloadError)?.to_string()
            } else {
                v.to_string()
            };
            Ok((k,v))
        }).collect::<Result<HashMap<String,String>,_>>()?;

        // Return JWT
        Ok(JWT::from_parts(header, payload))

    }

    pub fn sign_jwt(&self, jwt: JWT) -> Result<String,Error> {
        
        // Obtains both params
        let header = jwt.header;
        let payload = jwt.payload;

        // Encodes them without pading
        let header_str = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());

        // Creates no-signature jwt
        let unsecure_jwt = format!("{}.{}",header_str,payload_str);

        // Verifies that internal key exists
        match self.internal_key_pair.as_ref() {
            Some(internal_key_pair) => {
                
                // Create random number for signature
                let rng = rand::SystemRandom::new();
                let mut signature_vec = vec![0; internal_key_pair.public_modulus_len()];
                // Obtain signature
                internal_key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, unsecure_jwt.as_bytes(), &mut signature_vec).map_err(|_| Error::Custom("eyy".to_string()))?;
                // Returs signed jwt
                return Ok(format!("{}.{}",unsecure_jwt, general_purpose::URL_SAFE_NO_PAD.encode(signature_vec)));
            
            },
            None => {
                return Err(Error::NoInternalKey);
            }
        };

    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{Error, JWT, Header, sign_algorithms::RS256};


    #[test]
    fn verify_asymmetric_signing() -> Result<(),Error> {

        let header = Header::new_quick("SOME ID", "RS256");
        let payload = HashMap::from([(String::from("issuer"),String::from("arthurphys"))]);
        let unsecured_jwt = JWT::from_parts(header,payload);

        let asym_key = RS256::new("", "../private_key.pem")?;
        let secured_jwt = asym_key.sign_jwt(unsecured_jwt)?;
        
        asym_key.verify_jwt(secured_jwt).map(|_| ())


    }
}