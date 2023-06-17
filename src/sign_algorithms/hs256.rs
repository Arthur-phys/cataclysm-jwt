use std::collections::HashMap;

use crate::{Error, JWT, Header};

use ring::hmac::{self, Key};
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

/// Simple wrapper over HMAC_SHA256 key from ring
pub struct HS256 {
    pub key: Key
}

impl HS256 {
    
    /// New instance from a priori known secret
    pub fn new<A: AsRef<str>>(secret: A) -> Self {
        
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref().as_bytes());

        Self {
            key
        }

    }

    pub fn verify_jwt<A: AsRef<str>>(&self, jwt: A) -> Result<JWT,Error> {

        let jwt_parts = jwt.as_ref().split('.').collect::<Vec<&str>>();

        if jwt_parts.len() != 3 {
            return Err(Error::JWTParts)
        }

        let headerb64_str = &jwt_parts[0];
        let payloadb64_str = &jwt_parts[1];
        let signatureb64 = &jwt_parts[2];

        let unprotected_jwt = format!("{}.{}",headerb64_str,payloadb64_str);
        let signature = general_purpose::URL_SAFE_NO_PAD.decode(signatureb64).map_err(|e| Error::DecodeError(e))?;

        hmac::verify(&self.key, unprotected_jwt.as_bytes(), signature.as_ref()).map_err(|e| Error::VerificationError(e))?;

        let header_str = match general_purpose::URL_SAFE_NO_PAD.decode(headerb64_str) {
            Ok(h) => match std::str::from_utf8(&h) {
                Ok(h_s) => h_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        let payload_str =  match general_purpose::URL_SAFE_NO_PAD.decode(payloadb64_str) {
            Ok(p) => match std::str::from_utf8(&p) {
                Ok(p_s) => p_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        let header: Header = serde_json::from_str(&header_str).map_err(|e| Error::SerdeError(e))?;

        let payload = serde_json::from_str::<HashMap<String,Value>>(&payload_str).map_err(|e| Error::SerdeError(e))?.into_iter().map(|(k,v)| -> Result<(String,String),Error> {
            let v = if v.is_string() {
                v.as_str().ok_or(Error::PayloadError)?.to_string()
            } else {
                v.to_string()
            };
            Ok((k,v))
        }).collect::<Result<HashMap<String,String>,_>>()?;

        Ok(JWT::from_parts(header, payload))

    }

    pub fn sign_jwt(&self, jwt: JWT) -> String {

        let header = jwt.header;
        let payload = jwt.payload;

        let header_str = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());

        let unsecure_jwt = format!("{}.{}",header_str,payload_str);

        let sign = general_purpose::URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, unsecure_jwt.as_bytes()).as_ref());

        format!("{}.{}",unsecure_jwt,sign)

    }

}

#[cfg(test)]
mod test {
    use crate::{Error, Header, sign_algorithms::HS256, JWT};
    use std::collections::HashMap;

    #[test]
    fn verify_signing() -> Result<(),Error> {

        let header = Header::new_quick("SOME ID", "HS256");
        let payload = HashMap::from([(String::from("issuer"),String::from("arthurphys"))]);
        let unsecured_jwt = JWT::from_parts(header,payload);
        
        let secret = "Doggies";
        let sym_key = HS256::new(secret);
        
        let secured_jwt = sym_key.sign_jwt(unsecured_jwt);
        
        sym_key.verify_jwt(secured_jwt).map(|_| ())

    }

}