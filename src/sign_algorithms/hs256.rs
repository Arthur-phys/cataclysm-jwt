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

    /// JWT verification starting from the string with format 'a.b.c'
    /// Returns a new instance of a JWT
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

        // Signature verifiying based on unprotected jwt and signature.
        // If it's incorrect, the function ends here
        hmac::verify(&self.key, unprotected_jwt.as_bytes(), signature.as_ref()).map_err(|e| Error::VerificationError(e))?;

        // Convert header to json string
        let header_str = match general_purpose::URL_SAFE_NO_PAD.decode(headerb64_str) {
            Ok(h) => match std::str::from_utf8(&h) {
                Ok(h_s) => h_s.to_string(),
                Err(e) => return Err(Error::Utf8Error(e))
            },
            Err(e) => return Err(Error::DecodeError(e))
        };

        // COnvert payload to json string
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

    /// Sign created JWT with shared secret.
    /// This function can be used in a context where the server is acting as an authorization server and not a
    /// resource server.
    pub fn sign_jwt(&self, jwt: JWT) -> String {

        // Obtains both params
        let header = jwt.header;
        let payload = jwt.payload;

        // Encodes them without pading
        let header_str = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());

        // Creates no-signature jwt
        let unsecure_jwt = format!("{}.{}",header_str,payload_str);

        // Obtains signature
        let sign = general_purpose::URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, unsecure_jwt.as_bytes()).as_ref());

        // Returs signed jwt
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