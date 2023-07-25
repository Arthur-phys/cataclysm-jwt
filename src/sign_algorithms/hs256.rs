use std::fmt::Display;

use base64::{Engine as _, engine::general_purpose};
use ring::hmac::{self, Key};

use crate::error::{Error, JWTError, KeyError};

/// Simple wrapper over HMAC_SHA256 key from ring
#[derive(Clone)]
pub struct HS256 {
    key: Key
}

impl HS256 {
    
    /// New instance from a priori known secret
    pub fn new<A: AsRef<str>>(secret: A) -> Self {
        
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref().as_bytes());
        Self {
            key
        }

    }

    /// Sign created JWT with shared secret.
    /// This function can be used in a context where the server is acting as an authorization server and not a
    /// resource server.
    pub fn sign_jwt(&self, headers: &str, payload: &str) -> String {

        // Encodes them without pading
        let header_str = general_purpose::URL_SAFE_NO_PAD.encode(headers);
        let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(payload);

        // Creates no-signature jwt
        let unsecure_jwt = format!("{}.{}",header_str,payload_str);

        // Verifies that internal key exists
        let sign = general_purpose::URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, unsecure_jwt.as_bytes()).as_ref());
        // Returs signed jwt
        format!("{}.{}",unsecure_jwt,sign)
        
    }

    /// JWT verification starting from the string with format 'a.b.c'
    /// Returns a new instance of a JWT
    pub fn verify_jwt(&self, jwt: &str) -> Result<(),Error> {

        // Split jwt by '.'
        let jwt_parts = jwt.split('.').collect::<Vec<&str>>();

        if jwt_parts.len() != 3 {
            return Err(Error::JWT(JWTError::JWTParts))
        }

        // Obtain the url_safe b64 parts to not have to reference the original vector
        let headerb64_str = &jwt_parts[0];
        let payloadb64_str = &jwt_parts[1];
        let signatureb64 = &jwt_parts[2];

        // Create unprotected jwt (i.e. 'a.b' without the signature)
        let unprotected_jwt = format!("{}.{}",headerb64_str,payloadb64_str);
        // Obtain signature without b64 encoding
        let signature = general_purpose::URL_SAFE_NO_PAD.decode(signatureb64).map_err(|e| Error::Decode(e,"Unable to decode signature from jwt"))?;

        // Signature verifiying based on unprotected jwt and signature.
        // If it's incorrect, the function ends here
        hmac::verify(&self.key, unprotected_jwt.as_bytes(), signature.as_ref()).map_err(|e| Error::Key(KeyError::Verification(e)))

    }

}

impl Display for HS256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"hs256")
    }
}

#[cfg(test)]
mod test {
    use crate::{Error, sign_algorithms::HS256};

    #[test]
    fn verify_signing_hs256() -> Result<(),Error> {

        let header = String::from("{\"Animal\": \"perrito\"}");
        let payload = String::from("{\"Nombre\": \"Milaneso\"}");
        let secret = "Doggies";

        let sym_key = HS256::new(secret);
        
        let secured_jwt = sym_key.sign_jwt(&header,&payload);
        
        sym_key.verify_jwt(&secured_jwt)

    }

}