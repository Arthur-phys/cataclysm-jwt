use crate::error::{Error, JWTError};


use rsa::{RsaPublicKey, pkcs1v15::{VerifyingKey, Signature}, sha2::Sha256, BigUint, signature::Verifier};
use base64::{Engine as _, engine::general_purpose};
use std::fmt::Display;

#[derive(Clone)]
/// Simple wrapper arround rsa::VerifyingKey
pub struct RS256 {
    key: VerifyingKey<Sha256>
}

impl RS256 {

    /// Creates a new public key from primitives (like the ones obtained from JWKS identity server's endpoint)
    pub fn new_from_primitives<A: AsRef<str>, B: AsRef<str>>(n: A, e: B) -> Result<Self,Error> {
        
        let n = general_purpose::URL_SAFE_NO_PAD.decode(n.as_ref()).map_err(|e| Error::Decode(e, "Unable to decode modulus 'n' for public key!"))?;
        let e = general_purpose::URL_SAFE_NO_PAD.decode(e.as_ref()).map_err(|e| Error::Decode(e, "Unable to decode exponent 'e' for public key!"))?;
        let n = BigUint::from_bytes_be(&n);
        let e = BigUint::from_bytes_be(&e);

        let public_key = RsaPublicKey::new(n,e)?;

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::<Sha256>::new(public_key);

        Ok(RS256 {
            key: verifying_key
        })

    }

    /// JWT verification starting from the string with format 'a.b.c'
    /// Returns a new instance of a JWT
    pub fn verify_jwt(&self, jwt: &str) -> Result<(),Error> {

        // Split jwt by '.'
        let jwt_parts = jwt.split('.').collect::<Vec<&str>>();

        if jwt_parts.len() != 3 {
            return Err(Error::JWT(JWTError::JWTParts))
        }

        // Obtain the url_safe b64 parts to not have to refernce the original vector
        let headerb64_str = &jwt_parts[0];
        let payloadb64_str = &jwt_parts[1];
        let signatureb64 = &jwt_parts[2];

        // Create unprotected jwt (i.e. 'a.b' without the signature)
        let unprotected_jwt = format!("{}.{}",headerb64_str,payloadb64_str);
        // Obtain signature without b64 encoding
        let signature = general_purpose::URL_SAFE_NO_PAD.decode(signatureb64).map_err(|e| Error::Decode(e, "Unable to decode signature from jwt"))?;
        let real_signature: Signature = signature.as_slice().try_into()?;

        self.key.verify(unprotected_jwt.as_bytes(), &real_signature)?;
        Ok(())


    }
}

impl Display for RS256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"rs256")
    }
}