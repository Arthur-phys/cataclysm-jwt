use crate::error::{Error, JWTError};

use openssl::{rsa::Rsa, bn::BigNum};
use ring::{signature, signature::UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose};
use std::fmt::Display;

#[derive(Clone)]
pub struct RS256 {
    key: UnparsedPublicKey<Vec<u8>>
}

impl RS256 {

    pub fn new<A: AsRef<Vec<u8>>>(p_key: A) -> Result<Self,Error> {

        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,p_key.as_ref().to_owned());

        Ok(RS256 {
            key: public_key    
        })

    }

    pub fn new_from_primitives<A: AsRef<str>, B: AsRef<str>>(n: A, e: B) -> Result<Self,Error> {
        
        let n = BigNum::from_dec_str(n.as_ref())?;
        let e = BigNum::from_dec_str(e.as_ref())?;

        let rsa_public = Rsa::from_public_components(n,e)?;
        let rsa_public_der = rsa_public.public_key_to_der()?;

        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,rsa_public_der.to_owned());

        Ok(RS256 {
            key: public_key
        })

    }

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
        let mut signature = general_purpose::URL_SAFE_NO_PAD.decode(signatureb64)?;

        self.key.verify(unprotected_jwt.as_bytes(), &mut signature)?;
        Ok(())


    }
}

impl Display for RS256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"rs256")
    }
}


#[cfg(test)]
mod test {

    use std::io::Read;

    use base64::{engine::general_purpose, Engine};
    use ring::{signature::{RsaKeyPair, self}, rand};

    use crate::{Error, sign_algorithms::RS256};


    #[test]
    fn sign_and_verify_asymmetric_signing() -> Result<(),Error> {

        let mut private_key_der = std::fs::File::open("./private.der")?;

        let mut contents: Vec<u8> = Vec::new();
        private_key_der.read_to_end(&mut contents)?;
        let key_pair = RsaKeyPair::from_der(&contents)?;

        let header = String::from("{\"Animal\": \"perrito\"}");
        let payload = String::from("{\"Nombre\": \"Caloncho\"}");

        // Encodes them without pading
        let header_str = general_purpose::URL_SAFE_NO_PAD.encode(header);
        let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(payload);

        let unsecure_jwt = format!("{}.{}",header_str,payload_str);

        let rng = rand::SystemRandom::new();
        let mut signature_vec = vec![0; key_pair.public_modulus_len()];
        // Obtain signature
        key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, unsecure_jwt.as_bytes(), &mut signature_vec)?;
        // Returns signed jwt
        let secured_jwt = format!("{}.{}",unsecure_jwt, general_purpose::URL_SAFE_NO_PAD.encode(signature_vec));
        
        let mut public_key_der = std::fs::File::open("./public.der")?;
        let mut contents: Vec<u8> = Vec::new();
        public_key_der.read_to_end(&mut contents)?;

        let verifying_asym_key = RS256::new(contents)?;

        verifying_asym_key.verify_jwt(&secured_jwt)

    }
}