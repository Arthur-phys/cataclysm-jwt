use crate::error::{Error, JWTError, KeyError};
use crate::sign_algorithms::JWTAlgorithm;

use ring::{rand, signature, signature::{UnparsedPublicKey, RsaKeyPair}};
use base64::{Engine as _, engine::general_purpose};
use std::fmt::Display;
use std::{path::Path, io::Read};

pub enum Kind {
    Signing(RsaKeyPair),
    Verifiying(UnparsedPublicKey<Vec<u8>>),
}

pub struct RS256 {
    kind: Kind
}

impl RS256 {

    pub fn new_signing<A: AsRef<Path>>(internal_private_key: A) -> Result<Self,Error> {

        let mut private_key_der = std::fs::File::open(internal_private_key)?;

        let mut contents: Vec<u8> = Vec::new();
        private_key_der.read_to_end(&mut contents)?;
        let internal_key_pair = RsaKeyPair::from_der(&contents)?;
        
        Ok(RS256 {
            kind: Kind::Signing(internal_key_pair)
        })

    }

    pub fn new_verifiying<A: AsRef<Vec<u8>>>(p_key: A) -> Result<Self,Error> {

        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,p_key.as_ref().to_owned());

        Ok(RS256 {
            kind: Kind::Verifiying(public_key)    
        })

    }
}

impl Display for RS256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"rs256")
    }
}

impl JWTAlgorithm for RS256 {

    fn verify_jwt(&self, jwt: &str) -> Result<(),Error> {

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

        match &self.kind {
            Kind::Signing(_) => Err(Error::Key(KeyError::KeyType)),
            Kind::Verifiying(key_pair) => {
                
                key_pair.verify(unprotected_jwt.as_bytes(), &mut signature)?;
                Ok(())
            
            } 
        }


    }

    fn sign_jwt(&self, headers: &str, payload: &str) -> Result<String,Error> {
        // Encodes them without pading
        let header_str = general_purpose::URL_SAFE_NO_PAD.encode(headers);
        let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(payload);

        // Creates no-signature jwt
        let unsecure_jwt = format!("{}.{}",header_str,payload_str);

        match &self.kind {
            Kind::Verifiying(_) =>  Err(Error::Key(KeyError::KeyType)),
            Kind::Signing(key_pair) => {

                let rng = rand::SystemRandom::new();
                let mut signature_vec = vec![0; key_pair.public_modulus_len()];
                // Obtain signature
                key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, unsecure_jwt.as_bytes(), &mut signature_vec)?;
                // Returns signed jwt
                return Ok(format!("{}.{}",unsecure_jwt, general_purpose::URL_SAFE_NO_PAD.encode(signature_vec)));

            },
        }
    }

}


#[cfg(test)]
mod test {

    use std::io::Read;

    use crate::{Error, sign_algorithms::{RS256, JWTAlgorithm}};


    #[test]
    fn sign_and_verify_asymmetric_signing() -> Result<(),Error> {

        let header = String::from("{\"Animal\": \"perrito\"}");
        let payload = String::from("{\"Nombre\": \"Caloncho\"}");
        
        let mut public_key_der = std::fs::File::open("./public.der")?;
        let mut contents: Vec<u8> = Vec::new();
        public_key_der.read_to_end(&mut contents)?;

        let signing_asym_key = RS256::new_signing("./private.der")?;
        let verifying_asym_key = RS256::new_verifiying(contents)?;

        let secured_jwt = signing_asym_key.sign_jwt(&header,&payload)?;
        verifying_asym_key.verify_jwt(&secured_jwt)


    }
}