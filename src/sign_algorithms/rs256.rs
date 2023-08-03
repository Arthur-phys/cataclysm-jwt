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


#[cfg(test)]
mod test {

    // use std::io::Read;

    // use base64::{engine::general_purpose, Engine};
    // use ring::{signature::{RsaKeyPair, self}, rand};

    // use crate::{Error, sign_algorithms::RS256};

    // #[test]
    // fn from_primitives() -> Result<(),Error> {

    //     let n = "AKfNQkE4bI8xl9BSMH5WbsSBKAWM6C2F8hS6We3xDJCcqRtdUZEBCBiYo5kt3NIWrFjrcusSYYGXnvT8WRLZr0ERoaEwo-bcxHjBCYhDvgIpa1wIG8psgZmLjxxieKHIArcpkhM0Ly8ku8_dWhoSllH-49NANxKE6w8XLQ2R6CGK4x3KTwd0Wcb5nQaE5gfizZA91yZHoGgUL42BZg_s5RFi-U3XdT0Sw65mza-xZop10TO5xFwi1NFVphf-UeGgyB81sc2SRwufpqP6oZ1Ym6ncrWd-B6UdX5cnlredDUSdJpuhJqSXbPLNbd5qH1WNwO_f5jmi5UHsEEbbaDI2Wkk".to_string();
    //     let e = "AQAB".to_string();
    //     RS256::new_from_primitives(n, e)?;

    //     Ok(())
    // }

    // #[test]
    // fn sign_and_verify_asymmetric_signing() -> Result<(),Error> {

    //     let mut private_key_der = std::fs::File::open("./private.der")?;

    //     let mut contents: Vec<u8> = Vec::new();
    //     private_key_der.read_to_end(&mut contents)?;
    //     let key_pair = RsaKeyPair::from_der(&contents)?;

    //     let header = String::from("{\"Animal\": \"perrito\"}");
    //     let payload = String::from("{\"Nombre\": \"Caloncho\"}");

    //     // Encodes them without pading
    //     let header_str = general_purpose::URL_SAFE_NO_PAD.encode(header);
    //     let payload_str = general_purpose::URL_SAFE_NO_PAD.encode(payload);

    //     let unsecure_jwt = format!("{}.{}",header_str,payload_str);

    //     let rng = rand::SystemRandom::new();
    //     let mut signature_vec = vec![0; key_pair.public_modulus_len()];
    //     // Obtain signature
    //     key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, unsecure_jwt.as_bytes(), &mut signature_vec)?;
    //     // Returns signed jwt
    //     let secured_jwt = format!("{}.{}",unsecure_jwt, general_purpose::URL_SAFE_NO_PAD.encode(signature_vec));
        
    //     let mut public_key_der = std::fs::File::open("./public.der")?;
    //     let mut contents: Vec<u8> = Vec::new();
    //     public_key_der.read_to_end(&mut contents)?;

    //     let verifying_asym_key = RS256::new(contents)?;

    //     verifying_asym_key.verify_jwt(&secured_jwt)

    // }
}