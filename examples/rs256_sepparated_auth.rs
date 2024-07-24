use cataclysm::{Server, Shared, Branch, http::{Request, Query}, Stream};
use cataclysm_jwt::{jwt_session::{JWTSessionBuilder, JWTRS256Session, JWTSession}, Error, JWT, sign_algorithms::RS256};
use std::collections::HashMap;
use serde::Deserialize;

#[derive(Clone)]
pub struct ServerData {
    pub keys: HashMap<String,RS256>
}

#[derive(Deserialize)]
pub struct SimpleToken {
    token: String
}

const AUD: &str = "AUDIENCE";
const ISS: &str = "ISSUER";
const JWKS_URL: &str = "URL";
 
async fn index(_stream: Stream, _req: Request, shared: Shared<ServerData>, query: Query<SimpleToken>) {
    // Some sort of verification can be done with a token inside a stream_handler branch of the server 
    // A raw jwt (String)
    let raw_jwt = query.into_inner().token;
    let jwt: JWT = JWTRS256Session::deserialize_token(raw_jwt).unwrap();

    // Check the kid
    let kid = match jwt.header.get("kid") {
        Some(id) => id,
        None => {
            panic!()
        }
    };

    // Check the algorithm on jwt is the sames as the one on the key and retrieve appropiate key
    let verification_key = match jwt.header.get("alg") {
        Some(a) => {
            let possible_key = shared.keys.get(kid);
            let key = match possible_key {
                Some(k) => k,
                None => {
                    panic!()
                }
            };
            if a.to_lowercase().as_str() != key.to_string() {
                panic!()
            }
            key
        },
        None => {
            panic!()
        }
    };

    // Verify the jwt
    match verification_key.verify_jwt(&jwt.raw_jwt) {
        Err(_) => panic!(),
        _ => {}
    };
    
    // Do more stuff...
    return;


}


#[tokio::main]
async fn main() -> Result<(),Error> {

    // Session builder
    let session = JWTSessionBuilder::with_rs256().aud(AUD)
    .iss(ISS)
    .add_from_jwks(JWKS_URL)
    .await?
    .build()?;
    // Keys can be used for other purposes, such as session verification on WebSockets, since session is not allowed as a
    // parameter in the stream handler of the server
    let keys = session.verification_keys.clone();

    let server = Server::builder(
        Branch::<ServerData>::new("/").stream_handler(index)
    )
        .share(ServerData {keys})
        .session_creator(session)
        .build().unwrap();
 
    server.run("127.0.0.1:8000").await.unwrap();

    Ok(())

}