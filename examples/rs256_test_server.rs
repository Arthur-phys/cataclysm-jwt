use cataclysm::{Server, Branch, http::{Response, Method}, session::Session};
use cataclysm_jwt::{jwt_session::JWTSessionBuilder, Error};

const AUD: &str = "AUDIENCE";
const ISS: &str = "ISSUER";
const JWKS_URL: &str = "URL";
 
async fn index(session: Session) -> Response {
    let iat = session.get("iat").unwrap();
    let name = session.get("name").unwrap();
    println!("Token issued at: {}",iat);
    println!("Name of okis: {}",name);
    Response::ok().body("Hello, World!")
}


#[tokio::main]
async fn main() -> Result<(),Error> {

    let server = Server::builder(
        Branch::<()>::new("/").with(Method::Get.to(index))
    ).session_creator(
        JWTSessionBuilder::with_rs256().aud(AUD)
        .iss(ISS)
        .add_from_jwks(JWKS_URL)
        .await?
        .build()?
    )
    .build().unwrap();
 
    server.run("127.0.0.1:8000").await.unwrap();

    Ok(())

}