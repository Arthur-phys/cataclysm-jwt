use cataclysm::{Server, Branch, http::{Response, Method}, session::Session};
use cataclysm_jwt::{jwt_session::JWTSessionBuilder, Error};
 
const aud: &str = "AUDIENCE";
const iss: &str = "ISSUER";

async fn index(session: Session) -> Response {
    let iat = session.get("iat").unwrap();
    println!("Token issued at: {}",iat);
    Response::ok().body("Hello, World!")
}


#[tokio::main]
async fn main() -> Result<(),Error> {

    let server = Server::builder(
        Branch::<()>::new("/").with(Method::Get.to(index))
    ).session_creator(
        JWTSessionBuilder::with_hs256().aud(aud)
        .iss(iss)
        .add_from_secret("perritos")
        .build()?
    )
    .build().unwrap();
 
    server.run("127.0.0.1:8000").await.unwrap();

    Ok(())

}