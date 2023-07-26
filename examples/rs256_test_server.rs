use cataclysm::{Server, Branch, http::{Response, Method}, session::Session};
use cataclysm_jwt::{jwt_session::JWTSessionBuilder, Error};
 
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
        JWTSessionBuilder::with_rs256().aud("8cabf9ee-bd50-4d95-bfec-0aba7fb5fdba")
        .iss("https://auth.cloudb.sat.gob.mx/nidp/oauth/nam")
        .add_from_jwks("https://auth.cloudb.sat.gob.mx/nidp/oauth/nam/keys")
        .await?
        .build()?
    )
    .build().unwrap();
 
    server.run("127.0.0.1:8000").await.unwrap();

    Ok(())

}