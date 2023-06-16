use cataclysm::{Server, Branch, http::{Response, Method}, session::Session};
use cataclysm_jwt::jwt_session::{JWTSession, JWTAsymmetricSession};
 
async fn index(_session: Session) -> Response {
    Response::ok().body("Hello, World!")
}


#[tokio::main]
async fn main() {

    let server = Server::builder(
        Branch::<()>::new("/").with(Method::Get.to(index))
    ).session_creator(
        JWTAsymmetricSession::builder().new_with_rs256_signing().audience("8cabf9ee-bd50-4d95-bfec-0aba7fb5fdba")
        .issuer("https://auth.cloudb.sat.gob.mx/nidp/oauth/nam").jwks("https://auth.cloudb.sat.gob.mx/nidp/oauth/nam/keys").build().await.unwrap()
    )
    .build().unwrap();
 
    server.run("localhost:8000").await.unwrap();

}