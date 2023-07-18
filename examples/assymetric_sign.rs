// use cataclysm::{Server, Branch, http::{Response, Method}, session::Session};
// use cataclysm_jwt::jwt_session::{JWTSession, JWTAsymmetricSession};
 
// /* eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjdBTmZNRUFOcmhWT3FQTTdGQnZlTiJ9.eyJjb250ZXh0Ijp7InVzZXIiOnsiYXZhdGFyIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUFjSFR0ZXlZcGxVQkREZGdIRWZVcVVVNHFILThQeHBHRUpqY1owY0Rib2M9czk2LWMiLCJlbWFpbCI6ImFydHVyby5qbXMucHJvZ0BnbWFpbC5jb20iLCJuYW1lIjoiSm9yZ2UgQXJ0dXJvIE1hcnTDrW5leiBTw6FuY2hleiJ9fSwiaXNzIjoiaHR0cHM6Ly9kZXYtaG15bzNzb3lzNjJibDY3di51cy5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMDc4NDQxNDg0ODg2MjUyNjM5NzIiLCJhdWQiOiJodHRwOi8vY2F0YWNseXNtLnJzLyIsImlhdCI6MTY4Njk1Nzc0NSwiZXhwIjoxNjg3MDQ0MTQ1LCJhenAiOiI2bXgzcEttMldVVnJoVDk0ZlhyM0lOclB3djZaRTN2YSIsInNjb3BlIjoib2ZmbGluZV9hY2Nlc3MifQ.KD9LyBpaumlELdHZY0g3nkIpfmml0Qv4fSaWGF4UOHy2VCTyHqq9S7ZuMOdQtV8e26hd0G9MRU2-82FYz9tx0_iCGW8pxMwb0WLJOCwy68Rj08-6-NX1xP90OPOmdRya9jaembKPxP2NCjivOzJJH9fsbVJ1q33C72-9rLLH9lBBgucQ2WAwQw0EgMss2cfMGJBDLSJ5Qe3e1Svm9XrPrcnumcxjdgOKImj9YDDrcZ5USpHz5QX7_u6er9Z9pDBZDmQRw0xvukfsWFaH1sB7tJTbpfX5sQXDZJAJSJRWLQxEBhEt3orowf-wcnpWoXBIh5Ailwb_GPJO6SaGzFJiVg */

// async fn index(_session: Session) -> Response {
//     Response::ok().body("Hello, World!")
// }

// async fn doggies() -> Response {
//     Response::ok().body("Little doggies")
// }

// #[tokio::main]
// async fn main() {

//     let server = Server::builder(
//         Branch::<()>::new("/").with(Method::Get.to(index)).nest(
//             Branch::<()>::new("/doggies").with(Method::Get.to(doggies))
//         )
//     ).session_creator(
//         JWTAsymmetricSession::builder().new_with_rs256_signing().audience("http://cataclysm.rs/")
//         .issuer("https://dev-hmyo3soys62bl67v.us.auth0.com/").jwks("https://dev-hmyo3soys62bl67v.us.auth0.com/.well-known/jwks.json").build().await.unwrap()
//     )
//     .build().unwrap();
 
//     server.run("localhost:8000").await.unwrap();

// }

fn main() {
    
}