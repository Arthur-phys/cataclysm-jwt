# Cataclysm-jwt

Simple session builder for JWT with support for RS256 and HS256 for [Cataclysm](https://github.com/Malanche/cataclysm).
_______
## Instalation

Simply add the dependecy to `Cargo.toml` file:
```
cataclysm-jwt = { git = "https://github.com/Arthur-phys/cataclysm-jwt.git" }
```
## Configuration

The crate has three optional features:
- **lax-security**: disables checking for 'aud', 'iss', 'exp', 'iat' and 'nbf' fields
- **jwk-alg**: Enables checking JWK for **optional** field 'alg'
- **jwk-use**: Enables checking JWK for **optional** fiel 'use'

## Examples

Two examples can be found under the `examples` folder. One is provided here for completeness:
```rs
const aud: &str = "AUDIENCE";
const iss: &str = "ISSUER";
const jwks_url: &str = "URL";
 
// Function requires a session as argument
async fn index(session: Session) -> Response {

    // Parameters on JWT Payload can be obtained easily:
    let iat = session.get("iat").unwrap();
    let name = session.get("name").unwrap();
    println!("Token issued at: {}",iat);
    println!("Name of person: {}",name);
    Response::ok().body("Hello, World!")

}


#[tokio::main]
async fn main() -> Result<(),Error> {

    let server = Server::builder(
        Branch::<()>::new("/").with(Method::Get.to(index))
    ).session_creator(
        // Builder requires a session
        // Assymmetric session built in this case
        JWTSessionBuilder::with_rs256().aud(aud)
        .iss(iss)
        // Used url for JWKs 
        .add_from_jwks(jwks_url)
        .await?
        .build()?
    )
    .build().unwrap();
 
    server.run("127.0.0.1:8000").await.unwrap();

    Ok(())

}
```

## Documentation
https://arthur-phys.github.io/cataclysm-jwt/cataclysm_jwt/

