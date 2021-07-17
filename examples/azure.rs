//! Demonstrates the usage of `tide-openidconnect` with Azure's Active
//! Directory identity provider. Additional elements of this example:
//!
//! * The "index" route handles both authenticated and unauthenticated
//!   requests and displays different content based on the authentication
//!   status of the request. This is contrast to a route that uses
//!   `OpenIdConnectRequestExt.authenticated()` to only allow the route
//!   to see authenticated requests (and force authentication if an
//!   unauthenticated request is presented to that route). See the Auth0
//!   example for an example of that behavior.
//! * The access token received from the identity provider is used to call
//!   back into the Microsoft Graph service in order to retrieve the user's
//!   display name. This same flow can be used for any identity provider
//!   that also provides own APIs for use with that identity.
//! * Logout is supported and logs users out of the local app by clearing
//!   session state. Note that this does *not* log the user out of the
//!   identity provider! The user should be able to log back in to the
//!   app without having to present their credentials again. That behavior
//!   can be changed by setting the `idp_logout_url` URL in the configuration,
//!   which then destroys the identity provider session as well.

use dotenv::dotenv;
use serde::Deserialize;
use tide_openidconnect::{self, OpenIdConnectRequestExt};

#[async_std::main]
async fn main() -> tide::Result<()> {
    dotenv().ok();
    let cfg = Config::from_env().unwrap();

    tide::log::with_level(tide::log::LevelFilter::Info);
    let mut app = tide::new();

    // app.with(tide_csrf::CsrfMiddleware::new(&SECRET));

    app.with(
        tide::sessions::SessionMiddleware::new(
            tide::sessions::MemoryStore::new(),
            cfg.tide_secret.as_bytes(),
        )
        .with_same_site_policy(tide::http::cookies::SameSite::Lax),
    );

    app.with(tide_openidconnect::OpenIdConnectMiddleware::new(&cfg.azure).await);

    // Note that this example's single route does *not* require authentication
    // since we handle both authenticated and unauthenticated requests.
    app.at("/").get(index);

    app.listen("127.0.0.1:8000").await?;
    Ok(())
}

async fn get_display_name(access_token: &str) -> tide::Result<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProfileResponse {
        display_name: String,
    }
    let ProfileResponse { display_name } = surf::get("https://graph.microsoft.com/v1.0/me")
        .header("Authorization", format!("Bearer {}", access_token))
        .recv_json()
        .await?;
    Ok(display_name)
}

pub async fn index(req: tide::Request<()>) -> tide::Result {
    if req.is_authenticated() {
        let display_name = get_display_name(&req.access_token().unwrap()).await?;
        Ok(tide::Response::builder(200)
            .content_type(tide::http::mime::HTML)
            .body(format!(
                "<p>Hi {}, you are now logged in!</p>
    
                <p>Click <a href=\"/logout\">here</a> to logout <i>of this site</i>
                (you will remained logged into your Microsoft account).</p>",
                display_name
            ))
            .build())
    } else {
        Ok(tide::Response::builder(200)
            .content_type(tide::http::mime::HTML)
            .body(
                "<p>You are not logged in.</p>
        
                <p>Click <a href=\"/login\">here</a> to login.</p>",
            )
            .build())
    }
}

#[derive(Debug, Deserialize)]
struct Config {
    tide_secret: String,
    azure: tide_openidconnect::Config,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::new();
        cfg.merge(config::Environment::new().separator("__"))?;
        cfg.try_into()
    }
}
