use dotenv::dotenv;
use serde::Deserialize;
use tide_openidconnect::{self, OpenIdConnectRequestExt, OpenIdConnectRouteExt};

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

    app.with(
        tide_openidconnect::OpenIdConnectMiddleware::new(
            &cfg.auth0_issuer_url,
            &cfg.auth0_client_id,
            &cfg.auth0_client_secret,
            &tide_openidconnect::RedirectUrl::new("http://localhost:8000/callback".to_string())
                .unwrap(),
        )
        .await,
    );

    app.at("/").authenticated().get(|req: tide::Request<()>| async move {
        Ok(format!("This route requires authentication, and so I can say for sure that you have a user id: {}", req.user_id().unwrap()))
    });

    app.listen("127.0.0.1:8000").await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Config {
    tide_secret: String,

    // TODO Move all of these into a `tide_oidc::Config` struct (and add
    // things like `login_url` and `redirect_url` and stuff, which should
    // be `Option<String>` since we will default to `/login` *et al*) and
    // then use the dotenv crate's double-underscore thing to load them
    // through names like `OPENID__ISSUER_URL` and stuff.
    auth0_issuer_url: tide_openidconnect::IssuerUrl,
    auth0_client_id: tide_openidconnect::ClientId,
    auth0_client_secret: tide_openidconnect::ClientSecret,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::new();
        cfg.merge(config::Environment::new())?;
        cfg.try_into()
    }
}
