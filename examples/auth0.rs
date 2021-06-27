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

    app.with(tide_openidconnect::OpenIdConnectMiddleware::new(&cfg.auth0).await);

    app.at("/").authenticated().get(|req: tide::Request<()>| async move {
        Ok(format!("This route requires authentication, and so I can say for sure that you have a user id: {} (scopes {:?})", req.user_id().unwrap(), req.scopes().unwrap()))
    });

    app.listen("127.0.0.1:8000").await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Config {
    tide_secret: String,
    auth0: tide_openidconnect::Config,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::new();
        cfg.merge(config::Environment::new().separator("__"))?;
        cfg.try_into()
    }
}
