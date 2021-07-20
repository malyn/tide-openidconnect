use std::{collections::HashMap, sync::Arc};

use async_lock::Mutex;
use async_std::prelude::*;
use async_std::task;
use tide::{
    http::headers::{COOKIE, LOCATION, SET_COOKIE},
    sessions::{MemoryStore, SessionMiddleware},
    Request, StatusCode,
};
use tide_testing::TideTestingExt;

use tide_openidconnect::{
    ClientId, ClientSecret, Config, IssuerUrl, OpenIdConnectMiddleware, OpenIdConnectRequestExt,
    OpenIdConnectRouteExt, RedirectUrl,
};

mod common;
use common::oidc_emulator;

struct SessionCookieJarMiddleware {
    session_cookie: Arc<Mutex<Option<tide::http::Cookie<'static>>>>,
}

impl Default for SessionCookieJarMiddleware {
    fn default() -> Self {
        Self {
            session_cookie: Arc::new(Mutex::new(None)),
        }
    }
}

#[surf::utils::async_trait]
impl surf::middleware::Middleware for SessionCookieJarMiddleware {
    async fn handle(
        &self,
        mut req: surf::Request,
        client: surf::Client,
        next: surf::middleware::Next<'_>,
    ) -> surf::Result<surf::Response> {
        // Add the session cookie, if we have one, to the request.
        if let Some(cookie) = &*self.session_cookie.lock().await {
            tide::log::trace!("Adding session cookie to request.");
            req.set_header(COOKIE, cookie.to_string());
        }

        // Continue the request and collect the response.
        let res = next.run(req, client).await?;

        // Did we get a session cookie back? If so, either replace our
        // current session cookie, or clear the existing session cookie
        // if the new one has already expired (which is how servers
        // ask the browser to delete a cookie).
        if let Some(values) = res.header(SET_COOKIE) {
            if let Some(value) = values.get(0) {
                let mut session_cookie_guard = self.session_cookie.lock().await;

                let cookie = tide::http::Cookie::parse(value.to_string()).unwrap();
                if cookie
                    .expires()
                    .unwrap()
                    .ge(&time::OffsetDateTime::now_utc())
                {
                    tide::log::trace!("Received new/updated session cookie from server.");
                    *session_cookie_guard = Some(cookie);
                } else {
                    tide::log::trace!("Server removed session cookie.");
                    *session_cookie_guard = None;
                }
            }
        }

        // Pass the response back up the middleware chain.
        Ok(res)
    }
}

#[derive(Debug, PartialEq)]
struct ParsedAuthorizeUrl {
    host: String,
    path: String,
    response_type: String,
    client_id: String,
    scopes: String,
    state: Option<String>,
    nonce: Option<String>,
    redirect_uri: String,
}

impl ParsedAuthorizeUrl {
    fn default() -> Self {
        Self {
            host: "localhost".to_owned(),
            path: "/authorization".to_owned(),
            response_type: "code".to_owned(),
            client_id: "CLIENT-ID".to_string(),
            scopes: "openid".to_owned(),
            state: None,
            nonce: None,
            redirect_uri: "http://localhost/callback".to_string(),
        }
    }

    fn from_url(s: impl AsRef<str>) -> Self {
        let url = openidconnect::url::Url::parse(s.as_ref()).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();

        Self {
            host: url.host_str().unwrap().to_owned(),
            path: url.path().to_owned(),
            response_type: query.get("response_type").unwrap().to_owned(),
            client_id: query.get("client_id").unwrap().to_owned(),
            scopes: query.get("scope").unwrap().to_owned(),
            state: Some(query.get("state").unwrap().to_owned()),
            nonce: Some(query.get("nonce").unwrap().to_owned()),
            redirect_uri: query.get("redirect_uri").unwrap().to_owned(),
        }
    }

    fn with_nonce(self, nonce: Option<String>) -> Self {
        Self { nonce, ..self }
    }

    fn with_scopes(self, scopes: impl AsRef<str>) -> Self {
        Self {
            scopes: scopes.as_ref().to_owned(),
            ..self
        }
    }

    fn with_state(self, state: Option<String>) -> Self {
        Self { state, ..self }
    }
}

const SECRET: [u8; 32] = *b"secrets must be >= 32 bytes long";

fn get_config(issuer_url: IssuerUrl) -> tide_openidconnect::Config {
    Config {
        issuer_url,
        client_id: ClientId::new("CLIENT-ID".to_string()),
        client_secret: ClientSecret::new("CLIENT-SECRET".to_string()),
        redirect_url: RedirectUrl::new("http://localhost/callback".to_string()).unwrap(),
        idp_logout_url: None,
    }
}

#[test]
fn hello_world() -> tide::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    task::block_on(async {
        let oidc_emulator = Arc::new(oidc_emulator::OpenIdConnectEmulator::new(
            RedirectUrl::new("http://localhost/callback".to_string()).unwrap(),
        ));
        let oidc_server = oidc_emulator.run();

        // TODO What if we made this an oidc_emulator.run() fn? The idea is
        // that *the emulator* calls the function and then returns when that
        // function completes. This solves the drop problem, avoids the Arc,
        // etc.
        let test_emulator = Arc::clone(&oidc_emulator);
        let test = task::spawn(async move {
            let mut app = tide::new();
            app.with(
                SessionMiddleware::new(MemoryStore::new(), &SECRET)
                    .with_same_site_policy(tide::http::cookies::SameSite::Lax),
            );

            app.with(OpenIdConnectMiddleware::new(&get_config(test_emulator.issuer_url())).await);

            app.at("/").get(|mut req: Request<()>| async move {
                // Get/Update the request counter (used to verify session state
                // across login/logout operations).
                let session = req.session_mut();
                let visits: usize = session.get::<usize>("visits").unwrap_or_default() + 1;
                session.insert("visits", visits).unwrap();

                // Return the string that we use to validate the request state.
                Ok(if req.is_authenticated() {
                    format!(
                        "authed visits={} access_token={} scopes={:?} userid={}",
                        visits,
                        req.access_token().unwrap(),
                        req.scopes().unwrap(),
                        req.user_id().unwrap(),
                    )
                } else {
                    format!("unauthed visits={}", visits)
                })
            });

            // Create our test client (and its session cookie jar).
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // An initial check of our normal route should show that the request
            // (session, really) is not yet authenticated.
            let mut res = client.get("/").await?;
            assert_eq!(res.status(), StatusCode::Ok);
            assert_eq!(res.body_string().await?, "unauthed visits=1");

            // Navigate to the login path, which should generate a redirect to the
            // authentication provider. We extract the state and nonce from this
            // redirect so that the test can generate the proper auth provider
            // response during the token exchange request.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_url(
                res.header(LOCATION).unwrap().get(0).unwrap().as_str(),
            );
            println!("authorize_url: {:?}", authorize_url);
            let state = authorize_url.state.clone().unwrap().to_string();
            let nonce = authorize_url.nonce.clone().unwrap();
            assert_eq!(
                authorize_url.with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            // Prepare the auth provider's token response, then issue the callback
            // to our middleware, which completes the authentication process (by
            // exchaning the code for a token) and then redirects to the landing
            // path.
            let userid = "1234567890";
            let authorization_code = test_emulator
                .add_token(oidc_emulator::Token {
                    access_token: "atoken".to_string(),
                    scopes: "openid".to_string(),
                    userid: userid.to_string(),
                    nonce,
                })
                .await;

            let res = client
                .get(format!(
                    "/callback?code={}&state={}",
                    authorization_code, state
                ))
                .await?;
            assert_eq!(res.status(), StatusCode::Found);
            assert_eq!(res.header(LOCATION).unwrap().get(0).unwrap(), "/");

            // A final check of our normal route should show that the request
            // (session, really) is authenticated, and contains the user id.
            let mut res = client.get("/").await?;
            assert_eq!(res.status(), StatusCode::Ok);
            assert_eq!(
                res.body_string().await?,
                format!(
                    "authed visits=2 access_token=atoken scopes=[\"openid\"] userid={}",
                    userid
                )
            );

            // Log the user out of *the application* (they will still be logged
            // in to the identity provider) by navigating to the (middleware-provided)
            // logout route.
            let res = client.get("/logout").await?;
            assert_eq!(res.status(), StatusCode::Found);
            assert_eq!(res.header(LOCATION).unwrap().get(0).unwrap().as_str(), "/");

            // Just as in the very beginning, navigating to our normal route should
            // show that the request (session) is no longer authenticated. Furthermore,
            // because we destroy the session in this test (which is also the default),
            // the "visits" counter has been reset, indicating that the entire session
            // has been destroyed.
            let mut res = client.get("/").await?;
            assert_eq!(res.status(), StatusCode::Ok);
            assert_eq!(res.body_string().await?, "unauthed visits=1");

            Ok(())
        });

        oidc_server.race(test).await
    })
}
