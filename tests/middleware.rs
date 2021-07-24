use std::sync::Arc;

use async_std::prelude::*;
use async_std::task;
use tide::{
    http::headers::LOCATION,
    sessions::{MemoryStore, SessionMiddleware},
    Request, StatusCode,
};
use tide_testing::TideTestingExt;

use tide_openidconnect::{
    ClientId, ClientSecret, Config, IssuerUrl, OpenIdConnectMiddleware, OpenIdConnectRequestExt,
    OpenIdConnectRouteExt, RedirectUrl,
};

mod common;
use common::authorizeurl::ParsedAuthorizeUrl;
use common::cookiejar::SessionCookieJarMiddleware;
use common::oidc_emulator::OpenIdConnectEmulator;

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
fn middleware_provides_redirect_route() -> tide::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    task::block_on(async {
        let oidc_emulator = Arc::new(OpenIdConnectEmulator::new(
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

            // Add the `/` route, which we use to check the authed/unauthed
            // status status of the request. Note that we would also like
            // to use this handler to confirm that session state is preserved
            // across the auth procedure (which it is), but that behavior
            // is mostly a side-effect of the SessionMiddleware's cookie
            // setting (which *this* middleware requires be set to Lax).
            // So we could test that, but A) we would only be testing that
            // we set that to Lax earlier in this test function, and more
            // importantly B) wouldn't actually be testing the SameSite
            // setting anyway, since we are manually flowing the session
            // cookie across requests without even paying attention to the
            // SameSite attribute in the response. However, even with all
            // of that said, we still want to store (and later, check)
            // app-level session state, since we want to confirm that our
            // logout setting -- clear auth data vs. destroy session --
            // preserves/does not preserve that app state. Note that if
            // we destroy the session then the session id (and thus, cookie)
            // is no longer valid, whereas if we just clear the auth state
            // then the id is still valid and it is only the auth state
            // inside that session that is removed.
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
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.clone().with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            // Add the token to our emulator, then issue the callback to
            // our middleware (using the authorization code assigned to
            // the token by the emulator). This completes the authentication
            // process (by exchanging the code for a token) and redirects
            // the client to the landing path.
            let userid = "1234567890";
            let authorization_code = test_emulator
                .add_token("atoken", "openid", userid, &authorize_url.nonce.unwrap())
                .await;

            let res = client
                .get(format!(
                    "/callback?code={}&state={}",
                    authorization_code,
                    authorize_url.state.unwrap(),
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

        // Wait for the test to complete (or the OpenID Connect emulator
        // server to exit, although that would be unexpected).
        oidc_server.race(test).await
    })
}
