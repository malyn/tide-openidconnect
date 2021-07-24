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
use crate::common::{
    assert_redirect, assert_response, authorizeurl::ParsedAuthorizeUrl,
    cookiejar::SessionCookieJarMiddleware, create_test_server_and_client,
    oidc_emulator::OpenIdConnectEmulator,
};

#[test]
fn login_logout() -> tide::Result<()> {
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
            let (mut _app, client) =
                create_test_server_and_client(&test_emulator.issuer_url()).await;

            // An initial check of our normal route should show that the request
            // (session, really) is not yet authenticated.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

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
            let callback_url = test_emulator
                .add_token("atoken", "openid", "id", &authorize_url)
                .await;
            let res = client.get(callback_url).await?;
            assert_redirect(&res, "/");

            // A final check of our normal route should show that the request
            // (session, really) is authenticated, and contains the user id.
            let mut res = client.get("/").await?;
            assert_response(
                &mut res,
                "authed visits=2 access_token=atoken scopes=[\"openid\"] userid=id",
            )
            .await;

            // Log the user out of *the application* (they will still be logged
            // in to the identity provider) by navigating to the (middleware-provided)
            // logout route.
            let res = client.get("/logout").await?;
            assert_redirect(&res, "/");

            // Just as in the very beginning, navigating to our normal route should
            // show that the request (session) is no longer authenticated. Furthermore,
            // because we destroy the session in this test (which is also the default),
            // the "visits" counter has been reset, indicating that the entire session
            // has been destroyed.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

            Ok(())
        });

        // Wait for the test to complete (or the OpenID Connect emulator
        // server to exit, although that would be unexpected).
        oidc_server.race(test).await
    })
}
