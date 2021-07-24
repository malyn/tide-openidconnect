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

#[async_std::test]
async fn login_logout() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let (mut _app, client) = create_test_server_and_client(&emu.issuer_url()).await;

            // An initial check of our normal route should show that the request
            // (session, really) is not yet authenticated.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

            // Navigate to the login path, which should generate a redirect
            // to the authentication provider. We extract the state and nonce
            // from this redirect so that the test can generate the proper
            // auth provider response during the token exchange request.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.clone().with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            // Add the token to our emulator, then issue the callback to our
            // middleware (using the authorization code assigned to the token
            // by the emulator). This completes the authentication process
            // (by exchanging the code for a token) and redirects the client
            // to the landing path.
            let callback_url = emu
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
            // in to the identity provider) by navigating to the (middleware-
            // provided) logout route.
            let res = client.get("/logout").await?;
            assert_redirect(&res, "/");

            // Just as in the very beginning, navigating to our normal route
            // should show that the request (session) is no longer authenticated.
            // Furthermore, because we destroy the session in this test (which
            // is also the default), the "visits" counter has been reset,
            // indicating that the entire session has been destroyed.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

            Ok(())
        })
        .await
}
