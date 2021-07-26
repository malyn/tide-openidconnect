use crate::common::authorizeurl::ParsedAuthorizeUrl;
use crate::common::cookiejar::SessionCookieJarMiddleware;
use crate::common::oidc_emulator::OpenIdConnectEmulator;
use crate::common::{assert_redirect, assert_response, create_test_server, get_config};
use http_types::StatusCode;
use tide::Request;
use tide_testing::TideTestingExt;

use tide_openidconnect::{
    OpenIdConnectMiddleware, OpenIdConnectRequestExt, OpenIdConnectRouteExt, RedirectUrl,
};

pub mod common;

#[async_std::test]
async fn authenticated_routes_require_login() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);

            // Add an additional route that requires an authenticated session.
            app.at("/needsauth")
                .authenticated()
                .get(|req: Request<()>| async move {
                    if !req.is_authenticated() {
                        panic!("An unauthenticated request should not have made it to an `authenticated()` handler.");
                    } else {
                        Ok("authed")
                    }
                });

            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Confirm that the authenticated route redirects us to the
            // login URL (since we are not yet logged in).
            let res = client.get("/needsauth").await?;
            assert_redirect(&res, "/login");

            // Go through the login process.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);

            let callback_url = emu
                .add_token("atoken", "openid", "id", &authorize_url)
                .await;

            let res = client.get(callback_url).await?;
            assert_redirect(&res, "/");

            // *Now* a request for the authenticated route should succeed.
            let mut res = client.get("/needsauth").await?;
            assert_response(&mut res, "authed").await;

            Ok(())
        })
        .await
}

#[async_std::test]
async fn authentication_protects_subsequent_verbs() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);

            // Additional routes, some protected, others unprotected.
            app.at("/")
                .get(|_req: Request<()>| async { Ok("Unprotected route") });

            app.at("/secret")
                .authenticated()
                .get(|_req: Request<()>| async { Ok("Protected GET") })
                .post(|_req: Request<()>| async { Ok("Protected POST") });

            app.at("/semi-secret")
                .get(|_req: Request<()>| async { Ok("*Unprotected* GET") })
                .authenticated()
                .post(|_req: Request<()>| async { Ok("Protected POST") });

            let client = app.client().with(SessionCookieJarMiddleware::default());

            // All HTTP handlers *before* the call to `authenticated()`
            // do not require authentication.
            assert_response(&mut client.get("/").await?, "Unprotected route").await;
            assert_response(&mut client.get("/semi-secret").await?, "*Unprotected* GET").await;

            // Handlers after the call require authentication.
            assert_redirect(&client.get("/secret").await?, "/login");
            assert_redirect(&client.post("/secret").await?, "/login");
            assert_redirect(&client.post("/semi-secret").await?, "/login");

            Ok(())
        })
        .await
}
