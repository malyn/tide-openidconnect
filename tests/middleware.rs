use crate::common::authorizeurl::ParsedAuthorizeUrl;
use crate::common::cookiejar::SessionCookieJarMiddleware;
use crate::common::oidc_emulator::OpenIdConnectEmulator;
use crate::common::{assert_redirect, assert_response, create_test_server, get_config};
use http_types::StatusCode;
use tide_testing::TideTestingExt;

use tide_openidconnect::{OpenIdConnectMiddleware, RedirectUrl};

pub mod common;

#[async_std::test]
async fn middleware_can_be_initialized() -> tide::Result<()> {
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let _mw = OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await;
            Ok(())
        })
        .await
}

#[async_std::test]
async fn middleware_provides_login_route() -> http_types::Result<()> {
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Login and confirm that we are told to redirect to the identity
            // provider to begin the sign in process.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            Ok(())
        })
        .await
}

#[async_std::test]
async fn login_path_can_be_changed() -> http_types::Result<()> {
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(
                OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url()))
                    .await
                    .with_login_path("/oauthlogin"),
            );
            let client = app.client().with(SessionCookieJarMiddleware::default());

            let res = client.get("/oauthlogin").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            Ok(())
        })
        .await
}

#[async_std::test]
async fn oauth_scopes_can_be_changed() -> http_types::Result<()> {
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(
                OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url()))
                    .await
                    .with_scopes(&["profile"]),
            );
            let client = app.client().with(SessionCookieJarMiddleware::default());

            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default().with_scopes("openid profile"),
            );

            Ok(())
        })
        .await
}

#[async_std::test]
#[should_panic(
    expected = "request session not initialized, did you enable tide::sessions::SessionMiddleware?"
)]
async fn login_panics_on_missing_session_middleware() {
    let _result = OpenIdConnectEmulator::new(
        RedirectUrl::new("http://localhost/callback".to_string()).unwrap(),
    )
    .run_with_emulator(|emu| async move {
        let mut app = tide::new();
        // Note: *No* session middleware was added to the server.
        app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
        let client = app.client().with(SessionCookieJarMiddleware::default());

        // Login, which should panic as soon as the OpenID Connect Middleware
        // tries to access the request session.
        let _res = client.get("/login").await;

        // Unreachable, but required to satisfy `run_with_emulator`.
        Ok(())
    })
    .await;
}

#[async_std::test]
async fn login_rejects_invalid_csrf() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Navigate to the login path, which generates a redirect to the
            // authentication provider. Note that we do not need to confirm the
            // shape of the redirect URL (that happens in other tests), but we
            // do need to make this call in order to properly set up the session
            // state (which contains the CSRF state against which we will verify
            // the state in the callback).
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);

            // Issue the callback to our middleware, *but with a mismatched CSRF
            // state.* The request will be rejected before we even make the call
            // to the auth provider (hence no need to add the token to the
            // emulator).
            let res = client
                .get("/callback?code=12345&state=BADCSRFSTATE")
                .await?;
            assert_eq!(res.status(), StatusCode::Unauthorized);

            Ok(())
        })
        .await
}

#[async_std::test]
async fn login_route_rejects_invalid_nonce() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Login and confirm that we are told to redirect to the identity
            // provider to begin the sign in process.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.clone().with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            // Simulate the sign in process in the identity provider by
            // adding a token to our emulator, *but with a difference
            // nonce.*
            let callback_url = emu
                .add_token(
                    "atoken",
                    "openid",
                    "id",
                    &authorize_url.with_nonce(Some("BADNONCE".to_string())),
                )
                .await;

            // Complete the sign in process by redirecting back to our
            // application's callback URL; the request will fail because
            // the nonce in the token is not valid.
            let res = client.get(callback_url).await?;
            assert_eq!(res.status(), StatusCode::Unauthorized);

            Ok(())
        })
        .await
}

#[async_std::test]
async fn redirect_route_errors_on_missing_session_data() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Skip straight to the callback path, since the point of this
            // test is to confirm that missing session data generates an
            // error, not a panic.
            let res = client.get("/callback?code=12345&state=CSRFSTATE").await?;
            assert_eq!(res.status(), StatusCode::InternalServerError);

            Ok(())
        })
        .await
}

#[async_std::test]
#[should_panic(
    expected = "request session not initialized, did you enable tide::sessions::SessionMiddleware?"
)]
async fn redirect_route_panics_on_missing_session_middleware() {
    let _result = OpenIdConnectEmulator::new(
        RedirectUrl::new("http://localhost/callback".to_string()).unwrap(),
    )
    .run_with_emulator(|emu| async move {
        let mut app = tide::new();
        // Note: *No* session middleware was added to the server.
        app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
        let client = app.client().with(SessionCookieJarMiddleware::default());

        // Make a request to the callback path, which should panic as
        // soon as the OpenID Connect Middleware tries to access the
        // request session.
        let _res = client.get("/callback?code=12345&state=CSRFSTATE").await;

        // Unreachable, but required to satisfy `run_with_emulator`.
        Ok(())
    })
    .await;
}

#[async_std::test]
async fn login_and_destructive_logout() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url())).await);
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Request our test route; this is the first (unauthenticated) visit.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

            // Login and confirm that we are told to redirect to the identity
            // provider to begin the sign in process.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.clone().with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            // Simulate the sign in process in the identity provider by
            // adding a token to our emulator.
            let callback_url = emu
                .add_token("atoken", "openid", "id", &authorize_url)
                .await;

            // Complete the sign in process by redirecting back to our
            // application's callback URL.
            let res = client.get(callback_url).await?;
            assert_redirect(&res, "/");

            // Requesting our test route now shows that we are authenticated
            // (and also that we retained the pre-login session state).
            let mut res = client.get("/").await?;
            assert_response(
                &mut res,
                "authed visits=2 access_token=atoken scopes=[\"openid\"] userid=id",
            )
            .await;

            // Log the user out of the application, which redirects us to
            // the logout landing path.
            let res = client.get("/logout").await?;
            assert_redirect(&res, "/");

            // Because the middleware defaults to destroying the session on
            // logout, requesting the test route once again shows that the
            // request is authenticated (and we also have a new session, so
            // the "visits" counter has been reset).
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

            Ok(())
        })
        .await
}

#[async_std::test]
async fn login_and_auth_only_logout() -> http_types::Result<()> {
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            app.with(
                OpenIdConnectMiddleware::new(&get_config(&emu.issuer_url()))
                    .await
                    .with_logout_destroys_session(false),
            );
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Request our test route; this is the first (unauthenticated) visit.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=1").await;

            // Login and confirm that we are told to redirect to the identity
            // provider to begin the sign in process.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);
            assert_eq!(
                authorize_url.clone().with_nonce(None).with_state(None),
                ParsedAuthorizeUrl::default(),
            );

            // Simulate the sign in process in the identity provider by
            // adding a token to our emulator.
            let callback_url = emu
                .add_token("atoken", "openid", "id", &authorize_url)
                .await;

            // Complete the sign in process by redirecting back to our
            // application's callback URL.
            let res = client.get(callback_url).await?;
            assert_redirect(&res, "/");

            // Requesting our test route now shows that we are authenticated
            // (and also that we retained the pre-login session state).
            let mut res = client.get("/").await?;
            assert_response(
                &mut res,
                "authed visits=2 access_token=atoken scopes=[\"openid\"] userid=id",
            )
            .await;

            // Log the user out of the application, which redirects us to
            // the logout landing path.
            let res = client.get("/logout").await?;
            assert_redirect(&res, "/");

            // Just as in the very beginning, navigating to our test route
            // should show that the request is no longer authenticated.
            // However, unlike the test that uses the default logout options,
            // this test asks the middleware to clear only its auth state
            // and so our "visits" counter was retained.
            let mut res = client.get("/").await?;
            assert_response(&mut res, "unauthed visits=3").await;

            Ok(())
        })
        .await
}

#[async_std::test]
async fn logout_can_clear_idp_state() -> http_types::Result<()> {
    // tide::log::with_level(tide::log::LevelFilter::Warn);
    OpenIdConnectEmulator::new(RedirectUrl::new("http://localhost/callback".to_string()).unwrap())
        .run_with_emulator(|emu| async move {
            let mut app = create_test_server();
            let config = tide_openidconnect::Config {
                idp_logout_url: Some("http://idp.logout".to_string()),
                ..get_config(&emu.issuer_url())
            };
            app.with(OpenIdConnectMiddleware::new(&config).await);
            let client = app.client().with(SessionCookieJarMiddleware::default());

            // Log the user in.
            let res = client.get("/login").await?;
            assert_eq!(res.status(), StatusCode::Found);
            let authorize_url = ParsedAuthorizeUrl::from_response(&res);

            let callback_url = emu
                .add_token("atoken", "openid", "id", &authorize_url)
                .await;

            let res = client.get(callback_url).await?;
            assert_redirect(&res, "/");

            // Now log out; the default configuration would take us back
            // to the logout landing path, but in this test we have enabled
            // IdP logout and so we are redirected to that URL instead.
            let res = client.get("/logout").await?;
            assert_redirect(&res, "http://idp.logout");

            Ok(())
        })
        .await
}
