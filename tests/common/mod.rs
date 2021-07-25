use http_types::{headers::LOCATION, StatusCode};
use tide::sessions::{MemoryStore, SessionMiddleware};

use tide_openidconnect::{ClientId, ClientSecret, IssuerUrl, OpenIdConnectRequestExt, RedirectUrl};

pub mod authorizeurl;
pub mod cookiejar;
pub mod oidc_emulator;

const SECRET: [u8; 32] = *b"secrets must be >= 32 bytes long";

pub fn get_config(issuer_url: &IssuerUrl) -> tide_openidconnect::Config {
    tide_openidconnect::Config {
        issuer_url: issuer_url.clone(),
        client_id: ClientId::new("CLIENT-ID".to_string()),
        client_secret: ClientSecret::new("CLIENT-SECRET".to_string()),
        redirect_url: RedirectUrl::new("http://localhost/callback".to_string()).unwrap(),
        idp_logout_url: None,
    }
}

pub fn create_test_server() -> tide::Server<()> {
    // Create the Tide server and our (required-by-OpenIdConnectMiddleware)
    // session middleware. We do *not* add the OpenIdConnectMiddleware
    // in this function; we let the caller do that so that it can configure
    // the middleware according to the requirements of the test.
    let mut app = tide::new();

    app.with(
        SessionMiddleware::new(MemoryStore::new(), &SECRET)
            .with_same_site_policy(tide::http::cookies::SameSite::Lax),
    );

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
    app.at("/").get(|mut req: tide::Request<()>| async move {
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

    // Return the server.
    app
}

pub async fn assert_response(res: &mut surf::Response, expected_body: impl AsRef<str>) {
    if res.status() != StatusCode::Ok {
        panic!(
            "Response should have HTTP Status `Ok`, instead it had `{}`",
            res.status()
        );
    }

    let body = res.body_string().await.unwrap();
    if body != expected_body.as_ref() {
        panic!(
            "Expected body `{}`, found `{}` instead.",
            expected_body.as_ref(),
            body
        );
    }
}

pub fn assert_redirect(res: &surf::Response, expected_target: impl AsRef<str>) {
    if res.status() != StatusCode::Found {
        panic!(
            "Redirect should have HTTP Status `Found`, instead it had `{}`",
            res.status()
        );
    }

    let target = res.header(LOCATION).unwrap().get(0).unwrap();
    if target != expected_target.as_ref() {
        panic!(
            "Expected redirect to location `{}`, found `{}` instead.",
            expected_target.as_ref(),
            target
        );
    }
}
