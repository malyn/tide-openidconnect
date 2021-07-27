tide-openidconnect
==================

[![Build Status](https://github.com/malyn/tide-openidconnect/actions/workflows/main.yml/badge.svg)](https://github.com/malyn/tide-openidconnect/actions/workflows/main.yml)
[![Latest version](https://img.shields.io/crates/v/tide-openidconnect.svg)](https://crates.io/crates/tide-openidconnect)
[![Documentation](https://docs.rs/tide-openidconnect/badge.svg)](https://docs.rs/tide-openidconnect)
![License](https://img.shields.io/crates/l/tide-openidconnect.svg)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md) 

OpenID Connect middleware for Tide. Uses the OAuth 2.0 protocol to
authenticate users, retrieve access tokens, and make the authentication
status and tokens available to Tide requests. Includes optional route
middleware that blocks access to specific routes unless the request is
authenticated (redirecting the user through the authentication process
if not).

- [Documentation](https://docs.rs/tide-openidconnect)
- [Release notes](https://github.com/malyn/tide-openidconnect/releases)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tide-openidconnect = "0.1"
```

## Examples

```rust
use tide_openidconnect::{self, OpenIdConnectRequestExt, OpenIdConnectRouteExt};

let mut app = tide::new();

// OpenID Connect middleware *requires* session storage. Note that the
// cookies must be configured with `SameSite::Lax`.
app.with(
    tide::sessions::SessionMiddleware::new(
        tide::sessions::MemoryStore::new(),
        b"don't actually use a hardcoded secret",
    )
    .with_same_site_policy(tide::http::cookies::SameSite::Lax),
);

// Initialize the OpenID Connect middleware; normally all of these
// configuration values would come from an environment-specific config
// file, and in fact that is why they are in their own struct (so that
// you can deserialize that struct from a file or environment variables).
app.with(
    tide_openidconnect::OpenIdConnectMiddleware::new(
        &tide_openidconnect::Config {
            issuer_url: tide_openidconnect::IssuerUrl::new("https://your-tenant-name.us.auth0.com/".to_string()).unwrap(),
            client_id: tide_openidconnect::ClientId::new("app-id-goes-here".to_string()),
            client_secret: tide_openidconnect::ClientSecret::new("app-secret-goes-here".to_string()),
            redirect_url: tide_openidconnect::RedirectUrl::new("http://your.cool.site/callback".to_string()).unwrap(),
            idp_logout_url: None,
        }
    )
    .await,
);

// Define a basic Tide route, but protect it with the middleware's
// `.authenticated()` route extension.
app.at("/").authenticated().get(|req: tide::Request<()>| async move {
    Ok(format!(
        "If you got this far, then the request is authenticated, and your user id is {:?}",
        req.user_id()
    ))
});
```

See more examples in the
[examples](https://github.com/malyn/tide-openidconnect/tree/main/examples)
directory.

## Conduct

This project adheres to the [Contributor Covenant Code of
Conduct](https://github.com/malyn/tide-openidconnect/blob/main/CODE_OF_CONDUCT.md).
This describes the minimum behavior expected from all contributors.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.