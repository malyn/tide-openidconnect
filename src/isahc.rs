// TODO Move this into `lib.rs` so that we protect the entire library?
#![deny(clippy::unwrap_in_result, clippy::unwrap_used)]

use bytes::BufMut;
use futures_lite::io::AsyncReadExt;
use isahc::{config::RedirectPolicy, prelude::*, HttpClient, Request};
use once_cell::sync::Lazy;
use openidconnect::{HttpRequest, HttpResponse};

///
/// Error type returned by failed Isahc HTTP requests.
///
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Error returned by Isahc crate.
    #[error("Isahc request failed")]
    Isahc(#[source] isahc::Error),
    /// Non-Isahc HTTP error.
    #[error("HTTP error")]
    Http(#[source] http::Error),
    /// I/O error.
    #[error("I/O error")]
    Io(#[source] std::io::Error),
}

// Isahc recommends that you create a single client per "area of application"
// and reuse that client through your code. We have to create a global client
// instance (instead of putting the client in a struct and then having the
// `http_client` function be a trait function) because we need to pass the
// bare `http_client` function to the oauth2-rs crate and we cannot close
// over `self` when doing that.
static HTTP_CLIENT: Lazy<HttpClient> = Lazy::new(|| {
    HttpClient::builder()
        .redirect_policy(RedirectPolicy::None)
        .build()
        .expect("Unable to initialize Isahc client.")
});

pub(crate) async fn http_client(openid_request: HttpRequest) -> Result<HttpResponse, Error> {
    let mut request_builder = Request::builder()
        .method(openid_request.method)
        .uri(openid_request.url.as_str());
    for (name, value) in &openid_request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }
    let request = request_builder
        .body(openid_request.body)
        .map_err(Error::Http)?;

    let response = HTTP_CLIENT
        .send_async(request)
        .await
        .map_err(Error::Isahc)?;
    let status_code = response.status();
    let headers = response.headers().to_owned();
    let mut response_body = response.into_body();

    let mut body = vec![];
    let mut buf = [0u8; 1024];
    loop {
        match response_body.read(&mut buf[..]).await.map_err(Error::Io)? {
            0 => break,
            len => body.put(&buf[..len]),
        }
    }

    Ok(HttpResponse {
        status_code,
        headers,
        body,
    })
}
