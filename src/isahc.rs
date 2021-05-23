use futures_lite::{io::Cursor, AsyncRead};
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

    Ok(HttpResponse {
        status_code: response.status(),
        headers: response.headers().to_owned(),
        body: to_bytes(response.into_body()).await?,
    })
}

async fn to_bytes<R>(reader: R) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    // Create a cursor to a vector, which provides the vector with an
    // AsyncRead trait that appends to the vector.
    let mut writer = Cursor::new(Vec::new());

    // Asynchronously copy the data from the reader to the buffer.
    futures_lite::io::copy(reader, &mut writer)
        .await
        .map_err(Error::Io)?;

    // Return the buffer inside of the reader.
    Ok(writer.into_inner())
}
