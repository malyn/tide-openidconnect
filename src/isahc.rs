use bytes::BufMut;
use futures_lite::io::AsyncReadExt;
use isahc::{config::RedirectPolicy, prelude::*, HttpClient, Request};
use once_cell::sync::Lazy;
use openidconnect::{HttpRequest, HttpResponse};

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
        .unwrap()
});

pub(crate) async fn http_client(request: HttpRequest) -> Result<HttpResponse, isahc::Error> {
    let mut request_builder = Request::builder()
        .method(request.method)
        .uri(request.url.as_str());
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }
    let isahc_request = request_builder.body(request.body).unwrap();

    let isahc_response = HTTP_CLIENT.send_async(isahc_request).await?;
    let status_code = isahc_response.status();
    let headers = isahc_response.headers().to_owned();
    let mut response_body = isahc_response.into_body();

    let mut body = vec![];
    let mut buf = [0u8; 1024];
    loop {
        match response_body.read(&mut buf[..]).await {
            Ok(0) => break,
            Ok(len) => body.put(&buf[..len]),
            Err(err) => return Err(err.into()),
        }
    }

    Ok(HttpResponse {
        status_code,
        headers,
        body,
    })
}
