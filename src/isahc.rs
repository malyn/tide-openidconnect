use bytes::BufMut;
use futures_lite::io::AsyncReadExt;
use isahc::{config::RedirectPolicy, prelude::*, HttpClient, Request};
use openidconnect::{HttpRequest, HttpResponse};

pub(crate) async fn http_client(request: HttpRequest) -> Result<HttpResponse, isahc::Error> {
    // TODO Create/Cache the client in a lazy/once/whatever singleton,
    // since isahc really wants you to only create one client per "module"
    // (which in this case is our middleware). Otherwise you could run
    // into some issues related to creating too many resources like sockets
    // and threads.
    let client = HttpClient::builder()
        .redirect_policy(RedirectPolicy::None)
        .build()?;

    let mut request_builder = Request::builder()
        .method(request.method)
        .uri(request.url.as_str());
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }
    let isahc_request = request_builder.body(request.body).unwrap();

    let isahc_response = client.send_async(isahc_request).await?;
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
