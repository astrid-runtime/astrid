//! Bounded, anonymous Pages transport for the production TUF adapter.
//!
//! The transport is intentionally separate from source persistence. It
//! accepts only HTTPS (or loopback HTTP for local tests), disables automatic
//! redirects, sends no credentials, and bounds streamed response bytes before
//! handing them to tough. Artifact redirects are followed manually with every
//! hop revalidated.

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use reqwest::redirect::Policy;
use std::collections::BTreeSet;
use std::time::Duration;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

use super::IndexError;

/// Default maximum response body accepted by the Pages transport.
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A reqwest-backed tough transport with bounded bodies and no redirects.
#[derive(Debug, Clone)]
pub(crate) struct ReqwestTufTransport {
    client: reqwest::Client,
    max_response_bytes: usize,
}

impl ReqwestTufTransport {
    /// Construct a client with redirect following disabled.
    pub(crate) fn new(max_response_bytes: usize) -> Result<Self, IndexError> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|source| IndexError::Network {
                operation: "build Pages HTTP client".to_owned(),
                message: source.to_string(),
            })?;
        Ok(Self {
            client,
            max_response_bytes: max_response_bytes.max(1),
        })
    }

    /// Construct an adapter around an injected client (hermetic tests can
    /// use a custom connector or a loopback server).
    pub(crate) fn with_client(client: reqwest::Client, max_response_bytes: usize) -> Self {
        Self {
            client,
            max_response_bytes: max_response_bytes.max(1),
        }
    }

    /// Maximum body size accepted by this transport.
    pub(crate) const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Download one sealed artifact URL with bounded, manually validated
    /// redirects and a bounded response. This uses the same anonymous,
    /// HTTPS-only client as TUF metadata reads; callers still verify the
    /// protocol digest before handing bytes to an installer.
    pub(crate) async fn download_bytes(
        &self,
        url: &Url,
        max_bytes: usize,
    ) -> Result<Vec<u8>, IndexError> {
        const MAX_REDIRECTS: usize = 5;
        let mut current = url.clone();
        let mut visited = BTreeSet::new();
        let limit = self.max_response_bytes.min(max_bytes.max(1));
        for redirect_count in 0..=MAX_REDIRECTS {
            validate_fetch_url(&current).map_err(|message| IndexError::Network {
                operation: "download Index artifact".to_owned(),
                message: format!("{current} ({message})"),
            })?;
            if !visited.insert(current.as_str().to_owned()) {
                return Err(IndexError::Network {
                    operation: "download Index artifact".to_owned(),
                    message: format!("{current}: redirect loop detected"),
                });
            }
            let response = self
                .client
                .get(current.clone())
                .send()
                .await
                .map_err(|source| IndexError::Network {
                    operation: "download Index artifact".to_owned(),
                    message: format!("{current}: {source}"),
                })?;
            if response.status().is_redirection() {
                if redirect_count == MAX_REDIRECTS {
                    return Err(IndexError::Network {
                        operation: "download Index artifact".to_owned(),
                        message: format!("{current}: too many redirects (limit {MAX_REDIRECTS})"),
                    });
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| IndexError::Network {
                        operation: "download Index artifact".to_owned(),
                        message: format!("{current}: redirect has no Location header"),
                    })?
                    .to_str()
                    .map_err(|_| IndexError::Network {
                        operation: "download Index artifact".to_owned(),
                        message: format!("{current}: redirect Location is not valid UTF-8"),
                    })?;
                if raw_redirect_location_is_unsafe(location) {
                    return Err(IndexError::Network {
                        operation: "download Index artifact".to_owned(),
                        message: format!(
                            "{current}: redirect Location contains traversal or encoded separators"
                        ),
                    });
                }
                current = current
                    .join(location)
                    .map_err(|source| IndexError::Network {
                        operation: "download Index artifact".to_owned(),
                        message: format!(
                            "{current}: invalid redirect Location {location:?}: {source}"
                        ),
                    })?;
                continue;
            }
            if !response.status().is_success() {
                return Err(IndexError::Network {
                    operation: "download Index artifact".to_owned(),
                    message: format!("{current}: HTTP {}", response.status()),
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > limit as u64)
            {
                return Err(IndexError::Network {
                    operation: "download Index artifact".to_owned(),
                    message: format!("{current}: body exceeds {limit} bytes"),
                });
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|source| IndexError::Network {
                    operation: "download Index artifact".to_owned(),
                    message: format!("{current}: {source}"),
                })?;
                let next_len = body.len().saturating_add(chunk.len());
                if next_len > limit {
                    return Err(IndexError::Network {
                        operation: "download Index artifact".to_owned(),
                        message: format!("{current}: body exceeds {limit} bytes"),
                    });
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(body);
        }
        unreachable!("artifact redirect loop exits via return")
    }
}

#[async_trait]
impl Transport for ReqwestTufTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        validate_fetch_url(&url).map_err(|message| {
            TransportError::new(TransportErrorKind::Other, format!("{url} ({message})"))
        })?;

        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|source| {
                TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), source)
            })?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(TransportError::new(
                if status == reqwest::StatusCode::NOT_FOUND {
                    TransportErrorKind::FileNotFound
                } else {
                    TransportErrorKind::Other
                },
                format!("{url} (HTTP {status})"),
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(TransportError::new(
                TransportErrorKind::Other,
                format!("{} (body exceeds {} bytes)", url, self.max_response_bytes),
            ));
        }

        let limit = self.max_response_bytes;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|source| {
                TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), source)
            })?;
            let next_len = body.len().saturating_add(chunk.len());
            if next_len > limit {
                return Err(TransportError::new(
                    TransportErrorKind::Other,
                    format!("{url} (body exceeds {limit} bytes)"),
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let one =
            futures::stream::once(async move { Ok::<Bytes, TransportError>(Bytes::from(body)) });
        Ok(Box::pin(one))
    }
}

fn validate_fetch_url(url: &Url) -> Result<(), String> {
    let scheme = url.scheme();
    let host = url.host_str().ok_or_else(|| "URL has no host".to_owned())?;
    let host_for_loopback = host.trim_matches(['[', ']']);
    let loopback_http = scheme == "http"
        && (host_for_loopback.eq_ignore_ascii_case("localhost")
            || host_for_loopback
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback()));
    if scheme != "https" && !loopback_http {
        return Err("only HTTPS or loopback HTTP is permitted".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL credentials are not permitted".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("URL query and fragment are not permitted".to_owned());
    }
    if url
        .path_segments()
        .is_some_and(|mut segments| segments.any(|segment| segment == "." || segment == ".."))
        || url.path().to_ascii_lowercase().contains("%2e")
        || url.path().to_ascii_lowercase().contains("%2f")
        || url.path().to_ascii_lowercase().contains("%5c")
        || url.path().to_ascii_lowercase().contains("%25")
    {
        return Err("URL path traversal or encoded separator".to_owned());
    }
    Ok(())
}

fn raw_redirect_location_is_unsafe(location: &str) -> bool {
    let path = location.split(['?', '#']).next().unwrap_or(location);
    let lower = location.to_ascii_lowercase();
    location.contains('\\')
        || path.split('/').any(|part| part == "." || part == "..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%25")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn test_server<F>(response_count: usize, response_for: F) -> Url
    where
        F: Fn(&str, usize) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let base = format!("http://{address}");
        let response_base = base.clone();
        tokio::spawn(async move {
            for index in 0..response_count {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let response = response_for(&response_base, index);
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Url::parse(&format!("{base}/start")).unwrap()
    }

    #[tokio::test]
    async fn artifact_redirect_loop_is_bounded() {
        let start = test_server(2, |base, _| {
            format!("HTTP/1.1 302 Found\r\nLocation: {base}/artifact\r\nConnection: close\r\n\r\n")
        })
        .await;
        let transport = ReqwestTufTransport::new(1024).unwrap();
        let error = transport.download_bytes(&start, 1024).await.unwrap_err();
        assert!(error.to_string().contains("redirect loop"));
    }

    #[tokio::test]
    async fn artifact_redirect_to_insecure_host_is_rejected() {
        let start = test_server(1, |_, _| {
            "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/artifact\r\nConnection: close\r\n\r\n"
                .to_owned()
        })
        .await;
        let transport = ReqwestTufTransport::new(1024).unwrap();
        let error = transport.download_bytes(&start, 1024).await.unwrap_err();
        assert!(error.to_string().contains("only HTTPS or loopback HTTP"));
    }

    #[tokio::test]
    async fn artifact_redirect_traversal_is_rejected_before_url_join() {
        let start = test_server(1, |_, _| {
            "HTTP/1.1 302 Found\r\nLocation: ../private\r\nConnection: close\r\n\r\n".to_owned()
        })
        .await;
        let transport = ReqwestTufTransport::new(1024).unwrap();
        let error = transport.download_bytes(&start, 1024).await.unwrap_err();
        assert!(error.to_string().contains("traversal"));
    }

    #[tokio::test]
    async fn artifact_body_limit_is_enforced_before_acceptance() {
        let start = test_server(1, |_, _| {
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"
                .to_owned()
        })
        .await;
        let transport = ReqwestTufTransport::new(1024).unwrap();
        let error = transport.download_bytes(&start, 5).await.unwrap_err();
        assert!(error.to_string().contains("body exceeds 5 bytes"));
    }
}
