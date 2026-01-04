use anyhow::Result;
use bytes::Buf;
use http::Request;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls_native_certs::load_native_certs;
use std::net::ToSocketAddrs;
use std::sync::Arc;

async fn try_client(server_name: &str) -> Result<()> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    let mut cert_store = rustls::RootCertStore::empty();

    let certs = load_native_certs().expect("load_native_certs");
    for cert in certs {
        cert_store.add(cert.to_owned())?;
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(cert_store)
        .with_no_client_auth();

    tls.alpn_protocols = vec![b"h3".to_vec()];

    let tls_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))?;

    let mut cfg = ClientConfig::new(Arc::new(tls_cfg));
    cfg.transport_config(Arc::new(TransportConfig::default()));
    endpoint.set_default_client_config(cfg);

    let addr = (server_name, 443).to_socket_addrs()?.next().unwrap();
    let conn = endpoint.connect(addr, server_name)?.await?;

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let req = Request::get(format!("https://{}/", server_name)).body(())?;
    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    println!("Status: {}", resp.status());

    if let Some(mut data) = stream.recv_data().await? {
        let output = data.copy_to_bytes(data.remaining());
        println!("Output from server: {}", String::from_utf8_lossy(&output));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        try_client("quic.nginx.org").await.unwrap();
    }
}
