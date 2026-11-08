/*
 *
 * Copyright 2025 gRPC authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

use std::{fmt, sync::Arc, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tokio_rustls::{
    TlsAcceptor as RustlsAcceptor,
    rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier},
    server::TlsStream,
};

use crate::transport::{
    Certificate, Identity,
    service::tls::{
        ALPN_H2, TlsError, convert_certificate_to_pki_types, convert_identity_to_pki_types,
    },
};

#[derive(Clone)]
pub(crate) struct TlsAcceptor {
    inner: Arc<ServerConfig>,
    timeout: Option<Duration>,
}

impl TlsAcceptor {
    pub(crate) fn from_rustls(inner: Arc<ServerConfig>, timeout: Option<Duration>) -> Self {
        Self { inner, timeout }
    }

    pub(crate) fn new(
        identity: &Identity,
        client_ca_root: Option<&Certificate>,
        client_auth_optional: bool,
        ignore_client_order: bool,
        use_key_log: bool,
        timeout: Option<Duration>,
    ) -> Result<Self, crate::BoxError> {
        let builder = ServerConfig::builder();

        let builder = match client_ca_root {
            None => builder.with_no_client_auth(),
            Some(cert) => {
                let mut roots = RootCertStore::empty();
                roots.add_parsable_certificates(convert_certificate_to_pki_types(cert)?);
                let verifier = if client_auth_optional {
                    WebPkiClientVerifier::builder(roots.into()).allow_unauthenticated()
                } else {
                    WebPkiClientVerifier::builder(roots.into())
                }
                .build()?;
                builder.with_client_cert_verifier(verifier)
            }
        };

        let (cert, key) = convert_identity_to_pki_types(identity)?;
        let mut config = builder.with_single_cert(cert, key)?;
        config.ignore_client_order = ignore_client_order;

        if use_key_log {
            config.key_log = Arc::new(tokio_rustls::rustls::KeyLogFile::new());
        }

        config.alpn_protocols.push(ALPN_H2.into());
        Ok(Self {
            inner: Arc::new(config),
            timeout,
        })
    }

    pub(crate) async fn accept<IO>(&self, io: IO) -> Result<TlsStream<IO>, crate::BoxError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let acceptor = RustlsAcceptor::from(self.inner.clone());
        let accept_fut = acceptor.accept(io);
        match self.timeout {
            Some(timeout) => time::timeout(timeout, accept_fut)
                .await
                .map_err(|_| TlsError::HandshakeTimeout)?,
            None => accept_fut.await,
        }
        .map_err(Into::into)
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

#[cfg(all(test, feature = "tls-aws-lc"))]
mod preconfigured_tests {
    use super::*;
    use tokio_rustls::rustls::server::ResolvesServerCertUsingSni;

    #[test]
    fn preconfigured_tls_server_retains_the_supplied_arc_and_handshake_timeout() {
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new()));
        config.alpn_protocols = vec![ALPN_H2.to_vec()];
        config.ignore_client_order = true;
        let config = Arc::new(config);
        let timeout = Some(Duration::from_secs(2));
        let acceptor = TlsAcceptor::from_rustls(config.clone(), timeout);
        assert!(Arc::ptr_eq(&acceptor.inner, &config));
        assert!(acceptor.inner.ignore_client_order);
        assert_eq!(acceptor.timeout, timeout);
    }
}
