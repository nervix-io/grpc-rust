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

use std::{fmt, time::Duration};

use super::service::TlsAcceptor;
use crate::transport::tls::{Certificate, Identity};

/// Configures TLS settings for servers.
#[derive(Clone, Default)]
pub struct ServerTlsConfig {
    identity: Option<Identity>,
    rustls_config: Option<std::sync::Arc<tokio_rustls::rustls::ServerConfig>>,
    client_ca_root: Option<Certificate>,
    client_auth_optional: bool,
    ignore_client_order: bool,
    use_key_log: bool,
    timeout: Option<Duration>,
}

impl fmt::Debug for ServerTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTlsConfig").finish()
    }
}

impl ServerTlsConfig {
    /// Creates a new `ServerTlsConfig`.
    pub fn new() -> Self {
        ServerTlsConfig::default()
    }

    /// Supply the complete TLS configuration, including certificates, trust and ALPN.
    ///
    /// This configuration takes precedence over identity, client CA, cipher-order and key-log
    /// builder fields. The handshake timeout still applies. Existing accept scheduling,
    /// error handling and TLS connection information are unchanged.
    pub fn rustls_server_config(
        mut self,
        config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    ) -> Self {
        self.rustls_config = Some(config);
        self
    }

    /// Sets the [`Identity`] of the server.
    pub fn identity(self, identity: Identity) -> Self {
        ServerTlsConfig {
            identity: Some(identity),
            ..self
        }
    }

    /// Sets a certificate against which to validate client TLS certificates.
    pub fn client_ca_root(self, cert: Certificate) -> Self {
        ServerTlsConfig {
            client_ca_root: Some(cert),
            ..self
        }
    }

    /// Sets whether client certificate verification is optional.
    ///
    /// This option has effect only if CA certificate is set.
    ///
    /// # Default
    /// By default, this option is set to `false`.
    pub fn client_auth_optional(self, optional: bool) -> Self {
        ServerTlsConfig {
            client_auth_optional: optional,
            ..self
        }
    }

    /// Sets whether the server's cipher preferences are followed instead of the client's.
    ///
    /// # Default
    /// By default, this option is set to `false`.
    pub fn ignore_client_order(self, ignore_client_order: bool) -> Self {
        ServerTlsConfig {
            ignore_client_order,
            ..self
        }
    }

    /// Use key log as specified by the `SSLKEYLOGFILE` environment variable.
    pub fn use_key_log(self) -> Self {
        ServerTlsConfig {
            use_key_log: true,
            ..self
        }
    }

    /// Sets the timeout for the TLS handshake.
    pub fn timeout(self, timeout: Duration) -> Self {
        ServerTlsConfig {
            timeout: Some(timeout),
            ..self
        }
    }

    pub(crate) fn tls_acceptor(&self) -> Result<TlsAcceptor, crate::BoxError> {
        if let Some(config) = &self.rustls_config {
            return Ok(TlsAcceptor::from_rustls(config.clone(), self.timeout));
        }
        TlsAcceptor::new(
            self.identity.as_ref().unwrap(),
            self.client_ca_root.as_ref(),
            self.client_auth_optional,
            self.ignore_client_order,
            self.use_key_log,
            self.timeout,
        )
    }
}

#[cfg(all(test, feature = "tls-aws-lc"))]
mod preconfigured_tests {
    use super::*;
    use std::sync::Arc;
    use tokio_rustls::rustls::{ServerConfig, server::ResolvesServerCertUsingSni};

    #[test]
    fn preconfigured_tls_server_keeps_the_configuration_without_pem_identity() {
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new()));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let tls = ServerTlsConfig::new().rustls_server_config(Arc::new(config));
        assert!(tls.tls_acceptor().is_ok());
        assert!(tls.clone().tls_acceptor().is_ok());
    }
}
