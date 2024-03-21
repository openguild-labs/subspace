use crate::{Validity, X509CertificateVerificationRequest, X509CertificateVerificationResponse};
use sp_core::U256;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};

/// Host function trait for Certificate registration
pub trait HostFunctions: Send + Sync {
    fn verify_x509_certificate(
        &self,
        req: X509CertificateVerificationRequest,
    ) -> Option<X509CertificateVerificationResponse>;
}

sp_externalities::decl_extension! {
    pub struct HostFunctionExtension(Arc<dyn HostFunctions>);
}

impl HostFunctionExtension {
    /// Create a new instance of [`HostFunctionExtension`].
    #[allow(dead_code)]
    pub fn new(inner: Arc<dyn HostFunctions>) -> Self {
        Self(inner)
    }
}

/// Implementation of host functions for Certificate registry.
#[derive(Default)]
pub struct HostFunctionsImpl;

impl HostFunctions for HostFunctionsImpl {
    fn verify_x509_certificate(
        &self,
        req: X509CertificateVerificationRequest,
    ) -> Option<X509CertificateVerificationResponse> {
        let (cert_bytes, maybe_issuer_pki, block_time) = req.destruct();
        let (_, cert) = X509Certificate::from_der(cert_bytes.as_ref()).ok()?;
        if let Some(encoded_issuer_pki) = maybe_issuer_pki {
            let (_, pki) = SubjectPublicKeyInfo::from_der(encoded_issuer_pki.as_ref()).ok()?;
            // verify the certificate signature using issuer pki
            cert.verify_signature(Some(&pki)).ok()?
        } else {
            // verify signature using subject pki as an issuer
            cert.verify_signature(None).ok()?;
        };

        // block time is in milliseconds since unix epoch
        let block_time = OffsetDateTime::from(UNIX_EPOCH + Duration::from_millis(block_time));

        // check certificate validity
        cert.validity()
            .is_valid_at(block_time.into())
            .then_some(())?;

        Some(X509CertificateVerificationResponse {
            issuer_serial: U256::from_big_endian(&cert.serial.to_bytes_be()),
            subject: cert.subject.as_raw().to_vec().into(),
            subject_pki: cert.subject_pki.raw.to_vec().into(),
            validity: Validity::from(cert.validity().clone()),
        })
    }
}
