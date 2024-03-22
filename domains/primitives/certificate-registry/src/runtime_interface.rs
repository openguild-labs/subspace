#[cfg(feature = "std")]
use crate::host_functions::HostFunctionExtension;
use crate::{X509CertificateVerificationRequest, X509CertificateVerificationResponse};
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime_interface::runtime_interface;

/// Certificate registry runtime interfaces for X509 certificate.
#[runtime_interface]
pub trait X509CertificateRuntimeInterface {
    fn verify_x509_certificate(
        &mut self,
        req: X509CertificateVerificationRequest,
    ) -> Option<X509CertificateVerificationResponse> {
        self.extension::<HostFunctionExtension>()
            .expect(
                "No `CertificateRegistryHostFunctionExtension` associated for the current context!",
            )
            .verify_x509_certificate(req)
    }
}
