// Copyright (C) 2023 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pallet AutoID

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
use codec::{Decode, Encode};
use frame_support::dispatch::DispatchResult;
use frame_support::ensure;
use frame_support::traits::Time;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_certificate_registry::x509_certificate_runtime_interface::verify_x509_certificate;
use sp_certificate_registry::{
    DerVec, Validity, X509CertificateVerificationRequest, X509CertificateVerificationResponse,
    X509V3CertificateVerificationData,
};
use sp_core::U256;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Unique AutoId identifier.
pub type Identifier = U256;

/// Root X509 Certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct X509CertificateRoot {
    /// Serial number for this certificate
    pub serial: U256,
    /// Der encoded certificate's subject.
    pub subject: DerVec,
    /// Der encoded certificate's subject's public key info
    pub subject_pki: DerVec,
    /// Validity of the certificate
    pub validity: Validity,
    /// Der encoded full X509 certificate.
    pub raw: DerVec,
    /// A list of all certificate serials issues by the subject.
    /// Serial of root certificate is included as well.
    pub issued_serials: BTreeSet<U256>,
}

/// Leaf X509 certificate issued by a different issuer.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct X509CertificateLeaf {
    /// Issuer identifier of this certificate.
    pub issuer_id: Identifier,
    /// Serial number for this certificate
    pub serial: U256,
    /// Der encoded certificate's subject.
    pub subject: DerVec,
    /// Der encoded certificate's subject's public key info
    pub subject_pki: DerVec,
    /// Validity of the certificate
    pub validity: Validity,
    /// Der encoded full X509 certificate.
    pub raw: DerVec,
}

/// An X509 certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum X509Certificate {
    /// A root X509 certificate.
    Root(X509CertificateRoot),
    /// A leaf certificate issued by a root certificate
    Leaf(X509CertificateLeaf),
}

/// Certificate associated with AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum Certificate {
    X509(X509Certificate),
}

impl Certificate {
    /// Returns the public key info of a given root certificate.
    fn x509_root_issuer_pki(&self) -> Option<DerVec> {
        match self {
            Certificate::X509(cert) => match cert {
                X509Certificate::Root(cert) => Some(cert.subject_pki.clone()),
                X509Certificate::Leaf(_) => None,
            },
        }
    }

    fn issue_x509_certificate_serial<T: Config>(&mut self, serial: U256) -> DispatchResult {
        match self {
            Certificate::X509(cert) => match cert {
                X509Certificate::Root(cert) => {
                    ensure!(
                        !cert.issued_serials.contains(&serial),
                        Error::<T>::CertificateSerialAlreadyIssued
                    );
                    cert.issued_serials.insert(serial);
                    Ok(())
                }
                // leaf cannot issue certs, return invalid
                X509Certificate::Leaf(_) => Err(Error::<T>::IssuerNotRoot.into()),
            },
        }
    }
}

/// A representation of AutoId
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct AutoId {
    /// Unique AutoID identifier.
    pub identifier: Identifier,
    /// Certificate associated with this AutoId.
    pub certificate: Certificate,
}

/// Type holds X509 certificate details used to register an AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum RegisterAutoIdX509 {
    Root {
        certificate: DerVec,
    },
    Leaf {
        issuer_id: Identifier,
        certificate: DerVec,
    },
}

/// Request to register a new AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum RegisterAutoId {
    X509(RegisterAutoIdX509),
}

#[frame_support::pallet]
mod pallet {
    use crate::{AutoId, Identifier};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Time;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Time: Time<Moment = subspace_runtime_primitives::Moment>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the next auto id identifier.
    #[pallet::storage]
    pub(super) type NextAutoIdIdentifier<T> = StorageValue<_, Identifier, ValueQuery>;

    /// Stores the auto id identifier against an AutoId.
    #[pallet::storage]
    pub(super) type AutoIds<T> = StorageMap<_, Identity, Identifier, AutoId, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Issuer auto id does not exist.
        UnknownIssuer,
        /// Issuer is not a root certificate.
        IssuerNotRoot,
        /// Certificate is invalid,
        InvalidCertificate,
        /// Auto Id identifier overflow
        IdentifierOverflow,
        /// Certificate serial already issued.
        CertificateSerialAlreadyIssued,
    }
}

impl<T: Config> Pallet<T> {
    #[allow(dead_code)]
    pub(crate) fn do_register_auto_id(req: RegisterAutoId) -> DispatchResult {
        let block_time = T::Time::now();
        let certificate = match req {
            RegisterAutoId::X509(x509_req) => match x509_req {
                RegisterAutoIdX509::Root { certificate } => {
                    let req = X509CertificateVerificationRequest::V3(
                        X509V3CertificateVerificationData::Issuer {
                            certificate: certificate.clone(),
                            block_time,
                        },
                    );
                    let X509CertificateVerificationResponse {
                        issuer_serial: serial,
                        subject,
                        subject_pki,
                        validity,
                    } = verify_x509_certificate(req).ok_or(Error::<T>::InvalidCertificate)?;

                    Certificate::X509(X509Certificate::Root(X509CertificateRoot {
                        serial,
                        subject,
                        subject_pki,
                        validity,
                        raw: certificate,
                        issued_serials: BTreeSet::from([serial]),
                    }))
                }
                RegisterAutoIdX509::Leaf {
                    issuer_id,
                    certificate,
                } => {
                    let mut issuer_auto_id =
                        AutoIds::<T>::get(issuer_id).ok_or(Error::<T>::UnknownIssuer)?;
                    let issuer_pki = issuer_auto_id
                        .certificate
                        .x509_root_issuer_pki()
                        .ok_or(Error::<T>::IssuerNotRoot)?;
                    // TODO: verify validity of the issuer.
                    let req = X509CertificateVerificationRequest::V3(
                        X509V3CertificateVerificationData::Leaf {
                            certificate: certificate.clone(),
                            issuer_pki,
                            block_time,
                        },
                    );

                    let X509CertificateVerificationResponse {
                        issuer_serial: serial,
                        subject,
                        subject_pki,
                        validity,
                    } = verify_x509_certificate(req).ok_or(Error::<T>::InvalidCertificate)?;

                    issuer_auto_id
                        .certificate
                        .issue_x509_certificate_serial::<T>(serial)?;

                    AutoIds::<T>::insert(issuer_id, issuer_auto_id);

                    Certificate::X509(X509Certificate::Leaf(X509CertificateLeaf {
                        issuer_id,
                        serial,
                        subject,
                        subject_pki,
                        validity,
                        raw: certificate,
                    }))
                }
            },
        };

        let auto_id_identifier = NextAutoIdIdentifier::<T>::get();
        let next_auto_id_identifier = auto_id_identifier
            .checked_add(Identifier::one())
            .ok_or(Error::<T>::IdentifierOverflow)?;
        NextAutoIdIdentifier::<T>::put(next_auto_id_identifier);

        let auto_id = AutoId {
            identifier: auto_id_identifier,
            certificate,
        };

        AutoIds::<T>::insert(auto_id_identifier, auto_id);

        // TODO: emit events
        Ok(())
    }
}
