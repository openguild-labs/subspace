// Copyright (C) 2021 Subspace Labs, Inc.
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

//! Primitives for X509 certificate verification

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
mod host_functions;
mod runtime_interface;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub use crate::runtime_interface::x509_certificate_runtime_interface;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::U256;
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use subspace_runtime_primitives::Moment;

/// X509 Certificate verification request.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum X509CertificateVerificationRequest {
    V3(X509V3CertificateVerificationData),
}

impl PassBy for X509CertificateVerificationRequest {
    type PassBy = pass_by::Codec<Self>;
}

/// DER encoded bytes
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct DerVec(pub Vec<u8>);

impl AsRef<[u8]> for DerVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for DerVec {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum X509V3CertificateVerificationData {
    /// A issuer certificate
    Issuer {
        /// Der encoded X509 certificate.
        certificate: DerVec,
        /// Block time from the runtime.
        block_time: Moment,
    },
    Leaf {
        /// Der encoded X509 certificate.
        certificate: DerVec,
        /// Der encoded PKI of the issuer.
        issuer_pki: DerVec,
        /// Block time from the runtime.
        block_time: Moment,
    },
}

impl X509CertificateVerificationRequest {
    fn destruct(self) -> (DerVec, Option<DerVec>, Moment) {
        match self {
            X509CertificateVerificationRequest::V3(data) => match data {
                X509V3CertificateVerificationData::Issuer {
                    certificate,
                    block_time,
                } => (certificate, None, block_time),
                X509V3CertificateVerificationData::Leaf {
                    certificate,
                    issuer_pki,
                    block_time,
                } => (certificate, Some(issuer_pki), block_time),
            },
        }
    }
}

/// Validity of a given certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Validity {
    /// Not valid before the time since UNIX_EPOCH
    pub not_before: Moment,
    /// Not valid after the time since UNIX_EPOCH
    pub not_after: Moment,
}

impl From<x509_parser::prelude::Validity> for Validity {
    fn from(value: x509_parser::prelude::Validity) -> Self {
        Validity {
            not_before: value.not_before.timestamp() as u64,
            not_after: value.not_after.timestamp() as u64,
        }
    }
}

/// X509 certificate verification response.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct X509CertificateVerificationResponse {
    /// Issuer serial number for this certificate
    pub issuer_serial: U256,
    /// Der encoded certificate's subject.
    pub subject: DerVec,
    /// Der encoded certificate's subject's public key info
    pub subject_pki: DerVec,
    /// Validity of the certificate
    pub validity: Validity,
}
