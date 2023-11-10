// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS client SDK.

use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;

use anyhow::{anyhow, bail, Result};
use as_types::SetPolicyInput;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use kbs_protocol::evidence_provider::NativeEvidenceProvider;
use kbs_protocol::evidence_provider::SvsmEvidenceProvider;
use kbs_protocol::token_provider::TestTokenProvider;
use kbs_protocol::KbsClientBuilder;
use kbs_protocol::KbsClientCapabilities;
use serde::Serialize;
use sev::firmware::host::CertTableEntry;
use sev::firmware::host::CertType;
use tokio::runtime::Runtime;
use uuid::Uuid;

const KBS_URL_PREFIX: &str = "kbs/v0";

/// Attestation and get a result token signed by attestation service
/// Input parameters:
/// - url: KBS server root URL.
/// - [tee_pubkey_pem]: Public key (PEM format) of the RSA key pair generated in TEE.
///     This public key will be contained in attestation results token.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn attestation(
    url: &str,
    tee_key_pem: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<String> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, url);
    if let Some(key) = tee_key_pem {
        client_builder = client_builder.set_tee_key(&key)
    }
    for cert in kbs_root_certs_pem {
        client_builder = client_builder.add_kbs_cert(&cert)
    }
    let mut client = client_builder.build()?;

    let (token, _) = client.get_token().await?;

    Ok(token.content)
}

/// Get secret resources with attestation results token
/// Input parameters:
/// - url: KBS server root URL.
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - tee_key_pem: TEE private key file path (PEM format). This key must consistent with the public key in `token` claims.
/// - token: Attestation Results Token file path.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn get_resource_with_token(
    url: &str,
    path: &str,
    tee_key_pem: String,
    token: String,
    kbs_root_certs_pem: Vec<String>,
) -> Result<Vec<u8>> {
    let token_provider = Box::<TestTokenProvider>::default();
    let mut client_builder =
        KbsClientBuilder::with_token_provider(token_provider, url).set_token(&token);
    client_builder = client_builder.set_tee_key(&tee_key_pem);

    for cert in kbs_root_certs_pem {
        client_builder = client_builder.add_kbs_cert(&cert)
    }
    let mut client = client_builder.build()?;

    let resource_kbs_uri = format!("kbs:///{path}");
    let resource_bytes = client
        .get_resource(serde_json::from_str(&format!("\"{resource_kbs_uri}\""))?)
        .await?;
    Ok(resource_bytes)
}

/// Get secret resources with attestation
/// Input parameters:
/// - url: KBS server root URL.
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - [tee_pubkey_pem]: Public key (PEM format) of the RSA key pair generated in TEE.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn get_resource_with_attestation(
    url: &str,
    path: &str,
    tee_key_pem: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<Vec<u8>> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, url);
    if let Some(key) = tee_key_pem {
        client_builder = client_builder.set_tee_key(&key);
    }

    for cert in kbs_root_certs_pem {
        client_builder = client_builder.add_kbs_cert(&cert)
    }
    let mut client = client_builder.build()?;

    let resource_kbs_uri = format!("kbs:///{path}");
    let resource_bytes = client
        .get_resource(serde_json::from_str(&format!("\"{resource_kbs_uri}\""))?)
        .await?;
    Ok(resource_bytes)
}

/// Set attestation policy
/// Input parameters:
/// - url: KBS server root URL.
/// - auth_key: KBS owner's authenticate private key (PEM string).
/// - policy_bytes: Policy file content in `Vec<u8>`.
/// - [policy_type]: Policy type. Default value is "rego".
/// - [policy_id]: Policy ID. Default value is "default".
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_attestation_policy(
    url: &str,
    auth_key: String,
    policy_bytes: Vec<u8>,
    policy_type: Option<String>,
    policy_id: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let auth_private_key = Ed25519KeyPair::from_pem(&auth_key)?;
    let claims = Claims::create(Duration::from_hours(2));
    let token = auth_private_key.sign(claims)?;

    let http_client = build_http_client(kbs_root_certs_pem)?;

    let set_policy_url = format!("{}/{KBS_URL_PREFIX}/attestation-policy", url);
    let post_input = SetPolicyInput {
        r#type: policy_type.unwrap_or("rego".to_string()),
        policy_id: policy_id.unwrap_or("default".to_string()),
        policy: STANDARD.encode(policy_bytes.clone()),
    };

    let res = http_client
        .post(set_policy_url)
        .header("Content-Type", "application/json")
        .bearer_auth(token.clone())
        .json::<SetPolicyInput>(&post_input)
        .send()
        .await?;

    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

#[derive(Clone, Serialize)]
struct ResourcePolicyData {
    pub policy: String,
}

/// Set resource policy
/// Input parameters:
/// - url: KBS server root URL.
/// - auth_key: KBS owner's authenticate private key (PEM string).
/// - policy_bytes: Policy file content in `Vec<u8>`.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_resource_policy(
    url: &str,
    auth_key: String,
    policy_bytes: Vec<u8>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let auth_private_key = Ed25519KeyPair::from_pem(&auth_key)?;
    let claims = Claims::create(Duration::from_hours(2));
    let token = auth_private_key.sign(claims)?;

    let http_client = build_http_client(kbs_root_certs_pem)?;

    let set_policy_url = format!("{}/{KBS_URL_PREFIX}/resource-policy", url);
    let post_input = ResourcePolicyData {
        policy: STANDARD.encode(policy_bytes.clone()),
    };

    let res = http_client
        .post(set_policy_url)
        .header("Content-Type", "application/json")
        .bearer_auth(token.clone())
        .json::<ResourcePolicyData>(&post_input)
        .send()
        .await?;

    if res.status() != reqwest::StatusCode::OK {
        bail!("Request Failed, Response: {:?}", res.text().await?);
    }
    Ok(())
}

/// Set secret resource to KBS.
/// Input parameters:
/// - url: KBS server root URL.
/// - auth_key: KBS owner's authenticate private key (PEM string).
/// - resource_bytes: Resource data in `Vec<u8>`
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_resource(
    url: &str,
    auth_key: String,
    resource_bytes: Vec<u8>,
    path: &str,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let auth_private_key = Ed25519KeyPair::from_pem(&auth_key)?;
    let claims = Claims::create(Duration::from_hours(2));
    let token = auth_private_key.sign(claims)?;

    let http_client = build_http_client(kbs_root_certs_pem)?;

    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", url, path);
    let res = http_client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(token)
        .body(resource_bytes.clone())
        .send()
        .await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

fn build_http_client(kbs_root_certs_pem: Vec<String>) -> Result<reqwest::Client> {
    let mut client_builder =
        reqwest::Client::builder().user_agent(format!("kbs-client/{}", env!("CARGO_PKG_VERSION")));

    for custom_root_cert in kbs_root_certs_pem.iter() {
        let cert = reqwest::Certificate::from_pem(custom_root_cert.as_bytes())?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    client_builder
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}

#[repr(C, packed)]
pub struct CertBufEntry {
    pub guid: Uuid,
    pub offset: u32,
    pub length: u32,
}

fn parse_cert_buf(certs: *const u8) -> Vec<CertTableEntry> {
    let mut count = 0;
    let entry = certs as *const CertBufEntry;
    let mut certs_vec = Vec::<CertTableEntry>::new();

    unsafe {
        while !(*entry.offset(count)).guid.is_nil() {
            let current_entry = &*entry.offset(count);
            let cert_data = unsafe {
                from_raw_parts(
                    certs.add(current_entry.offset as usize),
                    current_entry.length as usize,
                )
            };
            if (*entry.offset(count)).guid
                == Uuid::parse_str("63da758d-e664-4564-adc5-f4b93be8accd").unwrap()
            {
                certs_vec.push(CertTableEntry::new(CertType::VCEK, cert_data.to_vec()));
            } else if (*entry.offset(count)).guid
                == Uuid::parse_str("4ab7b379-bbac-4fe4-a02f-05aef327c782").unwrap()
            {
                certs_vec.push(CertTableEntry::new(CertType::ASK, cert_data.to_vec()));
            } else if (*entry.offset(count)).guid
                == Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap()
            {
                certs_vec.push(CertTableEntry::new(CertType::ARK, cert_data.to_vec()));
            }
            count += 1;
        }
    }
    certs_vec
}

pub async fn get_svsm_resource(
    url: &str,
    path: &str,
    evidence: *const u8,
    evidence_len: usize,
    tee_key_pem: Option<String>,
    tee_certs: Vec<CertTableEntry>,
) -> Result<Vec<u8>> {
    let evidence_provider = unsafe {
        Box::new(SvsmEvidenceProvider::new(
            evidence,
            evidence_len,
            tee_certs,
        )?)
    };
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, url);
    if let Some(key) = tee_key_pem {
        client_builder = client_builder.set_tee_key(&key);
    }
    let mut client = client_builder.build()?;

    let resource_kbs_uri = format!("kbs:///{path}");
    let resource_bytes = client
        .get_resource(serde_json::from_str(&format!("\"{resource_kbs_uri}\""))?)
        .await?;
    Ok(resource_bytes)
}

///
/// # Safety
/// The caller must ensure the pointers are valid and they contain at least the
/// required amount of memory as specified by the len parameters.
#[no_mangle]
pub unsafe extern "C" fn get_svsm_secret(
    url: *const u8,
    url_len: usize,
    path: *const u8,
    path_len: usize,
    evidence: *const u8,
    evidence_len: usize,
    tee_key: *const u8,
    tee_key_len: usize,
    certs: *const u8,
    certs_len: usize,
    resource_buf: *mut u8,
    resource_buf_len: usize,
) -> usize {
    let url = String::from_utf8(unsafe { from_raw_parts(url, url_len).to_vec() })
        .unwrap_or(String::default());
    let path = String::from_utf8(unsafe { from_raw_parts(path, path_len).to_vec() })
        .unwrap_or(String::default());
    let tee_key = String::from_utf8(unsafe { from_raw_parts(tee_key, tee_key_len).to_vec() })
        .unwrap_or(String::default());

    if url.is_empty() || path.is_empty() || tee_key.is_empty() {
        return 0;
    }

    let runtime = Runtime::new().unwrap();
    let response = runtime.block_on(get_svsm_resource(
        &url,
        &path,
        evidence,
        evidence_len,
        Some(tee_key),
        parse_cert_buf(certs),
    ));

    match response {
        Ok(resource) => {
            if resource_buf_len < resource.len() {
                0
            } else {
                let resource_arr = unsafe { from_raw_parts_mut(resource_buf, resource.len()) };
                resource_arr.clone_from_slice(&resource);
                resource.len()
            }
        }
        Err(e) => {
            println!("Error: {}", e);
            0
        }
    }
}
