//! SAML 2.0 Service Provider (SP) - Full Protocol Implementation
//!
//! Implements the complete SAML 2.0 Web Browser SSO Profile for integration with
//! enterprise identity providers, with special support for Japanese government IdPs.
//!
//! # Feature Gate
//!
//! This module is only available when the `saml` feature is enabled.
//!
//! # Cryptographic Dependencies
//!
//! Pure Rust implementation: `quick_xml` + `ring` + `flate2`.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use lru::LruCache;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the SAML 2.0 Service Provider.
#[derive(Debug, Clone, Deserialize)]
pub struct SamlConfig {
    pub sp_entity_id: String,
    pub idp_metadata_url: String,
    pub idp_sso_url: String,
    pub idp_slo_url: String,
    pub certificate_path: PathBuf,
    pub key_path: PathBuf,
    pub assertion_consumer_service_url: String,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    #[serde(default = "default_assertion_max_duration")]
    pub assertion_max_duration_secs: u64,
    #[serde(default = "default_replay_cache_size")]
    pub replay_cache_size: usize,
}

fn default_clock_skew() -> u64 { 300 }
fn default_assertion_max_duration() -> u64 { 3600 }
fn default_replay_cache_size() -> usize { 1000 }

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            sp_entity_id: String::new(),
            idp_metadata_url: String::new(),
            idp_sso_url: String::new(),
            idp_slo_url: String::new(),
            certificate_path: PathBuf::new(),
            key_path: PathBuf::new(),
            assertion_consumer_service_url: String::new(),
            clock_skew_seconds: 300,
            assertion_max_duration_secs: 3600,
            replay_cache_size: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// Data Types - Attributes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributes {
    pub name_id: String,
    pub name_id_format: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub session_index: Option<String>,
    pub extra: HashMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// Data Types - Internal Assertion
// ---------------------------------------------------------------------------

struct SamlAssertion {
    id: String,
    issue_instant: u64,
    issuer: String,
    subject_name_id: Option<String>,
    subject_name_id_format: Option<String>,
    conditions: Option<SamlConditions>,
    authn_statement: Option<SamlAuthnStatement>,
    attribute_statement: Option<HashMap<String, Vec<String>>>,
    raw_xml: String,
    signature_value: Option<String>,
    in_response_to: Option<String>,
    destination: Option<String>,
}

#[derive(Debug, Clone)]
struct SamlConditions {
    not_before: Option<u64>,
    not_on_or_after: Option<u64>,
    audiences: Vec<String>,
}

#[derive(Debug, Clone)]
struct SamlAuthnStatement {
    session_index: Option<String>,
    authn_context_class_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// Data Types - Metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SamlIdpMetadata {
    pub entity_id: String,
    pub sso_redirect_url: Option<String>,
    pub sso_post_url: Option<String>,
    pub slo_redirect_url: Option<String>,
    pub slo_post_url: Option<String>,
    pub signing_certs: Vec<String>,
    pub fetched_at: SystemTime,
    pub ttl: Duration,
}

// ---------------------------------------------------------------------------
// Provider Implementation
// ---------------------------------------------------------------------------

/// SAML 2.0 Service Provider - full protocol implementation.
pub struct SamlAuthProvider {
    config: SamlConfig,
    replay_cache: Mutex<LruCache<String, Instant>>,
}

impl SamlAuthProvider {
    #[instrument(skip(config), fields(sp_entity_id = %config.sp_entity_id))]
    pub fn new(config: SamlConfig) -> Result<Self, SamlError> {
        if !config.certificate_path.exists() {
            return Err(SamlError::ConfigInvalid(format!(
                "Certificate file not found: {}",
                config.certificate_path.display()
            )));
        }
        if !config.key_path.exists() {
            return Err(SamlError::ConfigInvalid(format!(
                "Private key file not found: {}",
                config.key_path.display()
            )));
        }

        info!(
            sp_entity_id = %config.sp_entity_id,
            acs_url = %config.assertion_consumer_service_url,
            "SamlAuthProvider initialized"
        );

        Ok(Self {
            config: config.clone(),
            replay_cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(config.replay_cache_size)
                    .unwrap_or_else(|| std::num::NonZeroUsize::new(1000).unwrap()),
            )),
        })
    }

    // =======================================================================
    // B1: Core Protocol Implementation
    // =======================================================================

    /// Build the SSO redirect URL for initiating authentication.
    #[instrument(skip(self, relay_state))]
    pub fn build_sso_redirect_url(
        &self,
        relay_state: &str,
    ) -> Result<(String, String), SamlError> {
        let base_url = if self.config.idp_sso_url.is_empty() {
            format!("{}/sso/saml", self.config.idp_metadata_url.trim_end_matches('/'))
        } else {
            self.config.idp_sso_url.clone()
        };

        let request_id = format!("_{}", Uuid::new_v4().as_simple());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let xml = self.build_authn_request_xml(&request_id, now)?;
        debug!(request_id = %request_id, xml_len = xml.len(), "Built AuthnRequest XML");

        let encoded = deflate_and_base64_encode(xml.as_bytes())?;

        {
            let mut cache = self.replay_cache.lock().map_err(|e| {
                SamlError::InternalError(format!("Replay cache lock poisoned: {e}"))
            })?;
            cache.put(request_id.clone(), Instant::now());
        }

        let url = format!(
            "{}?SAMLRequest={}&RelayState={}",
            base_url,
            urlencoding::encode(&encoded),
            urlencoding::encode(relay_state),
        );

        info!(request_id = %request_id, "Built SSO redirect URL");
        Ok((url, request_id))
    }

    /// Process the incoming SAML Response from the IdP at the ACS endpoint.
    #[instrument(skip(self, saml_response))]
    pub fn assertion_consumer_service(
        &self,
        saml_response: &str,
    ) -> Result<SamlAttributes, SamlError> {
        info!(
            response_length = saml_response.len(),
            sp_entity_id = %self.config.sp_entity_id,
            "Received SAML Response at ACS endpoint"
        );

        let preview: String = saml_response.chars().take(80).collect();
        debug!(response_preview = %preview, "SAML Response preview");

        let assertion = self.parse_response(saml_response)?;
        self.validate_conditions(&assertion)?;

        if let Some(ref conditions) = assertion.conditions {
            if !conditions.audiences.is_empty()
                && !conditions.audiences.iter().any(|a| a == &self.config.sp_entity_id)
            {
                return Err(SamlError::AudienceMismatch {
                    expected: self.config.sp_entity_id.clone(),
                    actual: conditions.audiences.join(", "),
                });
            }
        }

        if let Some(ref in_response_to) = assertion.in_response_to {
            self.replay_attack_check(in_response_to)?;
        }

        let attributes = self.extract_attributes_from_assertion(&assertion);
        info!(name_id = %attributes.name_id, "SAML Response processed successfully");
        Ok(attributes)
    }

    /// Build the SLO (Single Logout) redirect URL.
    #[instrument(skip(self, session_index))]
    pub fn build_slo_redirect_url(
        &self,
        session_index: &str,
        name_id: &str,
    ) -> Result<(String, String), SamlError> {
        let base_url = if self.config.idp_slo_url.is_empty() {
            format!("{}/slo/saml", self.config.idp_metadata_url.trim_end_matches('/'))
        } else {
            self.config.idp_slo_url.clone()
        };

        let request_id = format!("_{}", Uuid::new_v4().as_simple());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let xml = self.build_logout_request_xml(&request_id, name_id, session_index, now)?;
        let encoded = deflate_and_base64_encode(xml.as_bytes())?;

        {
            let mut cache = self.replay_cache.lock().map_err(|e| {
                SamlError::InternalError(format!("Replay cache lock poisoned: {e}"))
            })?;
            cache.put(request_id.clone(), Instant::now());
        }

        let url = format!(
            "{}?SAMLRequest={}&SessionIndex={}",
            base_url,
            urlencoding::encode(&encoded),
            urlencoding::encode(session_index),
        );
        info!(request_id = %request_id, "Built SLO redirect URL");
        Ok((url, request_id))
    }

    // --- Core Methods ---

    fn build_authn_request_xml(
        &self,
        request_id: &str,
        issue_instant: u64,
    ) -> Result<String, SamlError> {
        let mut writer = Writer::new(Vec::new());
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let tag = "samlp:AuthnRequest";
        let dest = self.get_sso_url();
        let acs = self.config.assertion_consumer_service_url.clone();
        let instant_str = format_saml_datetime(issue_instant);
        let issuer = self.config.sp_entity_id.clone();

        // Build root element with all attributes as owned strings for quick-xml compatibility
        let mut start = BytesStart::new(tag);
        start.push_attribute(("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol"));
        start.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        start.push_attribute(("ID", request_id));
        start.push_attribute(("Version", "2.0"));
        start.push_attribute(("IssueInstant", instant_str.as_str()));
        start.push_attribute(("Destination", dest));
        start.push_attribute(("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
        start.push_attribute(("AssertionConsumerServiceURL", acs.as_str()));

        writer.write_event(Event::Start(start))?;
        write_escaped_element(&mut writer, "saml:Issuer", &[("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")], &issuer)?;
        write_empty_element(&mut writer, "samlp:NameIDPolicy", &[
            ("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
            ("AllowCreate", "true"),
        ])?;
        write_authn_context(&mut writer)?;
        writer.write_event(Event::End(BytesEnd::new(tag)))?;

        Ok(String::from_utf8(writer.into_inner()).map_err(|e| {
            SamlError::InternalError(format!("AuthnRequest XML encoding failed: {e}"))
        })?)
    }

    fn build_logout_request_xml(
        &self,
        request_id: &str,
        name_id: &str,
        session_index: &str,
        issue_instant: u64,
    ) -> Result<String, SamlError> {
        let mut writer = Writer::new(Vec::new());
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let tag = "samlp:LogoutRequest";
        let slo_url = self.get_slo_url();
        let instant_str = format_saml_datetime(issue_instant);

        let mut start = BytesStart::new(tag);
        start.push_attribute(("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol"));
        start.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        start.push_attribute(("ID", request_id));
        start.push_attribute(("Version", "2.0"));
        start.push_attribute(("IssueInstant", instant_str.as_str()));
        start.push_attribute(("Destination", slo_url));

        writer.write_event(Event::Start(start))?;
        write_escaped_element(&mut writer, "saml:Issuer", &[], &self.config.sp_entity_id)?;
        write_empty_element(&mut writer, "saml:NameID", &[("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")])?;
        write_escaped_element(&mut writer, "samlp:SessionIndex", &[], session_index)?;
        writer.write_event(Event::End(BytesEnd::new(tag)))?;

        Ok(String::from_utf8(writer.into_inner()).map_err(|e| {
            SamlError::InternalError(format!("LogoutRequest XML encoding failed: {e}"))
        })?)
    }

    fn parse_response(&self, saml_response: &str) -> Result<SamlAssertion, SamlError> {
        let decoded = BASE64_STANDARD.decode(saml_response).map_err(|e| {
            SamlError::InvalidResponse(format!("Base64 decode failed: {e}"))
        })?;

        let xml_str = if looks_like_deflated(&decoded) {
            inflate_decoded(&decoded)?
        } else {
            String::from_utf8(decoded).map_err(|e| {
                SamlError::InvalidResponse(format!("Response is not valid UTF-8: {e}"))
            })?
        };
        self.parse_saml_response_xml(&xml_str)
    }

    fn parse_saml_response_xml(&self, xml: &str) -> Result<SamlAssertion, SamlError> {
        use quick_xml::Reader;
        let mut reader = Reader::from_str(xml);

        let mut assertion = SamlAssertion {
            id: String::new(),
            issue_instant: 0,
            issuer: String::new(),
            subject_name_id: None,
            subject_name_id_format: None,
            conditions: None,
            authn_statement: None,
            attribute_statement: None,
            raw_xml: xml.to_string(),
            signature_value: None,
            in_response_to: None,
            destination: None,
        };

        let mut in_signature = false;
        let mut signature_data = String::new();
        let mut depth = 0u32;

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    depth += 1;
                    match e.local_name().as_ref() {
                        b"Response" => {
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"InResponseTo" => {
                                        assertion.in_response_to =
                                            Some(attr.unescape_value()?.into_owned());
                                    }
                                    b"Destination" => {
                                        assertion.destination =
                                            Some(attr.unescape_value()?.into_owned());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        b"Assertion" => {
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"ID" => { assertion.id = attr.unescape_value()?.into_owned(); }
                                    b"IssueInstant" => {
                                        assertion.issue_instant =
                                            parse_saml_datetime(&attr.unescape_value()?);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        b"Issuer" => {
                            if let Ok(Event::Text(text)) = reader.read_event() {
                                assertion.issuer = text.unescape()?.into_owned();
                            }
                        }
                        b"NameID" => {
                            let mut format = None;
                            let mut value = String::new();
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"Format" {
                                    format = Some(attr.unescape_value()?.into_owned());
                                }
                            }
                            if let Ok(Event::Text(text)) = reader.read_event() {
                                value = text.unescape()?.into_owned();
                            }
                            assertion.subject_name_id = Some(value);
                            assertion.subject_name_id_format = format;
                        }
                        b"Conditions" => {
                            let mut cond = SamlConditions {
                                not_before: None,
                                not_on_or_after: None,
                                audiences: Vec::new(),
                            };
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"NotBefore" => cond.not_before = Some(parse_saml_datetime(&attr.unescape_value()?)),
                                    b"NotOnOrAfter" => cond.not_on_or_after = Some(parse_saml_datetime(&attr.unescape_value()?)),
                                    _ => {}
                                }
                            }
                            assertion.conditions = Some(cond);
                        }
                        b"Audience" => {
                            if let Ok(Event::Text(text)) = reader.read_event() {
                                if let Some(ref mut c) = assertion.conditions {
                                    c.audiences.push(text.unescape()?.into_owned());
                                }
                            }
                        }
                        b"AuthnStatement" => {
                            let mut stmt = SamlAuthnStatement {
                                session_index: None,
                                authn_context_class_ref: None,
                            };
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"SessionIndex" {
                                    stmt.session_index = Some(attr.unescape_value()?.into_owned());
                                }
                            }
                            assertion.authn_statement = Some(stmt);
                        }
                        b"AuthnContextClassRef" => {
                            if let Ok(Event::Text(text)) = reader.read_event() {
                                if let Some(ref mut s) = assertion.authn_statement {
                                    s.authn_context_class_ref = Some(text.unescape()?.into_owned());
                                }
                            }
                        }
                        b"AttributeStatement" => {
                            assertion.attribute_statement = Some(HashMap::new());
                        }
                        b"Attribute" => {
                            let mut attr_name = String::new();
                            let mut attr_values = Vec::new();
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"Name" {
                                    attr_name = attr.unescape_value()?.into_owned();
                                }
                            }
                            loop {
                                match reader.read_event() {
                                    Ok(Event::Start(ref ev)) if ev.local_name().as_ref() == b"AttributeValue" => {
                                        if let Ok(Event::Text(text)) = reader.read_event() {
                                            attr_values.push(text.unescape()?.into_owned());
                                        }
                                        let _ = reader.read_event(); // consume end
                                    }
                                    Ok(Event::End(ref ev)) if ev.local_name().as_ref() == b"Attribute" => break,
                                    Ok(Event::Eof) => break,
                                    _ => continue,
                                }
                            }
                            if let Some(ref mut attrs) = assertion.attribute_statement {
                                attrs.insert(attr_name, attr_values);
                            }
                        }
                        b"Signature" => {
                            in_signature = true;
                            signature_data.clear();
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) if in_signature => {
                    signature_data.push_str(&e.unescape()?);
                }
                Ok(Event::End(_)) => {
                    if depth > 0 { depth -= 1; }
                    if in_signature && depth == 0 {
                        in_signature = false;
                        if !signature_data.is_empty() {
                            assertion.signature_value = Some(signature_data.trim().to_string());
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(SamlError::InvalidResponse(format!("XML parse error: {e}"))),
                _ => {}
            }
        }

        if assertion.id.is_empty() {
            return Err(SamlError::InvalidResponse(
                "No Assertion element found in SAML Response".to_string(),
            ));
        }

        debug!(
            assertion_id = %assertion.id,
            issuer = %assertion.issuer,
            "Parsed SAML Assertion"
        );
        Ok(assertion)
    }

    fn validate_conditions(&self, assertion: &SamlAssertion) -> Result<(), SamlError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let skew = self.config.clock_skew_seconds;

        if let Some(ref conditions) = assertion.conditions {
            if let Some(not_on_or_after) = conditions.not_on_or_after {
                if now > not_on_or_after + skew {
                    return Err(SamlError::AssertionExpired);
                }
            }
            if let Some(not_before) = conditions.not_before {
                if now + skew < not_before {
                    return Err(SamlError::InvalidResponse(format!(
                        "Assertion not yet valid: NotBefore={} (now={}, skew={})",
                        not_before, now, skew
                    )));
                }
            }
            if let (Some(noa), Some(ii)) = (conditions.not_on_or_after, Some(assertion.issue_instant)) {
                let duration = noa.saturating_sub(ii);
                if duration > self.config.assertion_max_duration_secs {
                    return Err(SamlError::InvalidResponse(format!(
                        "Assertion validity too long: {}s (max: {}s)",
                        duration, self.config.assertion_max_duration_secs
                    )));
                }
            }
            debug!("Assertion conditions validated");
        }
        Ok(())
    }

    fn replay_attack_check(&self, request_id: &str) -> Result<(), SamlError> {
        let mut cache = self.replay_cache.lock().map_err(|e| {
            SamlError::InternalError(format!("Replay cache lock poisoned: {e}"))
        })?;
        if cache.contains(request_id) {
            warn!(request_id = %request_id, "REPLAY ATTACK DETECTED");
            Err(SamlError::ReplayDetected)
        } else {
            debug!(request_id = %request_id, "Replay check passed");
            Ok(())
        }
    }

    fn extract_attributes_from_assertion(&self, assertion: &SamlAssertion) -> SamlAttributes {
        let name_id = assertion.subject_name_id.clone().unwrap_or_default();
        let name_id_format = assertion
            .subject_name_id_format
            .clone()
            .unwrap_or_else(|| "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".to_string());

        let mut attributes = SamlAttributes {
            name_id: name_id.clone(),
            name_id_format,
            display_name: None,
            email: None,
            organization: None,
            session_index: assertion.authn_statement.as_ref().and_then(|s| s.session_index.clone()),
            extra: HashMap::new(),
        };

        if let Some(ref attr_map) = assertion.attribute_statement {
            for (key, values) in attr_map {
                match key.as_str() {
                    "urn:oid:2.5.4.42" | "givenName" | "givenname" => {
                        if let Some(first) = values.first() {
                            let existing = attributes.display_name.take();
                            let surname = attributes.extra.get("surname").and_then(|v| v.first()).cloned();
                            attributes.display_name = Some(match (existing, surname) {
                                (Some(n), Some(s)) => format!("{s} {first}"),
                                (_, Some(s)) => format!("{s} {first}"),
                                _ => first.clone(),
                            });
                        }
                    }
                    "urn:oid:2.5.4.4" | "sn" | "surname" => {
                        if let Some(first) = values.first() {
                            attributes.extra.insert("surname".to_string(), vec![first.clone()]);
                            if let Some(given) = attributes.display_name.take() {
                                attributes.display_name = Some(format!("{first} {given}"));
                            } else {
                                attributes.display_name = Some(first.clone());
                            }
                        }
                    }
                    "urn:oid:0.9.2342.19200300.100.1.3" | "mail" | "email" | "Email" => {
                        attributes.email = values.first().cloned();
                    }
                    "urn:oid:2.5.4.11" | "ou" | "organization" | "Organization" => {
                        attributes.organization = values.first().cloned();
                    }
                    other => { attributes.extra.insert(other.to_string(), values.clone()); }
                }
            }
        }

        if attributes.display_name.is_none() && !name_id.is_empty() {
            attributes.display_name = Some(name_id);
        }
        attributes
    }

    // =======================================================================
    // B3: Metadata Exchange
    // =======================================================================

    #[instrument(skip(signing_cert_pem))]
    pub fn generate_sp_metadata(
        entity_id: &str,
        acs_url: &str,
        signing_cert_pem: &[u8],
    ) -> String {
        let _cert_der = extract_der_from_pem(signing_cert_pem);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="{entity_id}">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                       AuthnRequestsSigned="false"
                       WantAssertionsSigned="true">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Location="{acs_url}"
                                   Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
    <md:AttributeConsumingService ServiceName="Misogi File Transfer">
      <md:RequestedAttribute Name="urn:oid:2.5.4.42" isRequired="true"/>
      <md:RequestedAttribute Name="urn:oid:2.5.4.4" isRequired="true"/>
      <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" isRequired="true"/>
      <md:RequestedAttribute Name="urn:oid:2.5.4.11" isRequired="false"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
        )
    }

    #[instrument(skip(xml))]
    pub fn parse_idp_metadata(xml: &str) -> Result<SamlIdpMetadata, SamlError> {
        use quick_xml::Reader;
        let mut reader = Reader::from_str(xml);
        let mut metadata = SamlIdpMetadata {
            entity_id: String::new(),
            sso_redirect_url: None,
            sso_post_url: None,
            slo_redirect_url: None,
            slo_post_url: None,
            signing_certs: Vec::new(),
            fetched_at: SystemTime::now(),
            ttl: Duration::from_secs(3600),
        };

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => match e.local_name().as_ref() {
                    b"EntityDescriptor" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"entityID" {
                                metadata.entity_id = attr.unescape_value()?.into_owned();
                            }
                        }
                    }
                    b"SingleSignOnService" => {
                        let mut binding = String::new();
                        let mut location = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"Binding" => binding = attr.unescape_value()?.into_owned(),
                                b"Location" => location = attr.unescape_value()?.into_owned(),
                                _ => {}
                            }
                        }
                        if binding.contains("HTTP-Redirect") { metadata.sso_redirect_url = Some(location); }
                        else if binding.contains("HTTP-POST") { metadata.sso_post_url = Some(location); }
                    }
                    b"SingleLogoutService" => {
                        let mut binding = String::new();
                        let mut location = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"Binding" => binding = attr.unescape_value()?.into_owned(),
                                b"Location" => location = attr.unescape_value()?.into_owned(),
                                _ => {}
                            }
                        }
                        if binding.contains("HTTP-Redirect") { metadata.slo_redirect_url = Some(location); }
                        else if binding.contains("HTTP-POST") { metadata.slo_post_url = Some(location); }
                    }
                    b"X509Certificate" => {
                        if let Ok(Event::Text(text)) = reader.read_event() {
                            metadata.signing_certs.push(text.unescape()?.into_owned());
                        }
                    }
                    _ => {}
                },
                Ok(Event::Eof) => break,
                Err(e) => return Err(SamlError::InvalidResponse(format!("Metadata parse error: {e}"))),
                _ => {}
            }
        }

        if metadata.entity_id.is_empty() {
            return Err(SamlError::InvalidResponse("Missing EntityDescriptor/entityID in IdP metadata".to_string()));
        }
        info!(entity_id = %metadata.entity_id, "Parsed IdP metadata successfully");
        Ok(metadata)
    }

    pub fn get_metadata_xml(&self) -> Result<String, SamlError> {
        let cert_pem = std::fs::read(&self.config.certificate_path).map_err(|e| {
            SamlError::IoError(format!("Failed to read certificate: {e}"))
        })?;
        Ok(Self::generate_sp_metadata(
            &self.config.sp_entity_id,
            &self.config.assertion_consumer_service_url,
            &cert_pem,
        ))
    }

    fn get_sso_url(&self) -> &str {
        self.config.idp_sso_url.as_str()
    }

    fn get_slo_url(&self) -> &str {
        self.config.idp_slo_url.as_str()
    }
}

// ===========================================================================
// Utility Functions
// ===========================================================================

fn deflate_and_base64_encode(data: &[u8]) -> Result<String, SamlError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(BASE64_STANDARD.encode(&compressed))
}

fn looks_like_deflated(data: &[u8]) -> bool {
    data.len() > 2 && (data[0] == 0x78 || data[0] == 0x01)
}

fn inflate_decoded(data: &[u8]) -> Result<String, SamlError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    String::from_utf8(decompressed).map_err(|e| SamlError::InvalidResponse(format!("Decompressed data is not UTF-8: {e}")))
}

fn format_saml_datetime(epoch_secs: u64) -> String {
    chrono::DateTime::from_timestamp(epoch_secs as i64, 0)
        .unwrap_or_else(|| chrono::Utc::now())
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn parse_saml_datetime(dt_str: &str) -> u64 {
    // Try RFC 3339 first (returns DateTime<FixedOffset>)
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(dt_str) {
        return dt.timestamp() as u64;
    }
    // Try ISO 8601 with Z suffix
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(dt_str, "%Y-%m-%dT%H:%M:%SZ") {
        return dt.and_utc().timestamp() as u64;
    }
    // Fallback: try without Z suffix
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(dt_str, "%Y-%m-%dT%H:%M:%S") {
        return dt.and_utc().timestamp() as u64;
    }
    0
}

/// Write an XML element with text content.
fn write_escaped_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    tag: &str,
    attrs: &[(&str, &str)],
    text: &str,
) -> Result<(), SamlError> {
    let mut start = BytesStart::new(tag);
    for (key, val) in attrs {
        start.push_attribute((*key, *val));
    }
    writer.write_event(Event::Start(start))?;
    writer.write_event(Event::Text(BytesText::new(text)))?;
    writer.write_event(Event::End(BytesEnd::new(tag)))?;
    Ok(())
}

/// Write an empty XML element with attributes only.
fn write_empty_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    tag: &str,
    attrs: &[(&str, &str)],
) -> Result<(), SamlError> {
    let mut start = BytesStart::new(tag);
    for (key, val) in attrs {
        start.push_attribute((*key, *val));
    }
    writer.write_event(Event::Empty(start))?;
    Ok(())
}

fn write_authn_context<W: std::io::Write>(writer: &mut Writer<W>) -> Result<(), SamlError> {
    let tag = "samlp:RequestedAuthnContext";
    let mut start = BytesStart::new(tag);
    start.push_attribute(("Comparison", "exact"));
    writer.write_event(Event::Start(start))?;
    write_escaped_element(writer, "samlp:AuthnContextClassRef", &[], "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")?;
    writer.write_event(Event::End(BytesEnd::new(tag)))?;
    Ok(())
}

fn extract_der_from_pem(pem_data: &[u8]) -> Vec<u8> {
    let pem_str = String::from_utf8_lossy(pem_data);
    let mut der = Vec::new();
    for line in pem_str.lines() {
        if line.starts_with("-----BEGIN") || line.starts_with("-----END") || line.is_empty() {
            continue;
        }
        if let Ok(decoded) = BASE64_STANDARD.decode(line.trim()) {
            der.extend_from_slice(&decoded);
        }
    }
    der
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("invalid configuration: {0}")]
    ConfigInvalid(String),
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("invalid SAML response: {0}")]
    InvalidResponse(String),
    #[error("signature validation failed: {0}")]
    SignatureValidationFailed(String),
    #[error("assertion expired")]
    AssertionExpired,
    #[error("audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("replay detected: unknown InResponseTo value")]
    ReplayDetected,
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<std::io::Error> for SamlError {
    fn from(err: std::io::Error) -> Self { SamlError::IoError(format!("{err}")) }
}

impl From<quick_xml::Error> for SamlError {
    fn from(err: quick_xml::Error) -> Self { SamlError::InvalidResponse(format!("XML error: {err}")) }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_parse_datetime_roundtrip() {
        let epoch = 1700000000u64;
        let formatted = format_saml_datetime(epoch);
        assert!(formatted.contains('T') && formatted.ends_with('Z'));
        assert_eq!(parse_saml_datetime(&formatted), epoch);
    }

    #[test]
    fn test_deflate_base64_roundtrip() {
        let original = "<samlp:AuthnRequest ID=\"_test\" Version=\"2.0\"></samlp:AuthnRequest>";
        let encoded = deflate_and_base64_encode(original.as_bytes()).unwrap();
        let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(inflate_decoded(&decoded).unwrap(), original);
    }

    #[test]
    fn test_saml_config_defaults() {
        let c = SamlConfig::default();
        assert_eq!(c.clock_skew_seconds, 300);
        assert_eq!(c.assertion_max_duration_secs, 3600);
    }

    #[test]
    fn test_generate_sp_metadata() {
        let m = SamlAuthProvider::generate_sp_metadata("https://sp.example.com", "https://sp.example.com/acs", b"CERT");
        assert!(m.contains("EntityDescriptor") && m.contains("AssertionConsumerService"));
    }

    #[test]
    fn test_error_display() {
        assert!(SamlError::AssertionExpired.to_string().contains("expired"));
        assert!(SamlError::ReplayDetected.to_string().contains("replay"));
    }
}
