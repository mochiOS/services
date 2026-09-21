//! Read-only OS update check. No payload is downloaded until an atomic,
//! rollback-capable system/data layout is deployed.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mochios_http_client::HttpsUrl;
use serde_json::Value;
use crate::payload::decode_sha256_hex;
use crate::public_api::Response;

/// Developer CA roots are deliberately not release-manifest trust anchors.
/// Release keys are embedded at build time; rotations must ship both old and
/// new keys before the signing key changes.
pub use crate::RELEASE_PUBLIC_KEYS as TRUSTED_RELEASE_KEYS;

#[derive(Clone, Copy)]
pub struct TrustedKey {
    pub key_id: &'static str,
    pub public_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub year: u32,
    pub major: u32,
    pub minor: u32,
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.');
        let parse = |part: &str| {
            (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| part.parse::<u32>().ok()).flatten()
        };
        let year = parse(parts.next()?)?;
        let major = parse(parts.next()?)?;
        let minor = match parts.next() { Some(part) => parse(part)?, None => 0 };
        parts.next().is_none().then_some(Self { year, major, minor })
    }
}

/// Only this module can construct an offer. Possession means the exact
/// manifest fields were checked against an embedded release key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    release_id: String,
    version: String,
    build_number: u64,
    channel: String,
    architecture: String,
    url: String,
    sha256: [u8; 32],
    size_bytes: u64,
    filename: String,
    key_id: String,
}

impl VerifiedManifest {
    pub fn release_id(&self) -> &str { &self.release_id }
    pub fn version(&self) -> &str { &self.version }
    pub const fn build_number(&self) -> u64 { self.build_number }
    pub fn channel(&self) -> &str { &self.channel }
    pub fn architecture(&self) -> &str { &self.architecture }
    pub fn url(&self) -> &str { &self.url }
    pub const fn sha256(&self) -> &[u8; 32] { &self.sha256 }
    pub const fn size_bytes(&self) -> u64 { self.size_bytes }
    pub fn filename(&self) -> &str { &self.filename }
    pub fn key_id(&self) -> &str { &self.key_id }

    #[cfg(test)]
    pub(crate) fn fixture(version: &str, build_number: u64, bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            release_id: "test-release".to_owned(),
            version: version.to_owned(),
            build_number,
            channel: "developer_preview".to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            url: "https://storage.mochios.org/test.moupdate".to_owned(),
            sha256: Sha256::digest(bytes).into(),
            size_bytes: bytes.len() as u64,
            filename: "test.moupdate".to_owned(),
            key_id: "test".to_owned(),
        }
    }
}

impl core::fmt::Debug for VerifiedManifest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedManifest")
            .field("release_id", &self.release_id)
            .field("version", &self.version)
            .field("build_number", &self.build_number)
            .field("channel", &self.channel)
            .field("architecture", &self.architecture)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    NoUpdate,
    DistributionStopped,
    UnknownBuild,
    Available(VerifiedManifest),
}

impl CheckStatus {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NoUpdate => "no_update",
            Self::DistributionStopped => "distribution_stopped",
            Self::UnknownBuild => "unknown_build",
            Self::Available(_) => "available",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckError {
    InvalidJson,
    InvalidStatus,
    InvalidMetadata,
    WrongArchitecture,
    UntrustedKey,
    InvalidSignature,
    RateLimited(u64),
    ServiceUnavailable,
    HttpStatus(u16),
}

pub fn check_http_response(
    response: &Response,
    architecture: &str,
    keys: &[TrustedKey],
) -> Result<CheckStatus, CheckError> {
    match response.status {
        200 => check_response(&response.body, architecture, keys),
        429 => Err(CheckError::RateLimited(response.retry_after_seconds.unwrap_or(60))),
        503 => Err(CheckError::ServiceUnavailable),
        status => Err(CheckError::HttpStatus(status)),
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, CheckError> {
    value.get(key).and_then(Value::as_str).ok_or(CheckError::InvalidMetadata)
}

fn number(value: &Value, key: &str) -> Result<u64, CheckError> {
    value.get(key).and_then(Value::as_u64).ok_or(CheckError::InvalidMetadata)
}

pub fn check_response(
    body: &[u8],
    architecture: &str,
    keys: &[TrustedKey],
) -> Result<CheckStatus, CheckError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| CheckError::InvalidJson)?;
    match value.get("status").and_then(Value::as_str) {
        Some("no_update") => Ok(CheckStatus::NoUpdate),
        Some("distribution_stopped") => Ok(CheckStatus::DistributionStopped),
        Some("unknown_build") => Ok(CheckStatus::UnknownBuild),
        Some("available") => {
            let manifest = verify_available(value.get("release").ok_or(CheckError::InvalidMetadata)?, architecture, keys)?;
            Ok(CheckStatus::Available(manifest))
        }
        _ => Err(CheckError::InvalidStatus),
    }
}

fn verify_available(
    release: &Value,
    architecture: &str,
    keys: &[TrustedKey],
) -> Result<VerifiedManifest, CheckError> {
    let artifact = release.get("artifact").ok_or(CheckError::InvalidMetadata)?;
    let id = string(release, "id")?;
    let version = string(release, "version")?;
    let build = number(release, "build_number")?;
    let channel = string(release, "channel")?;
    let artifact_arch = string(artifact, "architecture")?;
    let url = string(artifact, "url")?;
    let sha = string(artifact, "sha256")?;
    let size = number(artifact, "size_bytes")?;
    let filename = string(artifact, "filename")?;
    let algorithm = string(artifact, "signature_algorithm")?;
    let key_id = string(artifact, "key_id")?;
    let signature = string(artifact, "signature")?;

    let parsed_url = HttpsUrl::parse(url).map_err(|_| CheckError::InvalidMetadata)?;
    let sha256 = decode_sha256_hex(sha).ok_or(CheckError::InvalidMetadata)?;
    if Version::parse(version).is_none() || build == 0
        || id.is_empty() || id.len() > 128
        || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !matches!(channel, "developer_preview" | "beta" | "stable")
        || !matches!(artifact_arch, "x86_64" | "aarch64")
        || algorithm != "Ed25519" || size == 0
        || filename.is_empty() || filename == "." || filename == ".."
        || !filename.ends_with(".moupdate")
        || filename.contains('/') || filename.contains('\\')
        || filename.bytes().any(|byte| byte.is_ascii_control())
        || parsed_url.hostname() != "storage.mochios.org" || parsed_url.port() != 443
        || !url.starts_with("https://storage.mochios.org/")
        || url.contains('#') || url.contains('?')
        || url.contains("/../") || url.contains("/%2e") || url.contains("/%2E")
        || url.contains("/releases/") || filename == "disk.img.zst"
    {
        return Err(CheckError::InvalidMetadata);
    }
    if artifact_arch != architecture { return Err(CheckError::WrongArchitecture); }

    let key = keys.iter().find(|key| key.key_id == key_id).ok_or(CheckError::UntrustedKey)?;
    let public_key = VerifyingKey::from_bytes(&key.public_key).map_err(|_| CheckError::InvalidSignature)?;
    let raw_signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| CheckError::InvalidSignature)?;
    let raw_signature: [u8; 64] = raw_signature.try_into().map_err(|_| CheckError::InvalidSignature)?;
    let signature = Signature::from_bytes(&raw_signature);
    let canonical = format!(
        "mochios-update-manifest-v1\nrelease_id={id}\nversion={version}\nbuild_number={build}\nchannel={channel}\narchitecture={artifact_arch}\nartifact_url={url}\nartifact_sha256={sha}\nartifact_size_bytes={size}\nartifact_filename={filename}\n"
    );
    public_key.verify(canonical.as_bytes(), &signature).map_err(|_| CheckError::InvalidSignature)?;
    Ok(VerifiedManifest {
        release_id: id.to_owned(), version: version.to_owned(), build_number: build,
        channel: channel.to_owned(), architecture: artifact_arch.to_owned(),
        url: url.to_owned(), sha256, size_bytes: size,
        filename: filename.to_owned(), key_id: key_id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    #[test]
    fn version_is_numeric_not_calendar_month() {
        let parse = |text| Version::parse(text).unwrap();
        assert_eq!(parse("26.0"), parse("26.0.0"));
        assert!(parse("26.0.1") > parse("26.0"));
        assert!(parse("26.13") > parse("26.9"));
        assert!(parse("26.10") > parse("26.9"));
        for invalid in ["", "26", "26.", "26..1", "26.0.0.0", "26.-1", "xx.0"] {
            assert_eq!(Version::parse(invalid), None);
        }
    }

    #[test]
    fn status_variants_and_errors_stay_distinct() {
        for (status, expected) in [
            ("no_update", CheckStatus::NoUpdate),
            ("distribution_stopped", CheckStatus::DistributionStopped),
            ("unknown_build", CheckStatus::UnknownBuild),
        ] {
            assert_eq!(check_response(json!({"status":status}).to_string().as_bytes(), "x86_64", &[]), Ok(expected));
        }
        assert_eq!(check_response(b"{", "x86_64", &[]), Err(CheckError::InvalidJson));
        assert_eq!(check_response(b"{}", "x86_64", &[]), Err(CheckError::InvalidStatus));
        let response = |status, retry_after_seconds| Response {
            status, request_id: None, retry_after_seconds, body: vec![],
        };
        assert_eq!(check_http_response(&response(429, Some(120)), "x86_64", &[]), Err(CheckError::RateLimited(120)));
        assert_eq!(check_http_response(&response(503, None), "x86_64", &[]), Err(CheckError::ServiceUnavailable));
    }

    #[test]
    fn signature_is_bound_to_every_manifest_field() {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let key = TrustedKey { key_id: "test-only", public_key: signing.verifying_key().to_bytes() };
        let mut value = json!({"status":"available","release":{
            "id":"release-test", "version":"26.13", "build_number":1300, "channel":"beta",
            "artifact":{"url":"https://storage.mochios.org/update-payload.moupdate", "sha256":"a".repeat(64),
                "size_bytes":123, "filename":"update-payload.moupdate", "architecture":"x86_64",
                "signature":"", "signature_algorithm":"Ed25519", "key_id":"test-only"}}});
        let canonical = format!("mochios-update-manifest-v1\nrelease_id=release-test\nversion=26.13\nbuild_number=1300\nchannel=beta\narchitecture=x86_64\nartifact_url=https://storage.mochios.org/update-payload.moupdate\nartifact_sha256={}\nartifact_size_bytes=123\nartifact_filename=update-payload.moupdate\n", "a".repeat(64));
        value["release"]["artifact"]["signature"] = json!(URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes()));
        let body = value.to_string();
        let offer = check_response(body.as_bytes(), "x86_64", &[key]).unwrap();
        let CheckStatus::Available(manifest) = offer else { panic!("valid signed offer was lost") };
        assert_eq!(manifest.release_id(), "release-test");
        assert_eq!(manifest.version(), "26.13");
        assert_eq!(manifest.build_number(), 1300);
        assert_eq!(manifest.channel(), "beta");
        assert_eq!(manifest.architecture(), "x86_64");
        assert_eq!(manifest.url(), "https://storage.mochios.org/update-payload.moupdate");
        assert_eq!(manifest.sha256(), &[0xaa; 32]);
        assert_eq!(manifest.size_bytes(), 123);
        assert_eq!(manifest.filename(), "update-payload.moupdate");
        assert_eq!(manifest.key_id(), "test-only");
        assert_eq!(check_response(body.as_bytes(), "x86_64", &[]), Err(CheckError::UntrustedKey));
        assert_eq!(check_response(body.as_bytes(), "aarch64", &[key]), Err(CheckError::WrongArchitecture));
        value["release"]["artifact"]["signature"] = json!("not-a-signature");
        assert_eq!(check_response(value.to_string().as_bytes(), "x86_64", &[key]), Err(CheckError::InvalidSignature));
        value["release"]["artifact"]["signature"] = json!(URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes()));
        value["release"]["artifact"]["size_bytes"] = json!(124);
        assert_eq!(check_response(value.to_string().as_bytes(), "x86_64", &[key]), Err(CheckError::InvalidSignature));
        value["release"]["artifact"]["url"] = json!("https://api.mochios.org/releases/release-test/artifact");
        assert_eq!(check_response(value.to_string().as_bytes(), "x86_64", &[key]), Err(CheckError::InvalidMetadata));
        value["release"]["artifact"]["url"] = json!("https://storage.mochios.org/update-payload.moupdate");
        value["release"]["id"] = json!("release-test\nversion=26.13");
        assert_eq!(check_response(value.to_string().as_bytes(), "x86_64", &[key]), Err(CheckError::InvalidMetadata));
    }

    #[test]
    fn signed_manifest_controls_staged_payload_digest_and_size() {
        let signing = SigningKey::from_bytes(&[73; 32]);
        let key = TrustedKey { key_id: "test-only", public_key: signing.verifying_key().to_bytes() };
        let bytes = b"normal-update-payload-not-disk-image";
        let digest = Sha256::digest(bytes);
        let sha = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let size = bytes.len();
        let canonical = format!(
            "mochios-update-manifest-v1\nrelease_id=release-test\nversion=26.13\nbuild_number=1300\nchannel=beta\narchitecture=x86_64\nartifact_url=https://storage.mochios.org/normal-update.moupdate\nartifact_sha256={sha}\nartifact_size_bytes={size}\nartifact_filename=normal-update.moupdate\n"
        );
        let body = json!({"status":"available","release":{
            "id":"release-test", "version":"26.13", "build_number":1300, "channel":"beta",
            "artifact":{"url":"https://storage.mochios.org/normal-update.moupdate", "sha256":sha,
                "size_bytes":size, "filename":"normal-update.moupdate", "architecture":"x86_64",
                "signature":URL_SAFE_NO_PAD.encode(signing.sign(canonical.as_bytes()).to_bytes()),
                "signature_algorithm":"Ed25519", "key_id":"test-only"}}}).to_string();
        let CheckStatus::Available(manifest) = check_response(body.as_bytes(), "x86_64", &[key]).unwrap()
            else { panic!("signed offer missing") };
        let directory = std::env::temp_dir().join(format!(
            "mochios-signed-stage-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let destination = directory.join("staged-update.bin");
        let mut tampered = bytes.to_vec();
        tampered[0] ^= 1;
        assert!(matches!(
            crate::payload::stage_signed_update(&mut tampered.as_slice(), &destination, &manifest),
            Err(crate::payload::StageError::Checksum),
        ));
        assert!(!destination.exists());
        crate::payload::stage_signed_update(&mut bytes.as_slice(), &destination, &manifest).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
