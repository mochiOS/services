use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::package_index::PackageIndex;

const CAPABILITY_PACKAGE_ID: &str = "org.mochios.capability";

#[derive(Default)]
pub(crate) struct AppPromptPolicy {
    interactive: BTreeSet<String>,
}

fn parse_toml_string_array(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        let unquoted = trimmed.strip_prefix('"')?.strip_suffix('"')?;
        out.push(unquoted.to_string());
    }
    Some(out)
}

pub(crate) fn load_app_prompt_policy(index: &PackageIndex) -> AppPromptPolicy {
    let Some(record) = index.by_package.get(CAPABILITY_PACKAGE_ID) else {
        return AppPromptPolicy::default();
    };
    let Ok(bytes) = platform::file::read_to_end_path(&record.manifest_path) else {
        return AppPromptPolicy::default();
    };
    let Ok(text) = core::str::from_utf8(&bytes) else {
        return AppPromptPolicy::default();
    };

    let mut policy = AppPromptPolicy::default();
    let mut section = "";
    let mut collecting = false;
    let mut array_body = String::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            collecting = false;
            array_body.clear();
            continue;
        }
        if collecting {
            if let Some(end) = line.find(']') {
                if !array_body.is_empty() {
                    array_body.push(' ');
                }
                array_body.push_str(line[..end].trim());
                if let Some(items) = parse_toml_string_array(&format!("[{}]", array_body)) {
                    for item in items {
                        if platform::capability::capability_from_string(item.as_str())
                            == platform::capability::CapabilityClass::UserGrantable
                        {
                            policy.interactive.insert(item);
                        }
                    }
                }
                collecting = false;
                array_body.clear();
                continue;
            }
            if !array_body.is_empty() {
                array_body.push(' ');
            }
            array_body.push_str(line);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if section != "prompt" || key.trim() != "interactive_capabilities" {
            continue;
        }
        let value = value.trim();
        if value.contains(']') {
            if let Some(items) = parse_toml_string_array(value) {
                for item in items {
                    if platform::capability::capability_from_string(item.as_str())
                        == platform::capability::CapabilityClass::UserGrantable
                    {
                        policy.interactive.insert(item);
                    }
                }
            }
        } else if let Some(start) = value.find('[') {
            collecting = true;
            array_body.clear();
            array_body.push_str(value[start + 1..].trim());
        }
    }

    policy
}

pub(crate) fn needs_app_prompt(policy: &AppPromptPolicy, capability: &str) -> bool {
    policy.interactive.contains(capability)
}

pub(crate) fn is_known_capability(name: &str) -> bool {
    mnu_abi::capability::metadata(name).is_some()
}

pub(crate) fn validate_capabilities(
    binary_path: &str,
    caps: &[String],
) -> Result<(), mochi_user_syscall::SysError> {
    for cap in caps {
        if !is_known_capability(cap.as_str()) {
            platform::logln!(
                "capability.service: unknown capability {} requested by {}",
                cap,
                binary_path
            );
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    Ok(())
}
