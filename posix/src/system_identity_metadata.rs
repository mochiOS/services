//! Parse the release manifest's deliberately simple scalar build metadata.
//! Reject unsupported escaping instead of silently publishing a wrong version.
pub fn generate(text: &str, architecture: &str) -> Result<String, String> {
    fn value<'a>(text: &'a str, key: &str) -> Result<&'a str, String> {
        let mut values = text.lines().filter_map(|line| {
            let (name, value) = line.trim().split_once('=')?;
            (name.trim() == key).then_some(value.trim())
        });
        let value = values.next().ok_or_else(|| format!("missing {key}"))?;
        if values.next().is_some() {
            return Err(format!("duplicate {key}"));
        }
        Ok(value)
    }
    fn string<'a>(text: &'a str, key: &str) -> Result<&'a str, String> {
        let value = value(text, key)?
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| format!("{key} must be a quoted string"))?;
        if value.is_empty()
            || value
                .chars()
                .any(|c| c.is_control() || c == '\\' || c == '"')
        {
            return Err(format!("unsupported {key} string"));
        }
        Ok(value)
    }
    let release = string(text, "release")?;
    let date = string(text, "build_date")?;
    let channel = string(text, "channel")?;
    let build = value(text, "build")?
        .parse::<u64>()
        .map_err(|_| "invalid build number")?;
    let version = format!("build {build} {channel} {date}");
    if [release, version.as_str(), architecture]
        .iter()
        .any(|s| s.is_empty() || s.len() >= 256 || s.contains('\0'))
    {
        return Err("identity field is empty or exceeds its ABI limit".into());
    }
    Ok(format!(
        "pub const RELEASE: &str = {release:?};\npub const VERSION: &str = {version:?};\npub const MACHINE: &str = {architecture:?};\n"
    ))
}
