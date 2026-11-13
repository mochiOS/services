//! Configuration for the opt-in, signed native test launcher only.
#[derive(Debug)]
pub struct Configuration {
    pub application: String,
    pub result: String,
    pub pass: String,
    pub fail: String,
    pub timeout_seconds: u64,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            application: "/system/applications/ExecRefTest.app/entry.elf".into(),
            result: "/tmp/executable-api-results.log".into(),
            pass: "EXE-API PASS".into(),
            fail: "EXE-API FAIL".into(),
            timeout_seconds: 120,
        }
    }
}
impl Configuration {
    /// Read bounded fixture settings. This selects an application; the normal
    /// capability broker still authenticates its package, bytes and permissions.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.len() > 4096 || text.contains(['\0', '\r']) {
            return Err("invalid fixture configuration");
        }
        let mut result = Self::default();
        let mut seen = 0u8;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let (key, value) = line.split_once('=').ok_or("invalid setting")?;
            let value = value.trim();
            let bit = match key.trim() {
                "application" => {
                    result.application = value.into();
                    1
                }
                "result" => {
                    result.result = value.into();
                    2
                }
                "pass" => {
                    result.pass = value.into();
                    4
                }
                "fail" => {
                    result.fail = value.into();
                    8
                }
                "timeout_seconds" => {
                    result.timeout_seconds = value.parse().map_err(|_| "invalid timeout")?;
                    16
                }
                _ => return Err("unknown setting"),
            };
            if seen & bit != 0 {
                return Err("duplicate setting");
            }
            seen |= bit;
        }
        let app = result
            .application
            .strip_prefix("/system/applications/")
            .and_then(|path| path.strip_suffix("/entry.elf"))
            .ok_or("invalid application path")?;
        if app.len() <= 4
            || !app.ends_with(".app")
            || app.contains(['/', '\\'])
            || result.application.len() > 512
        {
            return Err("invalid application path");
        }
        let file = result
            .result
            .strip_prefix("/tmp/")
            .ok_or("invalid result path")?;
        if file.is_empty()
            || matches!(file, "." | "..")
            || file.len() > 128
            || file.contains(['/', '\\'])
        {
            return Err("invalid result path");
        }
        if !(1..=3600).contains(&result.timeout_seconds)
            || [&result.pass, &result.fail]
                .iter()
                .any(|value| value.is_empty() || value.len() > 64)
            || result.pass == result.fail
        {
            return Err("invalid result markers or timeout");
        }
        Ok(result)
    }

    /// Accept only complete lines. Failure dominates a pass, and duplicate
    /// success markers cannot turn a reused or inconsistent result into success.
    pub fn completed(&self, text: &str) -> Option<bool> {
        if text.contains('\0') {
            return None;
        }
        let mut passes = 0;
        for line in text
            .split_inclusive('\n')
            .filter_map(|line| line.strip_suffix('\n'))
        {
            if line == self.fail
                || line
                    .strip_prefix(&self.fail)
                    .is_some_and(|tail| tail.starts_with([' ', ':']))
            {
                return Some(false);
            }
            passes += usize::from(line == self.pass);
        }
        match passes {
            0 => None,
            1 => Some(true),
            _ => Some(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_a_separate_signed_application_fixture() {
        let config = Configuration::parse("application=/system/applications/Terra.app/entry.elf\nresult=/tmp/terra-engine-results.log\npass=TERRA-ENGINE PASS\nfail=TERRA-ENGINE FAIL\ntimeout_seconds=1800\n").unwrap();
        assert_eq!(config.timeout_seconds, 1800);
        assert_eq!(config.completed("TERRA-ENGINE PASS\n"), Some(true));
    }
    #[test]
    fn rejects_traversal_and_non_application_targets() {
        for path in [
            "/system/services/core",
            "/system/applications/../entry.elf",
            "/system/applications/A.app/../B.app/entry.elf",
        ] {
            assert!(Configuration::parse(&format!("application={path}")).is_err());
        }
        assert!(Configuration::parse("result=/tmp/../private").is_err());
    }
    #[test]
    fn rejects_duplicates_unknown_fields_and_unbounded_input() {
        for text in [
            "pass=A\npass=B",
            "unknown=true",
            "timeout_seconds=0",
            "timeout_seconds=3601",
            "pass=",
            "pass=A\nfail=A",
        ] {
            assert!(Configuration::parse(text).is_err());
        }
        assert!(Configuration::parse(&" ".repeat(4097)).is_err());
    }
    #[test]
    fn partial_lines_are_not_a_completed_result() {
        let config = Configuration::default();
        assert_eq!(config.completed("EXE-API PASS"), None);
        assert_eq!(config.completed("EXE-API FAIL pending"), None);
        assert_eq!(config.completed("EXE-API PASS-other\n"), None);
    }
    #[test]
    fn failure_and_duplicate_pass_are_rejected() {
        let config = Configuration::default();
        assert_eq!(
            config.completed("EXE-API PASS\nEXE-API FAIL panic\n"),
            Some(false)
        );
        assert_eq!(
            config.completed("EXE-API PASS\nEXE-API PASS\n"),
            Some(false)
        );
        assert_eq!(config.completed("EXE-API PASS\n\0"), None);
    }
}
