const DRIVER_MANAGER_PREFIX: &[u8] = b"--driver-manager";
const DRIVER_MANAGER_VALUE_PREFIX: &[u8] = b"--driver-manager=";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DriverManagerConfig {
    pub(crate) endpoint: u64,
    pub(crate) token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverManagerArgError {
    Missing,
    Duplicate,
    MissingEndpoint,
    MissingToken,
    InvalidFormat,
    InvalidEndpoint,
    InvalidToken,
}

pub(crate) struct DriverManagerArgParser {
    config: Option<DriverManagerConfig>,
}

impl DriverManagerArgParser {
    pub(crate) const fn new() -> Self {
        Self { config: None }
    }

    pub(crate) fn push(&mut self, argument: &[u8]) -> Result<(), DriverManagerArgError> {
        if !argument.starts_with(DRIVER_MANAGER_PREFIX) {
            return Ok(());
        }
        if self.config.is_some() {
            return Err(DriverManagerArgError::Duplicate);
        }
        let Some(value) = argument.strip_prefix(DRIVER_MANAGER_VALUE_PREFIX) else {
            return Err(DriverManagerArgError::InvalidFormat);
        };
        let Some(separator) = value.iter().position(|&byte| byte == b':') else {
            return if value.is_empty() {
                Err(DriverManagerArgError::MissingEndpoint)
            } else {
                Err(DriverManagerArgError::MissingToken)
            };
        };
        if value[separator + 1..].contains(&b':') {
            return Err(DriverManagerArgError::InvalidFormat);
        }
        let endpoint_bytes = &value[..separator];
        let token_bytes = &value[separator + 1..];
        if endpoint_bytes.is_empty() {
            return Err(DriverManagerArgError::MissingEndpoint);
        }
        if token_bytes.is_empty() {
            return Err(DriverManagerArgError::MissingToken);
        }
        let endpoint =
            parse_decimal_u64(endpoint_bytes).ok_or(DriverManagerArgError::InvalidEndpoint)?;
        let token = parse_decimal_u64(token_bytes).ok_or(DriverManagerArgError::InvalidToken)?;
        self.config = Some(DriverManagerConfig { endpoint, token });
        Ok(())
    }

    pub(crate) const fn finish(self) -> Result<DriverManagerConfig, DriverManagerArgError> {
        match self.config {
            Some(config) => Ok(config),
            None => Err(DriverManagerArgError::Missing),
        }
    }
}

fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?;
        value = value.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}
