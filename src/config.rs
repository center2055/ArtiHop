use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use arti_client::CountryCode;
use clap::{Parser, ValueEnum};
use serde::Deserialize;

use crate::exit::parse_exit_country;

#[derive(Debug, Parser)]
#[command(name = "artihop", version, about = "Local SOCKS proxy powered by Arti")]
pub struct Cli {
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Path to an Arti-format TOML file with a [bridges] section (bridge lines + pluggable
    /// transports). When set, ArtiHop connects through those bridges instead of directly.
    #[arg(long, value_name = "FILE")]
    pub bridges_config: Option<PathBuf>,

    #[arg(long, value_enum)]
    pub mode: Option<Mode>,

    #[arg(long, value_name = "ADDR")]
    pub socks: Option<SocketAddr>,

    #[arg(long, value_name = "FILTER")]
    pub log: Option<String>,

    /// Loopback address for a small control listener. It accepts one command per line: `NEWNYM`
    /// (later streams use fresh circuits, like Tor's signal of that name) and `PING`.
    #[arg(long, value_name = "ADDR")]
    pub control: Option<SocketAddr>,

    /// Two-letter country that streams should appear to come from, e.g. `de`; `auto` for any.
    /// Only exit relays in that country are used. The control command `EXITCOUNTRY` changes it
    /// while ArtiHop runs.
    #[arg(long, value_name = "CC")]
    pub exit_country: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    #[value(name = "normal")]
    Normal,
    #[value(name = "short-2")]
    Short2,
    #[value(name = "short-1")]
    Short1,
}

impl Mode {
    pub fn is_experimental(self) -> bool {
        matches!(self, Self::Short1 | Self::Short2)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("normal"),
            Self::Short2 => f.write_str("short-2"),
            Self::Short1 => f.write_str("short-1"),
        }
    }
}

impl FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "normal" => Ok(Self::Normal),
            "short-2" | "short2" => Ok(Self::Short2),
            "short-1" | "short1" => Ok(Self::Short1),
            other => bail!("unsupported mode `{other}`"),
        }
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        <Mode as FromStr>::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub mode: Mode,
    pub socks: SocketAddr,
    pub log_filter: String,
    /// Optional Arti-format TOML config file carrying the [bridges] section.
    pub bridges_config: Option<PathBuf>,
    /// Optional loopback control listener (NEWNYM / EXITCOUNTRY / PING).
    pub control: Option<SocketAddr>,
    /// The country streams should appear to come from; `None` for any.
    pub exit_country: Option<CountryCode>,
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    mode: Option<Mode>,
    socks: Option<SocketAddr>,
    log_filter: Option<String>,
    bridges_config: Option<PathBuf>,
    control: Option<SocketAddr>,
    exit_country: Option<String>,
}

impl AppConfig {
    pub fn load(cli: Cli) -> Result<Self> {
        let mut config = Self::default();

        if let Some(path) = cli.config.as_deref() {
            config.apply_file(path)?;
        }

        if let Some(mode) = cli.mode {
            config.mode = mode;
        }

        if let Some(socks) = cli.socks {
            config.socks = socks;
        }

        if let Some(log_filter) = cli.log {
            config.log_filter = log_filter;
        }

        if let Some(bridges_config) = cli.bridges_config {
            config.bridges_config = Some(bridges_config);
        }

        if let Some(control) = cli.control {
            config.control = Some(control);
        }

        if let Some(exit_country) = cli.exit_country.as_deref() {
            config.exit_country = parse_exit_country(exit_country)?;
        }

        config.validate()?;
        Ok(config)
    }

    /// Anything that can reach the control listener can rotate circuits, so it only ever listens
    /// on this machine.
    fn validate(&self) -> Result<()> {
        if let Some(control) = self.control
            && !control.ip().is_loopback()
        {
            bail!("the control listener must use a loopback address, not {control}");
        }

        Ok(())
    }

    fn apply_file(&mut self, path: &Path) -> Result<()> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let file_config: FileConfig = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;

        if let Some(mode) = file_config.mode {
            self.mode = mode;
        }

        if let Some(socks) = file_config.socks {
            self.socks = socks;
        }

        if let Some(log_filter) = file_config.log_filter {
            self.log_filter = log_filter;
        }

        if let Some(bridges_config) = file_config.bridges_config {
            self.bridges_config = Some(bridges_config);
        }

        if let Some(control) = file_config.control {
            self.control = Some(control);
        }

        if let Some(exit_country) = file_config.exit_country.as_deref() {
            self.exit_country = parse_exit_country(exit_country)
                .with_context(|| format!("exit_country in config file {}", path.display()))?;
        }

        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Normal,
            socks: "127.0.0.1:9050"
                .parse()
                .expect("default SOCKS address must parse"),
            log_filter: "artihop=info,arti_client=info,tor_proto=warn,tor_circmgr=info".to_owned(),
            bridges_config: None,
            control: None,
            exit_country: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_defaults() {
        let cli = Cli {
            config: None,
            bridges_config: None,
            mode: Some(Mode::Short2),
            socks: Some("127.0.0.1:19050".parse().unwrap()),
            log: Some("artihop=debug".to_owned()),
            control: Some("127.0.0.1:19051".parse().unwrap()),
            exit_country: Some("de".to_owned()),
        };

        let config = AppConfig::load(cli).unwrap();

        assert_eq!(config.mode, Mode::Short2);
        assert_eq!(config.socks.to_string(), "127.0.0.1:19050");
        assert_eq!(config.log_filter, "artihop=debug");
        assert_eq!(config.control.unwrap().to_string(), "127.0.0.1:19051");
        assert_eq!(config.exit_country.unwrap().to_string(), "DE");
    }

    #[test]
    fn exit_country_must_be_a_country_code() {
        let cli = Cli {
            config: None,
            bridges_config: None,
            mode: None,
            socks: None,
            log: None,
            control: None,
            exit_country: Some("germany".to_owned()),
        };

        assert!(AppConfig::load(cli).is_err());
    }

    #[test]
    fn control_listener_must_be_loopback() {
        let cli = Cli {
            config: None,
            bridges_config: None,
            mode: None,
            socks: None,
            log: None,
            control: Some("0.0.0.0:19051".parse().unwrap()),
            exit_country: None,
        };

        assert!(AppConfig::load(cli).is_err());
    }

    #[test]
    fn parses_mode_aliases() {
        assert_eq!("normal".parse::<Mode>().unwrap(), Mode::Normal);
        assert_eq!("short2".parse::<Mode>().unwrap(), Mode::Short2);
        assert_eq!("short1".parse::<Mode>().unwrap(), Mode::Short1);
    }
}
