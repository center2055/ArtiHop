use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(name = "artihop", version, about = "Local SOCKS proxy powered by Arti")]
pub struct Cli {
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(long, value_enum)]
    pub mode: Option<Mode>,

    #[arg(long, value_name = "ADDR")]
    pub socks: Option<SocketAddr>,

    #[arg(long, value_name = "FILTER")]
    pub log: Option<String>,
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
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    mode: Option<Mode>,
    socks: Option<SocketAddr>,
    log_filter: Option<String>,
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

        Ok(config)
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
        }
    }
}
