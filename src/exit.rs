//! The exit country: the country new streams should appear to come from.
//!
//! It is shared between the SOCKS listener, which applies it to each new stream, and the control
//! listener, which can change it while ArtiHop runs. Arti then only picks exit relays whose address
//! is in that country according to its GeoIP database; in the 2-hop mode too, where the exit is
//! chosen the same way.

use std::sync::{Arc, RwLock};

use anyhow::{Result, bail};
use arti_client::CountryCode;

/// The current exit country, or `None` for any country.
#[derive(Clone, Default)]
pub struct ExitCountry(Arc<RwLock<Option<CountryCode>>>);

impl ExitCountry {
    pub fn new(country: Option<CountryCode>) -> Self {
        Self(Arc::new(RwLock::new(country)))
    }

    pub fn get(&self) -> Option<CountryCode> {
        *self
            .0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Streams opened from now on use the new country. Open streams keep their circuits.
    pub fn set(&self, country: Option<CountryCode>) {
        *self
            .0
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = country;
    }
}

/// A two-letter country code such as `de` or `US`, or `auto` (also `any`, or nothing) for no
/// preference.
pub fn parse_exit_country(text: &str) -> Result<Option<CountryCode>> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("auto") || text.eq_ignore_ascii_case("any") {
        return Ok(None);
    }

    if text.len() != 2 || !text.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        bail!("`{text}` is not a two-letter country code (or `auto`)");
    }

    match text.to_ascii_uppercase().parse::<CountryCode>() {
        Ok(country) => Ok(Some(country)),
        Err(error) => bail!("`{text}` is not a usable country code: {error}"),
    }
}

pub fn describe(country: Option<CountryCode>) -> String {
    match country {
        Some(country) => country.to_string(),
        None => "auto".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_letters_in_any_case_are_a_country() {
        assert_eq!(parse_exit_country("de").unwrap().unwrap().to_string(), "DE");
        assert_eq!(
            parse_exit_country(" US ").unwrap().unwrap().to_string(),
            "US"
        );
    }

    #[test]
    fn auto_any_and_nothing_mean_no_preference() {
        assert!(parse_exit_country("auto").unwrap().is_none());
        assert!(parse_exit_country("ANY").unwrap().is_none());
        assert!(parse_exit_country("").unwrap().is_none());
    }

    #[test]
    fn anything_else_is_refused() {
        assert!(parse_exit_country("germany").is_err());
        assert!(parse_exit_country("d").is_err());
        assert!(parse_exit_country("d3").is_err());
        assert!(parse_exit_country("??").is_err());
    }

    #[test]
    fn the_country_can_be_changed_while_running() {
        let exit = ExitCountry::new(None);
        assert_eq!(describe(exit.get()), "auto");

        let shared = exit.clone();
        shared.set(parse_exit_country("nl").unwrap());
        assert_eq!(describe(exit.get()), "NL");

        shared.set(None);
        assert!(exit.get().is_none());
    }
}
