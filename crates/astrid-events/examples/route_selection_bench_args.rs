//! One-pass argv parser for the route-selection release microbench.
//!
//! Unknown flags and missing flag values are hard errors so a typo cannot
//! silently become an n1 measurement. Well-formed argv used by the matched
//! ABBA protocol is unchanged.

use std::fmt;

/// Parsed microbench configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchConfig {
    pub label: String,
    pub foreign: usize,
    pub iters: u32,
    pub warmups: u32,
}

/// Argv parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchArgsError {
    UnknownFlag(String),
    MissingValue(&'static str),
    InvalidValue { flag: &'static str, value: String },
    ItersMustBePositive,
}

impl fmt::Display for BenchArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            Self::MissingValue(flag) => write!(f, "missing value for {flag}"),
            Self::InvalidValue { flag, value } => {
                write!(f, "invalid value for {flag}: {value}")
            },
            Self::ItersMustBePositive => write!(f, "--iters must be >= 1 (got 0)"),
        }
    }
}

impl BenchConfig {
    /// Defaults matching the previous well-formed harness behavior when flags
    /// are omitted: `label=unlabeled`, `foreign=0`, `iters=2000`, `warmups=2`.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            label: "unlabeled".into(),
            foreign: 0,
            iters: 2_000,
            warmups: 2,
        }
    }

    /// One-pass typed parse over argv tokens after the program name.
    pub fn parse<I, S>(args: I) -> Result<Self, BenchArgsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut cfg = Self::defaults();
        let mut iter = args.into_iter();
        while let Some(raw) = iter.next() {
            let arg = raw.as_ref();
            match arg {
                "--label" => {
                    let value = iter.next().ok_or(BenchArgsError::MissingValue("--label"))?;
                    let value = value.as_ref();
                    if value.is_empty() || value.starts_with('-') {
                        return Err(BenchArgsError::MissingValue("--label"));
                    }
                    value.clone_into(&mut cfg.label);
                },
                "--foreign" => {
                    cfg.foreign = parse_usize("--foreign", &mut iter)?;
                },
                "--iters" => {
                    cfg.iters = parse_u32("--iters", &mut iter)?;
                },
                "--warmups" => {
                    cfg.warmups = parse_u32("--warmups", &mut iter)?;
                },
                other if other.starts_with('-') => {
                    return Err(BenchArgsError::UnknownFlag(other.to_owned()));
                },
                other => {
                    return Err(BenchArgsError::UnknownFlag(other.to_owned()));
                },
            }
        }
        if cfg.iters == 0 {
            return Err(BenchArgsError::ItersMustBePositive);
        }
        Ok(cfg)
    }
}

fn parse_u32<'a, I, S>(flag: &'static str, iter: &mut I) -> Result<u32, BenchArgsError>
where
    I: Iterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let value = iter.next().ok_or(BenchArgsError::MissingValue(flag))?;
    let value = value.as_ref();
    value.parse().map_err(|_| BenchArgsError::InvalidValue {
        flag,
        value: value.to_owned(),
    })
}

fn parse_usize<'a, I, S>(flag: &'static str, iter: &mut I) -> Result<usize, BenchArgsError>
where
    I: Iterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let value = iter.next().ok_or(BenchArgsError::MissingValue(flag))?;
    let value = value.as_ref();
    value.parse().map_err(|_| BenchArgsError::InvalidValue {
        flag,
        value: value.to_owned(),
    })
}
