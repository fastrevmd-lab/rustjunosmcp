//! Validate SRX transport arguments before inventory or network initialization.

use crate::cli::Cli;
use std::net::IpAddr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CliRefusal {
    #[error("streamable HTTP requires --tokens-file (or --allow-no-auth on loopback)")]
    AuthRequired,
    #[error(
        "--allow-no-auth refuses to bind off-loopback (host '{host}' is not 127.0.0.1 or ::1)"
    )]
    NoAuthOffLoopback { host: String },
    #[error(
        "non-loopback bind '{host}' over plain HTTP requires --allow-insecure-bind (or --tls-cert/--tls-key)"
    )]
    InsecureBindRequired { host: String },
    #[error("--tls-cert and --tls-key must be set together (got cert={cert}, key={key})")]
    TlsPairIncomplete { cert: bool, key: bool },
}

pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    let tls_configured = match (cli.tls_cert.is_some(), cli.tls_key.is_some()) {
        (true, true) => true,
        (false, false) => false,
        (cert, key) => return Err(CliRefusal::TlsPairIncomplete { cert, key }),
    };

    let host_is_loopback = match cli.host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    };

    if cli.tokens_file.is_none() && !cli.allow_no_auth {
        return Err(CliRefusal::AuthRequired);
    }
    if cli.tokens_file.is_none() && cli.allow_no_auth && !host_is_loopback {
        return Err(CliRefusal::NoAuthOffLoopback {
            host: cli.host.clone(),
        });
    }
    if !host_is_loopback && !tls_configured && !cli.allow_insecure_bind {
        return Err(CliRefusal::InsecureBindRequired {
            host: cli.host.clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("rust-srxmcp").chain(args.iter().copied()))
    }

    #[test]
    fn startup_refusal_matrix() {
        struct Case<'a> {
            name: &'a str,
            args: &'a [&'a str],
            expected: Result<(), CliRefusal>,
        }

        let cases = [
            Case {
                name: "auth required by default",
                args: &[],
                expected: Err(CliRefusal::AuthRequired),
            },
            Case {
                name: "authenticated loopback plaintext",
                args: &["--tokens-file", "/tmp/tokens.json"],
                expected: Ok(()),
            },
            Case {
                name: "no auth loopback",
                args: &["--allow-no-auth"],
                expected: Ok(()),
            },
            Case {
                name: "no auth non-loopback remains forbidden with insecure override",
                args: &[
                    "--allow-no-auth",
                    "--host",
                    "0.0.0.0",
                    "--allow-insecure-bind",
                ],
                expected: Err(CliRefusal::NoAuthOffLoopback {
                    host: "0.0.0.0".into(),
                }),
            },
            Case {
                name: "no auth non-loopback remains forbidden with TLS",
                args: &[
                    "--allow-no-auth",
                    "--host",
                    "0.0.0.0",
                    "--tls-cert",
                    "/tmp/cert.pem",
                    "--tls-key",
                    "/tmp/key.pem",
                ],
                expected: Err(CliRefusal::NoAuthOffLoopback {
                    host: "0.0.0.0".into(),
                }),
            },
            Case {
                name: "authenticated non-loopback plaintext refused",
                args: &["--tokens-file", "/tmp/tokens.json", "--host", "0.0.0.0"],
                expected: Err(CliRefusal::InsecureBindRequired {
                    host: "0.0.0.0".into(),
                }),
            },
            Case {
                name: "authenticated non-loopback explicit insecure override",
                args: &[
                    "--tokens-file",
                    "/tmp/tokens.json",
                    "--host",
                    "0.0.0.0",
                    "--allow-insecure-bind",
                ],
                expected: Ok(()),
            },
            Case {
                name: "authenticated non-loopback TLS",
                args: &[
                    "--tokens-file",
                    "/tmp/tokens.json",
                    "--host",
                    "0.0.0.0",
                    "--tls-cert",
                    "/tmp/cert.pem",
                    "--tls-key",
                    "/tmp/key.pem",
                ],
                expected: Ok(()),
            },
            Case {
                name: "certificate without key refused",
                args: &[
                    "--tokens-file",
                    "/tmp/tokens.json",
                    "--tls-cert",
                    "/tmp/cert.pem",
                ],
                expected: Err(CliRefusal::TlsPairIncomplete {
                    cert: true,
                    key: false,
                }),
            },
            Case {
                name: "key without certificate refused",
                args: &[
                    "--tokens-file",
                    "/tmp/tokens.json",
                    "--tls-key",
                    "/tmp/key.pem",
                ],
                expected: Err(CliRefusal::TlsPairIncomplete {
                    cert: false,
                    key: true,
                }),
            },
            Case {
                name: "IPv6 loopback accepted",
                args: &["--tokens-file", "/tmp/tokens.json", "--host", "::1"],
                expected: Ok(()),
            },
            Case {
                name: "hostnames treated as non-loopback",
                args: &[
                    "--tokens-file",
                    "/tmp/tokens.json",
                    "--host",
                    "srxmcp.internal",
                ],
                expected: Err(CliRefusal::InsecureBindRequired {
                    host: "srxmcp.internal".into(),
                }),
            },
        ];

        for case in cases {
            assert_eq!(validate(&parse(case.args)), case.expected, "{}", case.name);
        }
    }
}
