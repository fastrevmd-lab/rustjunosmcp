//! The container builder and `rust-toolchain.toml` must name the same Rust.
//!
//! `FROM` cannot read a file, so the Dockerfile carries its own literal. Nothing
//! kept the two in step, which is the open item on #201: they agree today by
//! coincidence, and a `rust-toolchain.toml` bump would silently leave the image
//! building on the old compiler until something failed that only reproduced
//! inside the container.
//!
//! A test is the cheapest thing that actually holds them together.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path
}

/// `channel = "1.97.0"` → `1.97.0`
fn toolchain_channel() -> String {
    let text = std::fs::read_to_string(repo_root().join("rust-toolchain.toml"))
        .expect("read rust-toolchain.toml");
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_string())
        })
        .expect("rust-toolchain.toml declares a channel")
}

/// `FROM rust:1.97-slim-bookworm@sha256:… AS builder` → `1.97`
fn dockerfile_builder_version() -> String {
    let text = std::fs::read_to_string(repo_root().join("Dockerfile")).expect("read Dockerfile");
    text.lines()
        .find_map(|line| {
            let rest = line.strip_prefix("FROM rust:")?;
            let tag = rest.split(['-', '@', ' ']).next()?;
            Some(tag.to_string())
        })
        .expect("Dockerfile has a `FROM rust:<version>` builder stage")
}

/// The Dockerfile may pin a shorter form (`1.97` for `1.97.0`), since the
/// upstream `rust` image publishes both. It may not name a *different* release.
#[test]
fn the_container_builder_matches_the_pinned_toolchain() {
    let channel = toolchain_channel();
    let builder = dockerfile_builder_version();

    assert!(
        channel == builder || channel.starts_with(&format!("{builder}.")),
        "Dockerfile builds on Rust {builder} but rust-toolchain.toml pins {channel}. \
         Update `FROM rust:<version>-slim-bookworm` in the Dockerfile — including its \
         digest — so the image is built with the compiler this repo is tested on (#201)."
    );
}

/// The digest is what makes the pin reproducible; a bare tag is not a pin.
#[test]
fn the_builder_image_is_digest_pinned() {
    let text = std::fs::read_to_string(repo_root().join("Dockerfile")).expect("read Dockerfile");
    let builder = text
        .lines()
        .find(|line| line.starts_with("FROM rust:"))
        .expect("Dockerfile has a `FROM rust:` builder stage");

    assert!(
        builder.contains("@sha256:"),
        "the builder base must be digest-pinned, got: {builder}"
    );
}

/// Same requirement for the runtime stage — the one that ships.
#[test]
fn the_runtime_image_is_digest_pinned() {
    let text = std::fs::read_to_string(repo_root().join("Dockerfile")).expect("read Dockerfile");
    let runtime = text
        .lines()
        .rfind(|line| line.starts_with("FROM ") && !line.contains(" AS builder"))
        .expect("Dockerfile has a runtime stage");

    assert!(
        runtime.contains("@sha256:"),
        "the runtime base must be digest-pinned, got: {runtime}"
    );
}
