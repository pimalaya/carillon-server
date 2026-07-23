# Contributing guide

Thank you for investing your time in contributing to Carillon.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/main.rs: it is the architecture document of this crate;
4. the docs/ folder for the development history and living plans.

Everything below documents only what differs from the Pimalaya standards.

## Binary, not a library

This crate is a daemon: its architecture header lives in src/main.rs (not src/lib.rs), it publishes no rustdoc, and its public-item naming conventions do not apply since it exposes no API.

## Nix toolchain

There is no system cargo; every build and check runs through the shared Pimalaya nix devshell, for example nix develop --command cargo build. The production NixOS service module lives in nix/, and its consumer host lives in the separate carillon-deploy repository.
