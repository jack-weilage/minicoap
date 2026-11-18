# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/jack-weilage/minicoap/compare/v0.2.0...v0.3.0) - 2026-11-18

### Breaking changes

- Add a fallback arm to matches on CoapBuildError and CoapParseError. Handle OptionValueTooLong explicitly if your application needs to distinguish an unencodable option value.
- `empty()` and `ping()` no longer allow `token()`, `no_token()`, `option()` or `payload()`. Replace `.message_id(id).no_token()?.no_payload().build()` with `.message_id(id).build()`.
- adds `CoapBuildError::OptionValueTooLong`, returned for option values longer than 65804 bytes. Malformed packets with an overflowing option number now fail with `CoapParseError::InvalidOptionDelta` instead of parsing.

### Added

- [**breaking**] make build and parse errors non-exhaustive ([#14](https://github.com/jack-weilage/minicoap/pull/14))

### Fixed

- [**breaking**] make Empty messages header-only in the builder ([#10](https://github.com/jack-weilage/minicoap/pull/10))
- reject Empty messages that carry a token ([#9](https://github.com/jack-weilage/minicoap/pull/9))
- [**breaking**] eliminate panic sites in parser and builder ([#4](https://github.com/jack-weilage/minicoap/pull/4))

### Other

- update installation examples for 0.3 ([#15](https://github.com/jack-weilage/minicoap/pull/15))
- run README usage examples as doctests ([#13](https://github.com/jack-weilage/minicoap/pull/13))
- share option decoding between parsing and iteration ([#12](https://github.com/jack-weilage/minicoap/pull/12))
- show breaking-change notes in the changelog ([#11](https://github.com/jack-weilage/minicoap/pull/11))
- add PR checks and Dependabot ([#6](https://github.com/jack-weilage/minicoap/pull/6))

## [0.2.0](https://github.com/jack-weilage/minicoap/compare/v0.1.0...v0.2.0) - 2025-10-20

### Added

- Update IANA Expert Review CoAP Content-Formats
- Support RFC7967
- Support RFC9175

## [0.1.0](https://github.com/jack-weilage/minicoap/releases/tag/v0.1.0) - 2025-10-14

### Added

- *(ci)* Add release-plz workflow for automated releases
- Add utility method to measure the amount of remaining space in the buffer
- Support RFC8132
- Initial commit

### Fixed

- Ensure that options are always included in ascending order

### Other

- Improve documentation for errors
- Update README
- Code cleanup
