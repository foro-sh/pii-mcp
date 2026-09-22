## [1.5.2](https://github.com/foro-sh/pii-mcp/compare/v1.5.1...v1.5.2) (2026-09-22)

### Bug Fixes

* close IPv6, MAC, IMEI, and trunk-zero phone leaks ([2c43cfd](https://github.com/foro-sh/pii-mcp/commit/2c43cfd09cb068f1e4db6c11158c0687bb9a9460))
* close phone hex-glue and obvious fake-SSN hits ([c14bd7b](https://github.com/foro-sh/pii-mcp/commit/c14bd7b5cbd590ec3d28f1a9b120b9c593ba2ad1))
* merge detector false-positive fixes ([#23](https://github.com/foro-sh/pii-mcp/issues/23)) ([1210d62](https://github.com/foro-sh/pii-mcp/commit/1210d62557a2896227d5c45f2004a40e35e2dcdb))

## [1.5.1](https://github.com/foro-sh/pii-mcp/compare/v1.5.0...v1.5.1) (2026-09-20)

### Bug Fixes

* close email-glue, slash-SSN, and padded-IP leaks ([009a5ce](https://github.com/foro-sh/pii-mcp/commit/009a5ce28c3dffc686332e032bf248f4fe676500))
* close IBAN separator and glued-email scrub leaks ([6519099](https://github.com/foro-sh/pii-mcp/commit/6519099aafb7fb00bc680e0e82690ec1f4970740))
* close more separator and email-glue scrub leaks ([8a30f9b](https://github.com/foro-sh/pii-mcp/commit/8a30f9bec71f93ea1787c102a30a8d9c4314c700))
* close unicode-space, glue, and degree-location leaks ([47f5d1d](https://github.com/foro-sh/pii-mcp/commit/47f5d1d6487668cc672d849527168bad98d953ae))
* widen scrub separators and close mapped-IP leak ([b4f0c6d](https://github.com/foro-sh/pii-mcp/commit/b4f0c6dc9e4ec1b97bf9b409acb56998dffd41bd))

## [1.5.0](https://github.com/foro-sh/pii-mcp/compare/v1.4.0...v1.5.0) (2026-09-19)

### Features

* **ci:** publish maturin platform wheels to PyPI ([fac6dfb](https://github.com/foro-sh/pii-mcp/commit/fac6dfb80e9d26f9dfdb0c5b5fc3dd99373a6cd2))
* merge IMEI and Dutch passport detectors ([c421bb3](https://github.com/foro-sh/pii-mcp/commit/c421bb38e5308e030d3d35e2a5efcd470180d467))
* **python:** enable abi3 and sync native crate version ([736fc5c](https://github.com/foro-sh/pii-mcp/commit/736fc5c9688d872efa72e1c69810c87039f50174))
* scrub IMEI and Dutch passport numbers ([171fe1e](https://github.com/foro-sh/pii-mcp/commit/171fe1ea0ed9400ca27300becbba8b679f14a97c))
* TypeScript SDK with napi pii-core bindings ([#13](https://github.com/foro-sh/pii-mcp/issues/13)) ([414a8ed](https://github.com/foro-sh/pii-mcp/commit/414a8ed13915e015adc703f7d6427e290c32f9ca))

### Bug Fixes

* accept lowercased Dutch passport numbers ([c232e09](https://github.com/foro-sh/pii-mcp/commit/c232e09ace15489d2c313c6302370cd5a9ab2308))
* **ci:** avoid wheel shadowing and retire macos-13 ([c1643fe](https://github.com/foro-sh/pii-mcp/commit/c1643febe2c0ffb1129bd200ccade31aebf05d36))

## [1.4.0](https://github.com/foro-sh/pii-mcp/compare/v1.3.1...v1.4.0) (2026-09-18)

### Features

* **ci:** merge pypi publish wiring ([#12](https://github.com/foro-sh/pii-mcp/issues/12)) ([c957632](https://github.com/foro-sh/pii-mcp/commit/c957632deadb4f051dbeb3755a3bbfb63bc24562))
* **ci:** publish pii-mcp to PyPI on release ([bfc9790](https://github.com/foro-sh/pii-mcp/commit/bfc979064bb16534f5032feb22acd170ce29e0ac))

## [1.3.1](https://github.com/foro-sh/pii-mcp/compare/v1.3.0...v1.3.1) (2026-09-18)

### Bug Fixes

* **rust:** strip Unicode whitespace in validators ([1a45ba7](https://github.com/foro-sh/pii-mcp/commit/1a45ba7b38624f8824c83d59c2af00b63fca9a31))

### Performance Improvements

* **rust:** cut scrub allocs on hot path ([65e834b](https://github.com/foro-sh/pii-mcp/commit/65e834bfdfcec400fa465812dd99587a591742c2))

## [1.3.0](https://github.com/foro-sh/pii-mcp/compare/v1.2.0...v1.3.0) (2026-09-18)

### Features

* add optional Rust PII core with PyO3 bindings ([9e438ee](https://github.com/foro-sh/pii-mcp/commit/9e438ee967b02d5fe839d0210ed1bcb0a0da229f))
* merge optional Rust PII core with PyO3 bindings ([a7a9769](https://github.com/foro-sh/pii-mcp/commit/a7a9769cc800018fcd25a8fc3958d03f5dc58d55))

## [1.2.0](https://github.com/foro-sh/pii-mcp/compare/v1.1.0...v1.2.0) (2026-09-18)

### Features

* merge AP PII detector gaps ([73c1518](https://github.com/foro-sh/pii-mcp/commit/73c1518dec8d67fb123b781a3a74d9d7cc8aebf2))
* merge BIC and Dutch BTW-ids ([b60b530](https://github.com/foro-sh/pii-mcp/commit/b60b53073a7c9e78b17ae0cd16b6fafffa1fe166))
* scrub BIC/SWIFT and Dutch BTW-ids ([d0d0d4c](https://github.com/foro-sh/pii-mcp/commit/d0d0d4c2a926e127bc3c07a88d1dccdad07e14c8))
* scrub MAC, coordinates, and NL kentekens ([53e6310](https://github.com/foro-sh/pii-mcp/commit/53e6310f4a419daea9e15ad87f650edfa9924086))

## [1.1.0](https://github.com/foro-sh/pii-mcp/compare/v1.0.0...v1.1.0) (2026-09-18)

### Features

* scrub IP addresses and Dutch postcodes ([a6cd4e3](https://github.com/foro-sh/pii-mcp/commit/a6cd4e3c95dea9d9bf7d0650b1787af10d5ece78))
* scrub IP addresses and Dutch postcodes ([454559b](https://github.com/foro-sh/pii-mcp/commit/454559bb19d2c5d25187cb38bbb2d73964dcdff9))

## 1.0.0 (2026-09-18)

### Features

* add SSN, German tax ID, and de language pack ([7db095c](https://github.com/foro-sh/pii-mcp/commit/7db095c9699d6a2f042cb8bf89f25c70f33e4698))
* add Tier-1 PII scrubber + FastMCP middleware ([8028455](https://github.com/foro-sh/pii-mcp/commit/8028455b634a09bcb2264318217759840e7316e0)), closes [#1](https://github.com/foro-sh/pii-mcp/issues/1)

### Bug Fixes

* scrub meta/description and tighten IBAN/Amex matches ([e1ec738](https://github.com/foro-sh/pii-mcp/commit/e1ec7380759174f5a3ffc0a7fd1765710c4fc59b))

# Changelog

All notable changes to this project will be documented in this file.
