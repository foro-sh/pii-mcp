## [1.5.5](https://github.com/foro-sh/pii-mcp/compare/v1.5.4...v1.5.5) (2026-09-23)

### Bug Fixes

* **detectors:** accept 13-digit cards only with a visa prefix ([c616095](https://github.com/foro-sh/pii-mcp/commit/c6160958bdb2a65c3a1e5a1584ef016bf934ac4a))
* **detectors:** allow a label colon before ipv6 ([174a6c1](https://github.com/foro-sh/pii-mcp/commit/174a6c170c8a8eb0d4b091f127f5fe8a3687c10e))
* **detectors:** check kenteken letter rejects per group ([8ee7ce2](https://github.com/foro-sh/pii-mcp/commit/8ee7ce21afd11fad7ca6b8d1ca38753e80c7c8cb))
* **detectors:** cut grouped ibans back to the valid prefix ([9f4ccb2](https://github.com/foro-sh/pii-mcp/commit/9f4ccb292ee4842b3d03747715fc8b37e3e715bb))
* **detectors:** gate 17-19 digit cards on long-pan issuers ([2cb29ce](https://github.com/foro-sh/pii-mcp/commit/2cb29cecf833493facf65c3d13660f4f7a07172a))
* **detectors:** leave an unmatched opening paren outside phones ([4fc2895](https://github.com/foro-sh/pii-mcp/commit/4fc2895914bc7bc5791edaa6d6959a53a3afdcc4))
* **detectors:** require the registry length for each iban country ([2193da6](https://github.com/foro-sh/pii-mcp/commit/2193da63b4d8cbfc09719e36f0909b1eb6c46211))
* **detectors:** run national phone forms before bare-digit ids ([d937fde](https://github.com/foro-sh/pii-mcp/commit/d937fde461a7f7a0d786ade75c88070bd71a7d40))
* **detectors:** run nl btw-id before bsn ([12548cd](https://github.com/foro-sh/pii-mcp/commit/12548cd4bb8c8d011b37f385b62a76f4b7c160e3))
* **detectors:** skip decimal fractions in bsn and ssn ([f046256](https://github.com/foro-sh/pii-mcp/commit/f04625661aa266f5c918a461ca0158035ff8abae))
* **rust:** port detector fixes from python ([106966b](https://github.com/foro-sh/pii-mcp/commit/106966b9eb437b4c21ba411eaa55a1571fe06ec6))
* **typescript:** port detector fixes from python ([859da56](https://github.com/foro-sh/pii-mcp/commit/859da56e1f84dfc1387e8bfab354455a981d64fb))

## [1.5.4](https://github.com/foro-sh/pii-mcp/compare/v1.5.3...v1.5.4) (2026-09-23)

### Bug Fixes

* **python:** support fastmcp 4 in the middleware ([f6ab3ff](https://github.com/foro-sh/pii-mcp/commit/f6ab3ff2c1c0e9ac6ef4d89a92b79059abbedcf0))

## [1.5.3](https://github.com/foro-sh/pii-mcp/compare/v1.5.2...v1.5.3) (2026-09-23)

### Bug Fixes

* **credit-card:** add 19-digit and Diners groupings and issuer prefix gate ([7e7a411](https://github.com/foro-sh/pii-mcp/commit/7e7a4111ffc2b018f3d4ca886828787c791b28cc))
* **ip:** mask embedded-IPv4 IPv6 whole and IPv4 after a label colon ([06e5d5f](https://github.com/foro-sh/pii-mcp/commit/06e5d5f8f105505eca7c92ec977768aa90a497e9))
* **location:** skip sub-unit decimal pairs and trim trailing E/W in Rust ([37115aa](https://github.com/foro-sh/pii-mcp/commit/37115aa9c0158255a984611cf1e844f890aa1cef))
* **mac:** mask MAC addresses after a label colon ([cf12f0f](https://github.com/foro-sh/pii-mcp/commit/cf12f0fb816fb13f7af6fa898f2be93d451b28dd))

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
