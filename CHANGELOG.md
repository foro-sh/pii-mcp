## [1.9.0](https://github.com/foro-sh/pii-mcp/compare/v1.8.1...v1.9.0) (2026-09-30)

### Features

* **python:** add a US ITIN detector to the en pack ([56f39c7](https://github.com/foro-sh/pii-mcp/commit/56f39c78196b4ff483e47f438f038c088591277e)), closes [#62](https://github.com/foro-sh/pii-mcp/issues/62)
* **rust:** mirror the US ITIN detector in pii-core ([f0323f8](https://github.com/foro-sh/pii-mcp/commit/f0323f8f2c8f03d70e98a923e36d6e71bede04b3)), closes [#62](https://github.com/foro-sh/pii-mcp/issues/62)
* **typescript:** mirror the US ITIN detector in the js backend ([aad506e](https://github.com/foro-sh/pii-mcp/commit/aad506ed114c8cd3f00b04388e7ea786fa6f44f9)), closes [#62](https://github.com/foro-sh/pii-mcp/issues/62)

## [1.10.0](https://github.com/foro-sh/pii-mcp/compare/v1.9.1...v1.10.0) (2026-10-09)


### Features

* **detectors:** add German VAT IDs across backends ([f50c3e5](https://github.com/foro-sh/pii-mcp/commit/f50c3e5b6d80d537578331653430533d2b10ec3b))
* **detectors:** detect German VAT IDs in de pack ([298104e](https://github.com/foro-sh/pii-mcp/commit/298104ebf60e9157d5d44c3115a20c13b0ca6749))
* **detectors:** detect UK National Insurance numbers ([#94](https://github.com/foro-sh/pii-mcp/issues/94)) ([541b375](https://github.com/foro-sh/pii-mcp/commit/541b3750efe2a3998f98a5801ce3a14f73fb2f4c)), closes [#60](https://github.com/foro-sh/pii-mcp/issues/60)
* **detectors:** detect UK National Insurance numbers in the en pack ([8a0aa4d](https://github.com/foro-sh/pii-mcp/commit/8a0aa4da23086efcebbe05a343a788940fa69eb4)), closes [#60](https://github.com/foro-sh/pii-mcp/issues/60)
* **detectors:** detect UK NHS numbers in the en pack ([19ec28c](https://github.com/foro-sh/pii-mcp/commit/19ec28cd7aeaaada94430a12f15de8bbfe7e76d7)), closes [#61](https://github.com/foro-sh/pii-mcp/issues/61)
* match street addresses with a comma before the house number ([a4f5fe5](https://github.com/foro-sh/pii-mcp/commit/a4f5fe5bd2ad02080e6e59165f43b00d4ffdd8ea))
* match street addresses with a comma before the house number ([c9cef47](https://github.com/foro-sh/pii-mcp/commit/c9cef47acfbf6e8509d0a0d8bef916480ee5b024))
* **python:** ship py.typed metadata ([f19ce08](https://github.com/foro-sh/pii-mcp/commit/f19ce08164281953398dea69890af65b3dfab783))
* **python:** ship py.typed metadata ([2d3eb41](https://github.com/foro-sh/pii-mcp/commit/2d3eb4190aed03a1920033997119040ad954f169))


### Bug Fixes

* **python:** build packaging test wheel with pip ([f902d8d](https://github.com/foro-sh/pii-mcp/commit/f902d8dcf2944989bc30a5c291bfe60080e79a7c))
* **rust:** honor Unicode word boundaries for IPs ([f9c9900](https://github.com/foro-sh/pii-mcp/commit/f9c9900748619276f7afaff716ecab0ce8907d8a))

## [1.9.1](https://github.com/foro-sh/pii-mcp/compare/v1.9.0...v1.9.1) (2026-10-01)


### Bug Fixes

* **release:** resync Cargo.lock when the version is stamped ([6bb0d07](https://github.com/foro-sh/pii-mcp/commit/6bb0d07e22f1c916928c95e92676b7c8d2191128))

## [1.8.1](https://github.com/foro-sh/pii-mcp/compare/v1.8.0...v1.8.1) (2026-09-30)

### Bug Fixes

* make the Python and Rust backends agree on three inputs ([386160b](https://github.com/foro-sh/pii-mcp/commit/386160b848b50eb5f41c0b43d542388126dfa37f))
* **typescript:** retry rejected IBAN candidates like Python and Rust ([532eecc](https://github.com/foro-sh/pii-mcp/commit/532eecc6e52e2ce8cf9a41bf22ed091ca9819579))

## [1.8.0](https://github.com/foro-sh/pii-mcp/compare/v1.7.1...v1.8.0) (2026-09-29)

### Features

* merge UK postcode detector for the en pack ([#70](https://github.com/foro-sh/pii-mcp/issues/70)) ([7287407](https://github.com/foro-sh/pii-mcp/commit/72874077b2e63354a4f138c71033ec0a2e848b52)), closes [#58](https://github.com/foro-sh/pii-mcp/issues/58)
* **python:** add a UK postcode detector to the en pack ([f38eb65](https://github.com/foro-sh/pii-mcp/commit/f38eb65179be4a96b6e20f421ad213812235be7a))
* **rust:** mirror the UK postcode detector in pii-core ([0cb7da7](https://github.com/foro-sh/pii-mcp/commit/0cb7da7a9de411efa286503a939d84f7f0533597))
* **typescript:** mirror the UK postcode detector in the js backend ([0027539](https://github.com/foro-sh/pii-mcp/commit/0027539d4778e30f9d03bac1573f918579ebca6d))

### Bug Fixes

* **rust:** keep uk_postcode_valid crate-private ([be1fb51](https://github.com/foro-sh/pii-mcp/commit/be1fb51792af75260984fd6f2400237c254227e7))

## [1.7.1](https://github.com/foro-sh/pii-mcp/compare/v1.7.0...v1.7.1) (2026-09-28)

### Bug Fixes

* **python:** bump pyo3 to 0.29 for GHSA-36hh-v3qg-5jq4 ([89cb91b](https://github.com/foro-sh/pii-mcp/commit/89cb91b2aaf5cd4a33cbdc9c1162bb2fe8d8f9f7))

## [1.7.0](https://github.com/foro-sh/pii-mcp/compare/v1.6.0...v1.7.0) (2026-09-28)

### Features

* **detectors:** detect street and house number addresses ([a0e5fe4](https://github.com/foro-sh/pii-mcp/commit/a0e5fe43483fc693615d2789af2d4938e4a6bef8)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* expose ner option in the Python and TypeScript APIs ([786f134](https://github.com/foro-sh/pii-mcp/commit/786f13468c8adda643c6b601c8c6537c95bbcbe1)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **rust:** add optional ner feature for person names ([c60cdf9](https://github.com/foro-sh/pii-mcp/commit/c60cdf9eab7b593a0f89a77478dc811ba88b200a)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)

### Bug Fixes

* **detectors:** accept Nr. before house numbers and more EN street types ([719fbca](https://github.com/foro-sh/pii-mcp/commit/719fbcace3ad318bbb936654b0d163704703aced)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **detectors:** drop street suffixes that end common words ([f32e10f](https://github.com/foro-sh/pii-mcp/commit/f32e10f7e61ea612729a3582736427333931f198)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **detectors:** limit Dutch street adjectives and accept Kerkstr ([59a28c2](https://github.com/foro-sh/pii-mcp/commit/59a28c298a27d25cb9383277577de0fed6d5a08c)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **detectors:** match spaced and Laan-van Dutch streets and -ring ([5c694dc](https://github.com/foro-sh/pii-mcp/commit/5c694dc7c583e200339abe59cd1372bbdf7fe6cf)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **detectors:** restore the pad, hof, markt and ufer street suffixes ([e5559b8](https://github.com/foro-sh/pii-mcp/commit/e5559b8721f1d1fe96bd303a931a3abb987134ba)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **detectors:** skip German function words and widen street spacing ([0579400](https://github.com/foro-sh/pii-mcp/commit/05794006c1dd4ea0f17741cdcbb7d79ed80e5618)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* give one build hint when ner is unavailable ([955930e](https://github.com/foro-sh/pii-mcp/commit/955930eea4cc55dee2cdf72279b1b4fab22a9501)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **rust:** join low-scored surname tokens to the name before them ([aef7296](https://github.com/foro-sh/pii-mcp/commit/aef729636e72960953b4f07b8099e3be34b08b5f)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **rust:** keep names around placeholders in the NER pass ([d6a48aa](https://github.com/foro-sh/pii-mcp/commit/d6a48aacaad906cdd065a9a10dc80ee8775fbbcb)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)
* **rust:** stop widening person spans into unspaced scripts ([34c2a4e](https://github.com/foro-sh/pii-mcp/commit/34c2a4e76d6511ba13de2fc4e9d376338109b108)), closes [#32](https://github.com/foro-sh/pii-mcp/issues/32)

## [1.6.0](https://github.com/foro-sh/pii-mcp/compare/v1.5.5...v1.6.0) (2026-09-27)

### Features

* **detectors:** catch more PII formats ([#31](https://github.com/foro-sh/pii-mcp/issues/31)) ([91b1396](https://github.com/foro-sh/pii-mcp/commit/91b1396e3178e5edd342885993c1f9784ca0b04e))
* **detectors:** match dash-grouped mac addresses ([1db108f](https://github.com/foro-sh/pii-mcp/commit/1db108f2cc840c9fafa0a814cfe31b1c749cd70c))
* **detectors:** match degrees-minutes-seconds coordinates ([e620c26](https://github.com/foro-sh/pii-mcp/commit/e620c26d2be64be9649df07608136d5e7188e817))
* **detectors:** match grouped german tax ids ([3d9d9c1](https://github.com/foro-sh/pii-mcp/commit/3d9d9c17c3f4ed1705dd6700e87ae35c823642f7))
* **detectors:** match internationalized email addresses ([dcf30ba](https://github.com/foro-sh/pii-mcp/commit/dcf30ba50b7e65bb72d90b1d0bdd89e87560f619))

### Bug Fixes

* **detectors:** accept unicode separators in bsn and ssn groups ([60ff7e7](https://github.com/foro-sh/pii-mcp/commit/60ff7e7e81837d749813a6f64e7ce8c6105bb831))
* **detectors:** allow line breaks and thin spaces in dms pairs ([5a5eb63](https://github.com/foro-sh/pii-mcp/commit/5a5eb631b1fa5ef2343c69f6f2ffc71ff80a3eae))
* **detectors:** cover more unspaced scripts after an email ([6f5494a](https://github.com/foro-sh/pii-mcp/commit/6f5494afe1c239027ac8982689b62bb68f26c733))
* **detectors:** keep 0-led subscriber groups in international phones ([f89fc62](https://github.com/foro-sh/pii-mcp/commit/f89fc620644b55ec977cca8aace5a7cd10d80597))
* **detectors:** keep emails in unspaced-script prose masked ([391d88e](https://github.com/foro-sh/pii-mcp/commit/391d88e3fd24d48b8cd912c66681f150182791d1))
* **detectors:** mask a dash-grouped mac before a sentence period ([af0e49f](https://github.com/foro-sh/pii-mcp/commit/af0e49fcab4c1517888faf5056d8bab04c041b29))
* **detectors:** mask a phone run past 15 digits whole ([4f75076](https://github.com/foro-sh/pii-mcp/commit/4f75076b7c628bc318573d412f783fd0194ac690))
* **detectors:** mask an email when no clean end is found ([da4d5d6](https://github.com/foro-sh/pii-mcp/commit/da4d5d6df39a83d687dbd9a342a8df837c9cdc79))
* **detectors:** mask mixed-script email local parts whole ([d93c679](https://github.com/foro-sh/pii-mcp/commit/d93c679c50626b8ccb6fecdfb099ad960543a574))
* **detectors:** mask phones with unicode separators and a (0) trunk ([c5308ae](https://github.com/foro-sh/pii-mcp/commit/c5308aeccf25891e04bef41c12024377d2a9f450))
* **detectors:** match dms pairs alike in every backend ([401df5f](https://github.com/foro-sh/pii-mcp/commit/401df5f220ad80b1f633bf56a18232c435da74f6))
* **detectors:** match python's tld chars in rust and js ([f5b82bf](https://github.com/foro-sh/pii-mcp/commit/f5b82bfe2a076cb7f32c75512a6d2ae1b06795b4))
* **detectors:** read dms coordinates with ascii digits only ([936ca43](https://github.com/foro-sh/pii-mcp/commit/936ca438b451f8dfbeeffea58d9ef860f19b34c9))
* **detectors:** scan a phone run to its end, not a 64-char window ([8c96271](https://github.com/foro-sh/pii-mcp/commit/8c9627174c78fcba663dc268d4dc8c3a14cd53a1))
* **detectors:** split back-to-back international phones at groups ([2a68c9f](https://github.com/foro-sh/pii-mcp/commit/2a68c9f2683fc3fc613518ded6bdb498cd18d4c4))
* **detectors:** walk email ends by whole letters in rust and js ([4ac3645](https://github.com/foro-sh/pii-mcp/commit/4ac3645583bafe19596813435d1cfc2e87b9d979))
* **python:** use ascii word boundaries for dash-grouped macs ([4851d1f](https://github.com/foro-sh/pii-mcp/commit/4851d1f8c0687c11c6b6020cee47b746473f2555))
* **rust:** backtrack any optional tail of a decimal location ([4f9314e](https://github.com/foro-sh/pii-mcp/commit/4f9314eef8f3546087605eee3bd10700e0d7ae71))
* **rust:** emulate python's (?!@) inside the email regex ([b9638af](https://github.com/foro-sh/pii-mcp/commit/b9638aff42435edb66c983a853e527c0e2a6cbfc))
* **rust:** keep public id validators to their separator rules ([63bb4c6](https://github.com/foro-sh/pii-mcp/commit/63bb4c6f8d19dd27913c900d280b78610aa46c3a))

### Performance Improvements

* **detectors:** anchor the email match at each local-part start ([4f02b16](https://github.com/foro-sh/pii-mcp/commit/4f02b160b3bb9b03eba3e44b1827d865130d6c1b))
* **detectors:** cap the email shortening walk at 128 chars ([640b95f](https://github.com/foro-sh/pii-mcp/commit/640b95f1a48b41d5962c37b4a876dd3899a4c64d))
* **rust:** backtrack a decimal location by its two optional tails ([177c463](https://github.com/foro-sh/pii-mcp/commit/177c4632530b9b71ccc68d9e28677d7bec44101a))
* **rust:** read the email span without captures on most hits ([7692e50](https://github.com/foro-sh/pii-mcp/commit/7692e504c7e616b771214e20bfbf9bd77a726d1a))
* **rust:** stop re-walking an email that ends before an "@" ([3594c24](https://github.com/foro-sh/pii-mcp/commit/3594c24617390809f11f96bef7348f6c7fc86b35))
* **rust:** validate tax ids without allocating ([3d72759](https://github.com/foro-sh/pii-mcp/commit/3d72759c32291215e892845fae27edd8d448847f))

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
