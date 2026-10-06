<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# LDAP Injection Sink Companion Changelog

## [Unreleased]

### Added

- A description page for the inspection in **Settings | Editor |
  Inspections**, which showed "Under construction".

### Changed

- The rating prompt's local counter keeps one-way fingerprints of findings
  instead of their file paths, and deletes the list that earlier versions
  kept.
- `PRIVACY.md` describes the values the plugin keeps in the IDE's local
  settings.

## [0.1.1]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.1.0]

### Added

- Hand-written RFC 4515 LDAP filter tokenizer/parser (this catalog's
  fourth full custom grammar, prefix/Polish notation).
- Same-method taint detection from an HTTP endpoint parameter to
  `DirContext.search(...)` (CWE-90), with the grammar used to validate
  the argument's static skeleton parses as a well-formed filter before
  flagging.

[Unreleased]: https://github.com/GapHunterLabs/ldap-injection-sink-companion/compare/0.1.1...HEAD
[0.1.1]: https://github.com/GapHunterLabs/ldap-injection-sink-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/ldap-injection-sink-companion/commits/0.1.0
