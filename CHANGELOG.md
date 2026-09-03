<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# LDAP Injection Sink Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Hand-written RFC 4515 LDAP filter tokenizer/parser (this catalog's
  fourth full custom grammar, prefix/Polish notation).
- Same-method taint detection from an HTTP endpoint parameter to
  `DirContext.search(...)` (CWE-90), with the grammar used to validate
  the argument's static skeleton parses as a well-formed filter before
  flagging.

[Unreleased]: https://github.com/GapHunterLabs/ldap-injection-sink-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/ldap-injection-sink-companion/commits/0.1.0
