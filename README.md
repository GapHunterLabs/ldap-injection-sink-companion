# LDAP Injection Sink Companion

Flags a `DirContext.search(...)` call whose filter argument is built
from an HTTP endpoint parameter.

## Why it exists

CWE-90 (LDAP Injection): an attacker's raw input becomes LDAP filter
SOURCE TEXT, re-parsed by the directory server. CodeQL and Datadog Code
Security have their own rules for this category -- batch/CI or
enterprise-SAST-only. No dedicated Marketplace plugin found.

## Why built this way

- **A real hand-written RFC 4515 LDAP filter parser** -- the FOURTH
  full custom grammar in this catalog, after regex
  (`redos-catastrophic-backtracking-companion`), SpEL
  (`spel-injection-sink-companion`), and XPath
  (`xpath-injection-sink-companion`). LDAP filters are fully PREFIX/
  Polish notation (`(&(a=1)(b=2))`, the operator comes BEFORE its
  operands) with no infix operators and no precedence at all -- a
  structurally distinct parsing shape from all three prior grammars,
  not a minor variation.
- **Taint alone is the vulnerability, flagged unconditionally** -- same
  reasoning as the SpEL/XPath plugins: the attacker controls the
  substituted text's shape.
- **The grammar's real job is noise reduction** -- confirms the
  argument's static skeleton (tainted operand replaced by a
  placeholder) parses as a well-formed filter before flagging, never a
  security gate.

## v0.1 scope — stated honestly, not exhaustively

- Only Java; only same-method taint (a direct reference, or a `+`
  concatenation of literals and tainted references).
- `looksLikeDirContext` is a declared-type-TEXT heuristic, never
  resolved against the real `javax.naming` classpath.
- The grammar supports `&`/`|`/`!` and simple `attr<op>value` items
  (`=`, `~=`, `>=`, `<=`) -- extensible match filters (`attr:dn:=`)
  aren't specially parsed (treated as a leaf item's raw value text,
  which still validates the overall structure correctly).

## Usage

Open a Java file with a Spring MVC/JAX-RS endpoint method that builds
an LDAP filter from a request parameter -- the `search(...)` call shows
a warning.

## Enterprise / Team Licensing

Need enterprise features, custom rules, or team licensing? Contact us at
**gaphunterlabs@gmail.com**.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
