# Ruby/Rails Gemfile Lockfile Boundary

**Status:** Implemented as the opt-in native control `SEC-RUBY-RAILS-GEMFILE-LOCK-001` version `0.1.0`.

## Purpose and authority boundary

Bundler documents `Gemfile` as an application dependency manifest and `Gemfile.lock` as the installed gem/version snapshot. Its guidance distinguishes directly deployed or run applications, for which it recommends committing the lockfile, from libraries consumed by other applications, for which it advises against committing one.[1] Rails lists `config/application.rb` as a standard application configuration location.[2]

> **Authority boundary:** This control contributes only a normalized finding or normalized execution state for its exact lexical file-presence condition. The versioned deterministic policy engine remains the sole release authority. The project profile, capability registry, domain contract, security analysis plan, coverage audit, and documentation remain diagnostic or descriptive and cannot independently alter a release decision.

## Exact detection contract

The control is selected only by `rules/ruby-rails-gemfile-lock-policy.yaml` and is compatible only when the bounded profile detects both `Ruby` and `Rails`. A finding exists only when every condition below is true.

| Static condition | Required observation |
|---|---|
| Root manifest | An inventory-included root `Gemfile` is present and readable as UTF-8. |
| Direct framework declaration | An unindented line has exactly the direct lexical form `gem 'rails'` or `gem "rails"`, optionally followed by a comma and same-line arguments. The arguments are not retained or interpreted. |
| Conventional application marker | An inventory-included root-relative `config/application.rb` exists. Its content is not read. |
| Missing evidence | No inventory-included root `Gemfile.lock` exists. |
| Finding result | One `SEC-RUBY-RAILS-GEMFILE-LOCK-001` finding at `Gemfile:1`, with constant evidence `ecosystem=bundler`, `framework=rails`, and `issue=gemfile_lock_missing`. |

A root `Gemfile.lock` prevents this **presence-only** finding even if the file is empty, malformed, stale, inconsistent, or otherwise unusable. The lockfile is never parsed or validated by this control.

## Non-applicability and errors

A missing root `Gemfile`, missing `config/application.rb`, or absent direct literal Rails declaration produces `NOT_APPLICABLE`. This deliberately excludes a Ruby library, a non-Rails project, a conditional/indented declaration, a group/source block, an alias, a dynamic declaration, a parenthesized call, a gemspec, or an unrecognized Rails layout.

An unreadable root `Gemfile` after the conventional application marker is observed produces `ERROR` with only `GEMFILE_UNREADABLE` or `GEMFILE_INVALID_ENCODING` metadata. The raw error, Gemfile content, dependency version, argument values, source text, lockfile content, command output, and secrets are discarded. A policy that requires this control then fails closed through the existing deterministic policy engine.

| Situation | Execution state | Finding from this control |
|---|---|---|
| Direct conventional Rails form; no root lockfile | `COMPLETED` | One normalized presence finding. |
| Direct conventional Rails form; root lockfile present | `COMPLETED` | None. |
| Conditional/indented, dynamic, library, or unsupported Rails form | `NOT_APPLICABLE` | None. |
| Conventional Rails form with unreadable root Gemfile | `ERROR` | None; a required policy selection fails closed. |

## Explicit exclusions

The control does **not** run Ruby, Bundler, Rails, Gemfile code, scripts, builds, tests, resolvers, downloads, registries, networks, or target commands. It does not inspect version values, groups, sources, dependency declarations beyond the exact literal marker, `Gemfile.lock` content, integrity, freshness, manifest-lock consistency, transitive dependencies, vulnerability status, provenance, Rails configuration, library/package classification, source reachability, runtime behavior, or deployment behavior.

A clean result means only that this one conventional root Rails form has a root file named `Gemfile.lock`; it is not evidence of Bundler integrity, reproducible dependency installation, absence of vulnerable gems, Rails security, runtime safety, production readiness, or compliance.

## Fixtures and reporting

The regression corpus includes a missing-lock fixture, a root-lock-present fixture, a conditional indented declaration excluded by contract, and a controlled unreadable-Gemfile unit error case. Integration coverage confirms opt-in `BLOCK`, default-policy isolation, `PASS`, one-to-one capability/contract mapping, catalog provenance, and redaction across JSON, Markdown, and SARIF.

Normalized reports contain only the fixed rule ID, execution state, relative finding location, and constant evidence. They do not retain Gemfile versions, arguments, arbitrary source text, raw errors, lockfile content, Ruby source, command output, or secrets.

## References

[1]: https://guides.rubygems.org/dependency_management/ "RubyGems Guides — How to manage dependencies with Bundler"
[2]: https://guides.rubyonrails.org/configuring.html "Rails Guides — Configuring Rails Applications"
