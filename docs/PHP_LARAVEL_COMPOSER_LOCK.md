# PHP/Laravel Composer Lockfile Boundary

**Status:** Implemented as the opt-in native control `SEC-PHP-LARAVEL-COMPOSER-LOCK-001` version `0.1.0`.

## Purpose and authority boundary

Composer documents `composer.json` as a dependency manifest and `composer.lock` as the record of the exact resolved dependency versions. Its application guidance recommends committing the lockfile so collaborators and deployment environments use the same dependency versions.[1] Laravel documents Composer as a prerequisite for a Laravel application.[2]

> **Authority boundary:** This control contributes one normalized finding only for its stated static file-presence condition. The versioned deterministic policy engine remains the sole release authority. Neither the capability registry, domain contract, project profile, coverage audit, nor this control can independently produce `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED`.

## Exact detection contract

The control is selected only by `rules/php-laravel-composer-lock-policy.yaml`. Its registered capability requires the deterministic project profile to contain both `PHP` and `Laravel`. Once selected, it creates a finding only when all required source conditions below are observed.

| Static condition | Required observation |
|---|---|
| Root manifest | An inventory-included root `composer.json` parses as a JSON object. |
| Direct framework declaration | The root object has a direct `require` JSON object containing exactly the `laravel/framework` key. The dependency value is not inspected. |
| Application marker | An inventory-included root file named `artisan` exists. Its content is not read. |
| Missing evidence | No inventory-included root `composer.lock` file exists. |
| Finding result | One `SEC-PHP-LARAVEL-COMPOSER-LOCK-001` finding at `composer.json:1`, with constant evidence `ecosystem=composer`, `framework=laravel`, and `issue=composer_lock_missing`. |

A root `composer.lock` suppresses this **presence-only** finding even if it is empty, malformed, stale, incompatible, or unrelated to the manifest. That behavior is deliberate: the control does not parse or validate the lockfile.

## Non-applicability and errors

A missing root manifest, missing `artisan`, missing direct `require`, or missing exact framework key returns `NOT_APPLICABLE`. This prevents a generic PHP project, a Composer library, a nested project, a `require-dev` declaration, or an unrecognized Laravel shape from becoming a finding merely because it lacks a root lockfile.

A root manifest that cannot be read, has invalid JSON, is not an object, or has a non-object `require` member returns an execution `ERROR` with only `COMPOSER_MANIFEST_UNREADABLE` or `COMPOSER_MANIFEST_INVALID` metadata. No parser message, source excerpt, dependency version, manifest field value, lockfile content, PHP source, command output, or secret is retained.

| Situation | Execution state | Finding from this control |
|---|---|---|
| Complete static Laravel shape; missing root lockfile | `COMPLETED` | One normalized lockfile-presence finding. |
| Complete static Laravel shape; root lockfile present | `COMPLETED` | None. |
| Composer/PHP or Laravel form outside the direct contract | `NOT_APPLICABLE` | None. |
| Selected static shape with unreadable or invalid manifest structure | `ERROR` | None; a required policy entry fails closed. |

## Explicit exclusions

The control does **not** execute PHP, Composer, Artisan, Composer scripts, package installation, dependency update, dependency resolution, build steps, application code, network requests, vulnerability scanners, or package registries. It does not infer or validate Composer values or constraints, `require-dev`, indirect dependencies, repositories, signatures, content hashes, lockfile contents, manifest-lock consistency, freshness, package vulnerabilities, SBOM/provenance, PHP extensions, Laravel configuration, nested/monorepo projects, symbolic links, effective deployment inputs, or runtime behavior.

Therefore, a clean result means only that this narrow root Laravel form has a root file named `composer.lock`; it is not evidence of dependency integrity, deterministic installation, absence of vulnerabilities, Laravel security, production readiness, or compliance.

## Fixtures and reporting

The regression corpus contains a missing-lock fixture, a root-lock-present fixture, an incomplete form without `artisan`, and an invalid manifest fixture. Integration tests prove default-policy isolation, explicit `BLOCK` only under the opt-in policy, `NOT_APPLICABLE` and `ERROR` boundaries, stable catalog/contract provenance, and redaction across JSON, Markdown, and SARIF reports.

The normalized reports may contain the fixed rule ID, execution state, relative finding location, and constant evidence fields. They do not contain the manifest's dependency values, arbitrary metadata, parser message, lockfile content, PHP source, or command output.

## References

[1]: https://getcomposer.org/doc/01-basic-usage.md "Composer — Basic usage"
[2]: https://laravel.com/docs/12.x/installation "Laravel — Installation"
