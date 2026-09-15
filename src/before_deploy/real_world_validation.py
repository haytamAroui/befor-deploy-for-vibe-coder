"""Multi-repository real-world blinded validation for Before Deploy.

This module evaluates the evidence required by section 3 of
``docs/PRODUCTION_READINESS_CRITERIA.md``: a blinded benchmark over frozen pre-fix snapshots from
at least three unrelated public repositories containing at least six independently documented
historical defects.

It reuses the frozen corpus provenance contract in ``before_deploy.review_benchmark_corpus`` for
every repository instead of defining a parallel one, and it adds the multi-repository aggregation,
identifier-opacity, and blinding checks that §3 requires.

Every value produced here is ``BENCHMARK_DIAGNOSTIC`` evidence with ``gate_effect=NONE``. It never
grants advisory output deterministic release authority, and it never changes release disposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps, loads
from pathlib import Path, PurePosixPath
from re import compile as compile_pattern, fullmatch
from typing import Any, Callable, Iterable, Mapping, Sequence

from before_deploy.review_benchmark import load_benchmark_corpus
from before_deploy.review_benchmark_corpus import (
    BenchmarkCorpusValidation,
    validate_benchmark_corpus_provenance,
)

REAL_WORLD_VALIDATION_SCHEMA = "before-deploy-real-world-validation-v1"
REAL_WORLD_RUN_SCHEMA = "before-deploy-real-world-run-v1"
REAL_WORLD_AUTHORITY = "BENCHMARK_DIAGNOSTIC"
REAL_WORLD_GATE_EFFECT = "NONE"

MIN_REAL_WORLD_REPOSITORIES = 3
MIN_REAL_WORLD_KNOWN_DEFECTS = 6
MIN_REAL_WORLD_RECALL = 0.60

STATIC_ROLE = "STATIC"
EXPLORATORY_ROLE = "EXPLORATORY"
_ALLOWED_ROLES = {STATIC_ROLE, EXPLORATORY_ROLE}

# Model-visible payload keys. Anything outside this set is evaluator-only material and must not
# reach a provider, which is what keeps expected locations out of the reviewer's input.
VISIBLE_EVIDENCE_KEYS = frozenset(
    {
        "content",
        "content_sha256",
        "evidence_id",
        "path",
        "source_end_line",
        "source_start_line",
    }
)

_OBSERVATION_KEYS = frozenset(
    {
        "detected_defect_ids",
        "exploration_attributable_fp",
        "exploration_attributable_tp",
        "false_positive_count",
        "uncited_credit_count",
    }
)
_OPAQUE_REPOSITORY_ID = r"[A-Z]{2}-[0-9A-Z]{4}"
_OPAQUE_DEFECT_ID = r"[A-Z]{1,3}-[0-9A-Z]{3,}"
_LEAKAGE_PATTERNS = (
    ("cve", compile_pattern(r"[Cc][Vv][Ee]-\d{4}-\d{4,}")),
    ("ghsa", compile_pattern(r"[Gg][Hh][Ss][Aa]-[0-9a-z]{4,}")),
    ("advisory_url", compile_pattern(r"https?://(?:www\.)?(?:nvd\.nist\.gov|github\.com/[^/\s]+/[^/\s]+/security)")),
)


@dataclass(frozen=True)
class RealWorldRepositoryProof:
    """One frozen upstream repository snapshot with its validated corpus provenance."""

    repository_id: str
    repository: str
    commit: str
    upstream_revision: str
    corpus: str
    positive_file_count: int
    negative_file_count: int
    known_defects: int

    @property
    def reviewed_file_count(self) -> int:
        return self.positive_file_count + self.negative_file_count


@dataclass(frozen=True)
class RealWorldValidationDefinition:
    """Aggregated, provenance-validated definition of one real-world validation corpus."""

    name: str
    repositories: tuple[RealWorldRepositoryProof, ...]
    defect_ids: tuple[str, ...]
    blinded: bool
    independent: bool
    schema_version: str = REAL_WORLD_VALIDATION_SCHEMA

    @property
    def repository_count(self) -> int:
        return len(self.repositories)

    @property
    def known_defects(self) -> int:
        return len(self.defect_ids)

    @property
    def reviewed_file_count(self) -> int:
        return sum(item.reviewed_file_count for item in self.repositories)


@dataclass(frozen=True)
class RealWorldVariantObservation:
    """Recorded outcome of one variant across every repository in the validation set."""

    variant_role: str
    detected_defect_ids: tuple[str, ...]
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    false_positive_count: int
    uncited_credit_count: int = 0


@dataclass(frozen=True)
class RealWorldValidationResult:
    """Aggregate §3 evaluation over the paired static and exploratory variants."""

    name: str
    decision: str
    reason_codes: tuple[str, ...]
    repository_count: int
    known_defects: int
    detected_defects: int
    recall: float
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    static_false_positive_rate: float
    exploratory_false_positive_rate: float
    blinded: bool
    independent: bool
    gate_effect: str = REAL_WORLD_GATE_EFFECT
    authority: str = REAL_WORLD_AUTHORITY
    schema_version: str = REAL_WORLD_VALIDATION_SCHEMA


def validate_real_world_benchmark(
    manifest_path: Path,
    repository_root: Path,
    *,
    provenance_validator: Callable[
        [Path, Path, Path], BenchmarkCorpusValidation
    ] = validate_benchmark_corpus_provenance,
) -> RealWorldValidationDefinition:
    """Validate every pinned repository snapshot and derive the aggregate §3 definition."""
    root = repository_root.resolve()
    manifest = _load_mapping(manifest_path, "real-world validation manifest")
    if manifest.get("schema_version") != REAL_WORLD_VALIDATION_SCHEMA:
        raise ValueError("Unsupported real-world validation manifest schema")
    validation = _required_mapping(manifest, "validation")
    name = _required_text(validation, "name")
    raw_repositories = validation.get("repositories")
    if not isinstance(raw_repositories, list) or not raw_repositories:
        raise ValueError("Real-world validation repositories must be a non-empty array")

    repositories: list[RealWorldRepositoryProof] = []
    defect_ids: list[str] = []
    seen_ids: set[str] = set()
    seen_repositories: set[str] = set()
    seen_upstream_revisions: set[str] = set()
    for index, raw in enumerate(raw_repositories):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Real-world validation repository {index + 1} must be an object")
        repository_id = _required_text(raw, "repository_id")
        if fullmatch(_OPAQUE_REPOSITORY_ID, repository_id) is None:
            raise ValueError(
                f"Real-world validation repository id must be opaque {_OPAQUE_REPOSITORY_ID}: "
                f"{repository_id!r}"
            )
        if repository_id in seen_ids:
            raise ValueError(f"Duplicate real-world validation repository id: {repository_id}")
        seen_ids.add(repository_id)

        repository = _required_text(raw, "repository")
        if not repository.startswith("https://"):
            raise ValueError(
                f"Real-world validation repository must be an https source of record: {repository!r}"
            )
        if repository in seen_repositories:
            raise ValueError(f"Duplicate real-world validation repository: {repository}")
        seen_repositories.add(repository)

        commit = _required_text(raw, "commit").lower()
        if fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise ValueError(
                f"Real-world validation repository {repository_id} commit must be a full "
                "40-character Git SHA"
            )
        # Several snapshots may be vendored by one local commit, so snapshot commits are allowed to
        # coincide. Independence is an upstream property and is enforced on the upstream revision.
        upstream_revision = _required_text(raw, "upstream_revision")
        if upstream_revision in seen_upstream_revisions:
            raise ValueError(
                f"Duplicate real-world validation upstream revision: {upstream_revision}"
            )
        seen_upstream_revisions.add(upstream_revision)

        corpus_path = _resolve_declared_file(root, _required_text(raw, "corpus"), "corpus")
        provenance_path = _resolve_declared_file(
            root, _required_text(raw, "provenance"), "provenance"
        )
        _resolve_declared_file(root, _required_text(raw, "license_notice"), "license notice")

        proof = provenance_validator(corpus_path, provenance_path, root)
        if proof.source_commit != commit:
            raise ValueError(
                f"Real-world validation repository {repository_id} declares commit {commit}, but "
                f"its provenance manifest validates {proof.source_commit}"
            )
        corpus = load_benchmark_corpus(corpus_path)
        if proof.name != corpus.name:
            raise ValueError(
                f"Real-world validation repository {repository_id} provenance does not describe "
                "its declared corpus"
            )

        repository_defect_ids = [defect.defect_id for defect in corpus.defects]
        if len(repository_defect_ids) != proof.defect_count:
            raise ValueError(
                f"Real-world validation repository {repository_id} corpus defect count does not "
                "match its validated provenance"
            )
        for defect_id in repository_defect_ids:
            if fullmatch(_OPAQUE_DEFECT_ID, defect_id) is None:
                raise ValueError(
                    f"Real-world validation defect id must be opaque {_OPAQUE_DEFECT_ID}: "
                    f"{defect_id!r}"
                )
            if defect_id in defect_ids:
                raise ValueError(
                    f"Real-world validation defect ids must be globally unique: {defect_id}"
                )
            defect_ids.append(defect_id)

        repositories.append(
            RealWorldRepositoryProof(
                repository_id=repository_id,
                repository=repository,
                commit=commit,
                upstream_revision=upstream_revision,
                corpus=corpus_path.relative_to(root).as_posix(),
                positive_file_count=proof.positive_file_count,
                negative_file_count=proof.negative_file_count,
                known_defects=proof.defect_count,
            )
        )

    distinct_repositories = len(seen_repositories)
    independent = (
        distinct_repositories >= MIN_REAL_WORLD_REPOSITORIES
        and len(repositories) == distinct_repositories
        and len(seen_upstream_revisions) == len(repositories)
        and len(defect_ids) == len(set(defect_ids))
    )
    blinded = all(
        _identifier_is_opaque(item.repository_id, item.repository) for item in repositories
    )
    return RealWorldValidationDefinition(
        name=name,
        repositories=tuple(repositories),
        defect_ids=tuple(defect_ids),
        blinded=blinded,
        independent=independent,
    )


def assert_model_visible_payload_is_blinded(
    payload: Any,
    *,
    forbidden_tokens: Iterable[str] = (),
) -> None:
    """Fail closed when a provider payload carries evaluator-only material.

    The caller must pass every evaluator-only token it holds, such as advisory identifiers, fix
    commits, expected locations, label text, and repository names. A payload that fails this check
    makes the run contaminated and it must not be reported as a valid §3 result.
    """
    serialized = dumps(payload, sort_keys=True, ensure_ascii=False)
    for token in forbidden_tokens:
        if token and token in serialized:
            raise ValueError("Real-world validation payload leaks an evaluator-only token")
    for label, pattern in _LEAKAGE_PATTERNS:
        if pattern.search(serialized):
            raise ValueError(f"Real-world validation payload leaks a {label} identifier")
    _assert_visible_keys(payload)


def load_real_world_run(
    path: Path,
) -> tuple[RealWorldVariantObservation, RealWorldVariantObservation]:
    """Load one paired static/exploratory observation record for a real-world run."""
    payload = _load_mapping(path, "real-world run record")
    if payload.get("schema_version") != REAL_WORLD_RUN_SCHEMA:
        raise ValueError("Unsupported real-world run record schema")
    observations: dict[str, RealWorldVariantObservation] = {}
    for role in (STATIC_ROLE, EXPLORATORY_ROLE):
        key = role.lower()
        raw = payload.get(key)
        if not isinstance(raw, Mapping):
            raise ValueError(f"Real-world run record requires a {key} object")
        unexpected = sorted(set(raw) - _OBSERVATION_KEYS)
        if unexpected:
            raise ValueError(
                f"Real-world run record {key} object has unsupported fields: "
                + ",".join(str(item) for item in unexpected)
            )
        raw_ids = raw.get("detected_defect_ids")
        if not isinstance(raw_ids, list) or not all(
            isinstance(item, str) and item.strip() for item in raw_ids
        ):
            raise ValueError(
                f"Real-world run record {key} detected_defect_ids must be an array of text"
            )
        observations[role] = RealWorldVariantObservation(
            variant_role=role,
            detected_defect_ids=tuple(item.strip() for item in raw_ids),
            exploration_attributable_tp=_count(raw, "exploration_attributable_tp", key),
            exploration_attributable_fp=_count(raw, "exploration_attributable_fp", key),
            false_positive_count=_count(raw, "false_positive_count", key),
            uncited_credit_count=_count(raw, "uncited_credit_count", key),
        )
    return observations[STATIC_ROLE], observations[EXPLORATORY_ROLE]


def evaluate_real_world_validation(
    definition: RealWorldValidationDefinition,
    *,
    static: RealWorldVariantObservation,
    exploratory: RealWorldVariantObservation,
) -> RealWorldValidationResult:
    """Evaluate the frozen §3 criteria for one paired real-world run."""
    if static.variant_role != STATIC_ROLE or exploratory.variant_role != EXPLORATORY_ROLE:
        raise ValueError("Real-world validation requires one STATIC and one EXPLORATORY variant")
    known = set(definition.defect_ids)
    for observation in (static, exploratory):
        _validate_observation(observation, known)

    if definition.reviewed_file_count <= 0:
        raise ValueError("Real-world validation requires at least one reviewed file")

    detected = tuple(sorted(known & set(exploratory.detected_defect_ids)))
    recall = len(detected) / len(known) if known else 0.0
    static_fp_rate = static.false_positive_count / definition.reviewed_file_count
    exploratory_fp_rate = exploratory.false_positive_count / definition.reviewed_file_count

    reasons: list[str] = []
    if definition.repository_count < MIN_REAL_WORLD_REPOSITORIES:
        reasons.append("INSUFFICIENT_REAL_WORLD_REPOSITORIES")
    if definition.known_defects < MIN_REAL_WORLD_KNOWN_DEFECTS:
        reasons.append("INSUFFICIENT_REAL_WORLD_DEFECTS")
    if recall < MIN_REAL_WORLD_RECALL:
        reasons.append("INSUFFICIENT_REAL_WORLD_RECALL")
    if exploratory.exploration_attributable_tp <= exploratory.exploration_attributable_fp:
        reasons.append("REAL_WORLD_EXPLORATION_TP_NOT_GREATER_THAN_FP")
    if exploratory_fp_rate > static_fp_rate:
        reasons.append("REAL_WORLD_FALSE_POSITIVE_RATE_REGRESSED")
    if static.uncited_credit_count or exploratory.uncited_credit_count:
        reasons.append("REAL_WORLD_CREDITED_FINDING_WITHOUT_CITED_EVIDENCE")
    if not definition.blinded:
        reasons.append("REAL_WORLD_BENCHMARK_NOT_BLINDED")
    if not definition.independent:
        reasons.append("REAL_WORLD_BENCHMARK_NOT_INDEPENDENT")

    return RealWorldValidationResult(
        name=definition.name,
        decision="PASS" if not reasons else "FAIL",
        reason_codes=tuple(reasons),
        repository_count=definition.repository_count,
        known_defects=definition.known_defects,
        detected_defects=len(detected),
        recall=recall,
        exploration_attributable_tp=exploratory.exploration_attributable_tp,
        exploration_attributable_fp=exploratory.exploration_attributable_fp,
        static_false_positive_rate=static_fp_rate,
        exploratory_false_positive_rate=exploratory_fp_rate,
        blinded=definition.blinded,
        independent=definition.independent,
    )


def real_world_readiness_evidence(result: RealWorldValidationResult) -> dict[str, Any]:
    """Project a §3 result onto the frozen production-readiness evidence fields.

    Operators must populate readiness evidence from this projection rather than asserting the
    real-world fields by hand.
    """
    return {
        "real_world_repository_count": result.repository_count,
        "real_world_known_defects": result.known_defects,
        "real_world_detected_defects": result.detected_defects,
        "real_world_exploration_attributable_tp": result.exploration_attributable_tp,
        "real_world_exploration_attributable_fp": result.exploration_attributable_fp,
        "real_world_static_false_positive_rate": result.static_false_positive_rate,
        "real_world_exploratory_false_positive_rate": result.exploratory_false_positive_rate,
        "real_world_blinded": result.blinded,
        "real_world_independent": result.independent,
    }


def render_real_world_validated_json(result: RealWorldValidationResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "real_world_validation": {
            "authority": result.authority,
            "decision": result.decision,
            "detected_defects": result.detected_defects,
            "exploration_attributable_fp": result.exploration_attributable_fp,
            "exploration_attributable_tp": result.exploration_attributable_tp,
            "exploratory_false_positive_rate": result.exploratory_false_positive_rate,
            "gate_effect": result.gate_effect,
            "known_defects": result.known_defects,
            "name": result.name,
            "reason_codes": list(result.reason_codes),
            "recall": result.recall,
            "repository_count": result.repository_count,
            "static_false_positive_rate": result.static_false_positive_rate,
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_real_world_validated_markdown(result: RealWorldValidationResult) -> str:
    lines = [
        "# Before Deploy Independent Real-World Validation",
        "",
        f"- Validation: `{result.name}`",
        f"- Decision: **{result.decision}**",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        f"- Frozen repositories: **{result.repository_count}**",
        f"- Known / detected defects: **{result.detected_defects} / {result.known_defects}**",
        f"- Exploratory known-defect recall: **{result.recall:.4f}**",
        (
            "- Exploration-attributable TP / FP: "
            f"**{result.exploration_attributable_tp} / {result.exploration_attributable_fp}**"
        ),
        (
            "- False-positive rate (static / exploratory): "
            f"**{result.static_false_positive_rate:.4f} / "
            f"{result.exploratory_false_positive_rate:.4f}**"
        ),
        f"- Blinded / independent: **{result.blinded} / {result.independent}**",
        "",
        "## Reasons",
        "",
    ]
    if result.reason_codes:
        lines.extend(f"- `{reason}`" for reason in result.reason_codes)
    else:
        lines.append("- Every frozen §3 criterion passed.")
    lines.extend(
        [
            "",
            "> Real-world validation is a diagnostic. It never grants advisory findings release authority.",
        ]
    )
    return "\n".join(lines) + "\n"


def _validate_observation(
    observation: RealWorldVariantObservation, known: set[str]
) -> None:
    if observation.variant_role not in _ALLOWED_ROLES:
        raise ValueError("Real-world validation variant role must be STATIC or EXPLORATORY")
    for name in (
        "exploration_attributable_tp",
        "exploration_attributable_fp",
        "false_positive_count",
        "uncited_credit_count",
    ):
        value = getattr(observation, name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Real-world validation {name} must be a non-negative integer")
    unknown = sorted(set(observation.detected_defect_ids) - known)
    if unknown:
        raise ValueError(
            "Real-world validation detected defects must belong to the frozen corpus: "
            + ",".join(unknown)
        )
    if len(set(observation.detected_defect_ids)) != len(observation.detected_defect_ids):
        raise ValueError("Real-world validation detected defects must be unique")


def _identifier_is_opaque(repository_id: str, repository: str) -> bool:
    name = repository.rstrip("/").rsplit("/", 1)[-1].lower()
    if not name:
        return False
    return name not in repository_id.lower()


def _assert_visible_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        unexpected = sorted(str(key) for key in value if str(key) not in VISIBLE_EVIDENCE_KEYS)
        if unexpected:
            raise ValueError(
                "Real-world validation payload exposes evaluator-only keys: " + ",".join(unexpected)
            )
        for item in value.values():
            _assert_visible_keys(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _assert_visible_keys(item)


def _resolve_declared_file(root: Path, relative: str, label: str) -> Path:
    safe = _safe_relative_path(relative)
    resolved = (root / Path(*PurePosixPath(safe).parts)).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"Real-world validation {label} path escapes the repository root")
    if not resolved.is_file():
        raise ValueError(f"Real-world validation {label} file does not exist: {safe}")
    return resolved


def _count(item: Mapping[str, Any], key: str, variant: str) -> int:
    value = item.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"Real-world run record {variant} field {key!r} must be a non-negative integer"
        )
    return value


def _load_mapping(path: Path, label: str) -> Mapping[str, Any]:
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except ValueError as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Real-world validation path must be repository-relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("Real-world validation path must not be an absolute drive path")
    return candidate.as_posix()


def _required_mapping(item: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = item.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Real-world validation manifest field {key!r} must be an object")
    return value


def _required_text(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Real-world validation manifest field {key!r} must be non-empty text")
    return value.strip()
