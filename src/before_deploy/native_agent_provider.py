"""First-class native AI advisory provider for `before-deploy review`."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, advisory_error_import
from before_deploy.advisory_execution import (
    MODEL_IDENTITY_ATTESTED,
    MODEL_IDENTITY_UNATTESTED,
    AdvisoryExecutionBudget,
    AdvisoryExecutionDescriptor,
    AdvisoryExecutionParameter,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
)
from before_deploy.advisory_provider import AdvisoryProviderIdentity, AdvisoryProviderRequest
from before_deploy.agent_orchestration import (
    DEFAULT_SPECIALIST_IDS,
    AgentReviewOrchestrator,
    AgentReviewResult,
)
from before_deploy.agent_routing import NativeModelRouter
from before_deploy.agent_runtime import AgentBudget, AgentContextItem, AgentRuntime
from before_deploy.agent_snapshot_tools import SnapshotRepositoryTools
from before_deploy.agent_tool_executor import BoundedRepositoryTools
from before_deploy.agent_tools import RepositoryToolPolicy
from before_deploy.models import Location

NATIVE_AGENT_SOURCE = "before-deploy-agent"
NATIVE_AGENT_SOURCE_FORMAT = "before-deploy-agent-v1"


@dataclass(frozen=True)
class NativeAgentAdvisoryProvider:
    """Run bounded native agents and normalize accepted claims as ordinary advisory findings."""

    router: NativeModelRouter
    budget: AgentBudget = AgentBudget()
    specialist_ids: tuple[str, ...] = DEFAULT_SPECIALIST_IDS
    tool_policy: RepositoryToolPolicy = RepositoryToolPolicy()

    @property
    def identity(self) -> AdvisoryProviderIdentity:
        return AdvisoryProviderIdentity(
            provider_id="native-agent",
            input_name="agent",
            source=NATIVE_AGENT_SOURCE,
            source_format=NATIVE_AGENT_SOURCE_FORMAT,
        )

    def execution_descriptor(self, request: AdvisoryProviderRequest) -> AdvisoryExecutionDescriptor:
        del request
        routes = self.router.route_manifest()
        if len(routes) == 1:
            model = AdvisoryModelIdentity(
                status=MODEL_IDENTITY_ATTESTED,
                provider=routes[0].provider_id,
                model=routes[0].model_id,
            )
        else:
            model = AdvisoryModelIdentity(
                status=MODEL_IDENTITY_UNATTESTED,
                reason="Routed native agent execution uses multiple provider/model identities",
            )
        route_value = ",".join(
            f"{route.route_id}:{route.provider_id}/{route.model_id}" for route in routes
        )
        return AdvisoryExecutionDescriptor(
            implementation="before-deploy-native-agent",
            implementation_version="1",
            model=model,
            configuration=(
                AdvisoryExecutionParameter(name="routes", value=route_value),
                AdvisoryExecutionParameter(name="specialists", value=",".join(self.specialist_ids)),
                AdvisoryExecutionParameter(
                    name="scope_expansion",
                    value="enabled" if self.tool_policy.allow_scope_expansion else "disabled",
                ),
                AdvisoryExecutionParameter(name="claim_contract", value=NATIVE_AGENT_SOURCE_FORMAT),
            ),
            budgets=(
                AdvisoryExecutionBudget("max_steps", self.budget.max_steps, "steps"),
                AdvisoryExecutionBudget("max_tool_calls", self.budget.max_tool_calls, "calls"),
                AdvisoryExecutionBudget(
                    "max_tool_result_bytes", self.budget.max_tool_result_bytes, "bytes"
                ),
                AdvisoryExecutionBudget("max_input_tokens", self.budget.max_input_tokens, "tokens"),
                AdvisoryExecutionBudget(
                    "max_output_tokens", self.budget.max_output_tokens, "tokens"
                ),
                AdvisoryExecutionBudget(
                    "max_cost_microusd", self.budget.max_cost_microusd, "micro-usd"
                ),
                AdvisoryExecutionBudget(
                    "max_duration_ms", self.budget.max_duration_ms, "milliseconds"
                ),
            ),
        )

    def review(self, request: AdvisoryProviderRequest) -> AdvisoryImport:
        context = request.context
        if context is None:
            return _provider_error("Native agent provider received no deterministic advisory context")
        if not context.files:
            return AdvisoryImport(
                input_name="agent",
                source=NATIVE_AGENT_SOURCE,
                source_format=NATIVE_AGENT_SOURCE_FORMAT,
                findings=(),
                scope_status="MATCHED",
                scope_message="No deterministic advisory context files were selected",
            )

        context_items = tuple(
            AgentContextItem.from_text(
                evidence_id=_context_evidence_id(file.path, entry.content_sha256),
                kind="changed-file",
                path=file.path,
                content=file.content,
            )
            for file, entry in zip(context.files, context.manifest.selected, strict=True)
        )
        starting_paths = tuple(file.path for file in context.files)
        historical_scope = context.manifest.mode in {"RANGE", "COMMIT"}
        effective_policy = RepositoryToolPolicy(
            allowed_tools=self.tool_policy.allowed_tools,
            allow_scope_expansion=(
                self.tool_policy.allow_scope_expansion and not historical_scope
            ),
            max_file_bytes=self.tool_policy.max_file_bytes,
            max_results=self.tool_policy.max_results,
            max_read_lines=self.tool_policy.max_read_lines,
        )
        try:
            if historical_scope:
                tools = SnapshotRepositoryTools(context.files, policy=effective_policy)
            else:
                tools = BoundedRepositoryTools(
                    request.repository,
                    starting_paths=starting_paths,
                    policy=effective_policy,
                )
            orchestration = AgentReviewOrchestrator(
                runtime=AgentRuntime(budget=self.budget)
            ).run(
                model_factory=self.router,
                tools=tools,
                context=context_items,
                specialist_ids=self.specialist_ids,
            )
        except (OSError, ValueError) as error:
            return _provider_error(
                f"Native agent preparation failed: {type(error).__name__}",
                scope_status="CONTEXT_LIMITED" if historical_scope else "NOT_CHECKED",
            )

        completed_runs = sum(run.status == "COMPLETED" for run in orchestration.specialist_runs)
        if completed_runs == 0:
            return _provider_error(
                "Native agent review produced no completed specialist run",
                scope_status="CONTEXT_LIMITED" if historical_scope else "MATCHED",
            )

        findings = tuple(_finding_from_claim(claim) for claim in orchestration.accepted_claims)
        return AdvisoryImport(
            input_name="agent",
            source=NATIVE_AGENT_SOURCE,
            source_format=NATIVE_AGENT_SOURCE_FORMAT,
            findings=findings,
            status="COMPLETED",
            message=(
                f"specialists_completed={completed_runs}/{len(orchestration.specialist_runs)} "
                f"critic_assessments={len(orchestration.critic_assessments)}"
            ),
            scope_status="CONTEXT_LIMITED" if historical_scope else "MATCHED",
            scope_message=(
                "Historical scope uses exact deterministic changed-file snapshot; dynamic "
                "expansion outside that snapshot is disabled"
                if historical_scope
                else "Native agent started from the exact deterministic advisory context"
            ),
            raw_artifact=_orchestration_artifact(orchestration),
        )


def _finding_from_claim(claim) -> AdvisoryFinding:
    semantic_sha = sha256(
        dumps(
            {
                "source": NATIVE_AGENT_SOURCE,
                "claim_id": claim.claim_id,
                "title": claim.title,
                "message": claim.message,
                "category": claim.category,
                "severity": claim.severity,
                "path": claim.path,
                "start_line": claim.start_line,
                "end_line": claim.end_line,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    location = (
        Location(path=claim.path, start_line=claim.start_line, end_line=claim.end_line)
        if claim.path is not None
        else None
    )
    return AdvisoryFinding(
        finding_id=f"AIA-{semantic_sha[:12]}",
        source=NATIVE_AGENT_SOURCE,
        title=claim.title,
        message=claim.message,
        category=claim.category,
        severity=claim.severity,
        confidence=claim.confidence,
        fingerprint=semantic_sha,
        location=location,
    )


def _context_evidence_id(path: str, content_sha256: str) -> str:
    digest = sha256(f"{path}\0{content_sha256}".encode("utf-8")).hexdigest()
    return f"agent-context:{digest}"


def _orchestration_artifact(result: AgentReviewResult) -> AdvisoryRawArtifact:
    payload = {
        "schema_version": result.schema_version,
        "orchestration_sha256": result.orchestration_sha256,
        "specialist_run_sha256s": tuple(run.run_sha256 for run in result.specialist_runs),
        "corroboration": tuple(
            {
                "claim_sha256": item.claim_sha256,
                "status": item.status,
                "specialist_ids": item.specialist_ids,
                "run_sha256s": item.run_sha256s,
            }
            for item in result.corroboration
        ),
        "critic_assessments": tuple(
            {
                "candidate_claim_sha256": item.candidate_claim_sha256,
                "decision": item.decision,
                "critic_run_sha256": item.critic_run_sha256,
            }
            for item in result.critic_assessments
        ),
        "accepted_claim_ids": tuple(claim.claim_id for claim in result.accepted_claims),
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "release_status": result.release_status,
    }
    raw = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return AdvisoryRawArtifact(
        sha256=sha256(raw).hexdigest(),
        size_bytes=len(raw),
        media_type="application/json",
        schema=result.schema_version,
    )


def _provider_error(
    message: str,
    *,
    scope_status: str = "NOT_CHECKED",
) -> AdvisoryImport:
    return advisory_error_import(
        input_name="agent",
        source=NATIVE_AGENT_SOURCE,
        source_format=NATIVE_AGENT_SOURCE_FORMAT,
        message=message,
        scope_status=scope_status,
    )
