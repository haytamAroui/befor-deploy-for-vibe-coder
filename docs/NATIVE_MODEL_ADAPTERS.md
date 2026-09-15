# Native model adapters and routing

PR44 connects the bounded agent runtime to current first-party model APIs without adding vendor SDK dependencies to the deterministic core.

## Current defaults

Verified on 2026-09-15 against the providers' official model/API documentation:

- OpenAI Responses API: `gpt-6-astra`, using client-side function calling. The current model catalog lists GPT-6 Astra as the flagship/default for complex reasoning and coding.
- Anthropic Messages API: `claude-opus-5`, using client-side tool use. Anthropic recommends Opus 5 for most complex agentic coding and enterprise work; `claude-fable-5-1` is available for especially demanding long-horizon work.

Provider docs:

- https://developers.openai.com/api/docs/models
- https://developers.openai.com/api/docs/guides/function-calling
- https://platform.claude.com/docs/en/models/overview
- https://platform.claude.com/docs/en/claude_api_primer

Model IDs remain configurable. Non-default model IDs require explicit token pricing so a route cannot silently bypass the runtime cost budget.

## No SDK coupling

The adapters use a small `JsonHttpTransport` protocol and a standard-library `UrllibJsonTransport`. Tests can replace transport deterministically, and applications can supply another transport without changing the runtime.

API credentials are accepted by the adapter and sent only in provider request headers. Route manifests contain route/provider/model IDs only and never credentials.

## Tool-only action protocol

Both providers receive the same bounded client tools:

```text
read_file
search_text
search_symbol
find_references
find_callers
find_tests
dependency_neighbors
finalize_review
```

`finalize_review` has a strict JSON schema for evidence-cited advisory claims. A provider turn either requests repository evidence or finalizes; mixing finalization with evidence calls is rejected.

OpenAI receives strict Responses API function definitions with `tool_choice=required`; the adapter parses `function_call` output items by `call_id`, `name`, and JSON `arguments`.

Anthropic receives Messages API client-tool definitions with `tool_choice={"type":"any"}`; the adapter parses `tool_use` blocks by `id`, `name`, and `input`.

Free-form provider text, visible reasoning, and thinking blocks are not persisted or used as findings. Only structured tool actions enter the Before Deploy runtime.

## Cost budget

Provider token usage is converted to conservative micro-USD cost using configured per-token pricing. The checked-in defaults reflect the verified 2026-09-15 list prices for the default models:

```text
gpt-6-astra:   $10 / 1M input, $50 / 1M output
claude-opus-5: $5 / 1M input,  $25 / 1M output
```

Cached-token discounts are intentionally not subtracted, so the runtime does not undercount cost against its hard budget.

## Routing

`NativeModelRouter` deterministically maps specialist IDs to configured routes and uses a separately configured critic route. The model cannot choose a provider or change its own route.

This enables patterns such as OpenAI for general/correctness review and Anthropic for security, or independent-provider specialist/critic passes, while keeping all output advisory.
