# Provider Resilience Policy

`production_openai_caller_pilot_bridge.py` wraps the blinded Luna experiment bridge without changing its model-visible evidence or response contract.

## Retry policy

The wrapper retries only transient transport classes:

- HTTP 408, 409, 429, 500, 502, 503, and 504;
- URL/transport errors;
- local timeout errors raised while opening the request.

The default is at most **3 attempts** per model turn with bounded exponential delay (250 ms base, 2 s maximum). A numeric `Retry-After` is honored but capped by the same maximum delay. Authentication/authorization errors and other non-transient 4xx responses are not retried.

Every logical model turn carries one stable `X-Client-Request-Id` across retries. This follows OpenAI's production troubleshooting guidance while avoiding any secret or repository content in the identifier.

## Cumulative usage budget

When `BEFORE_DEPLOY_BUDGET_LEDGER` is set, the wrapper can enforce explicit cumulative ceilings using:

- `BEFORE_DEPLOY_MAX_COST_MICROUSD`;
- `BEFORE_DEPLOY_MAX_INPUT_TOKENS`;
- `BEFORE_DEPLOY_MAX_OUTPUT_TOKENS_TOTAL`.

The ledger is written atomically after each valid provider response. A run that is already at a configured limit is rejected before another request is sent. A response that would exceed a limit is rejected and is not committed to the ledger. Because provider usage is only known after a response completes, the external provider may still bill the final over-limit request; the wrapper prevents that response from being accepted and prevents subsequent requests. Per-request output remains independently bounded by the underlying bridge.

The production wrapper currently accepts only `gpt-5.6-luna` for cumulative price accounting.

## Authority boundary

Retry and budget handling are transport/accounting concerns only. They do not change the caller experiment's `AI_DISCOVERY_ADVISORY` authority, and the generic advisory provider runtime continues to normalize provider failures to gate-neutral advisory errors. No retry, timeout, malformed output, or budget event may create deterministic release evidence.
