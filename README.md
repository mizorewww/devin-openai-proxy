# devin-openai-proxy

A minimal, single-user OpenAI-compatible reverse proxy for Devin's cloud
`GetChatMessage` endpoint (`server.codeium.com`, Connect-RPC + protobuf).

Pure Go standard library — no third-party dependencies, one static binary.

## Features

- `POST /v1/chat/completions` — streaming (SSE) and buffered responses
- Reasoning models fully supported: thinking streams out as
  `reasoning_content`, and **signed CoT round-trips are preserved** (see
  below)
- Tool calling (`tools` → upstream tool defs, streamed `tool_calls` back),
  `tool` results, `image_url` data-URI inputs
- `GET /v1/models`, `GET /healthz`
- Optional bearer auth (`AUTH_KEY`)

## Encrypted-CoT design

Devin's upstream attaches an opaque `signature` + `signature_type` to every
thinking block. Verifying and continuing a reasoning trace across turns
requires replaying that signature — the same thing the official Devin CLI
does internally.

This proxy keeps an in-memory store of issued thinking keyed by content
digests:

1. On a response, each `{thinking, signature, signature_type, redacted}`
   blob is stored under the hash of its thinking text **and** the hash of the
   assistant turn's content. Unsigned-reasoning models (e.g. `swe-2-flash`,
   which returns thinking with no signature) are stored the same way.
2. On the next request, each assistant message in the history is rehydrated
   by looking up first the client-echoed `reasoning_content`, then the
   assistant text + tool_calls digest, and the blob is replayed through
   ChatMessage fields `#11` (thinking) / `#12` (signature) / `#13`
   (redacted) / `#18` (signature_type). Unsigned blobs send field 11 alone —
   the same shape the Devin CLI uses for these models.
3. When the store misses, an echoed `reasoning_content` is still replayed as
   unsigned field-11 text. Signed blobs only ever replay to the model
   selector that issued them; a cross-family miss degrades to unsigned text.

Clients never see or send signatures; the conversation only carries normal
OpenAI-shaped messages.

`cascade_id` / trajectory / session ids are derived from a stable
conversation-root hash, so upstream sees one continuous session across
requests.

## Requirements

- A Devin/Windsurf account session token. Either:
  - set `DEVIN_API_KEY`, or
  - have a Devin CLI login on the same machine — the proxy reads
    `~/.local/share/devin/credentials.toml` automatically.

## Build & run

```sh
go build -o devin-openai-proxy .
ADDR=127.0.0.1:8795 ./devin-openai-proxy
```

```sh
curl http://127.0.0.1:8795/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"swe-2-medium","messages":[{"role":"user","content":"hi"}]}'
```

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `DEVIN_API_KEY` | — | Session token; falls back to the Devin CLI credential store |
| `DEVIN_HOST` | `https://server.codeium.com` | Upstream base URL |
| `AUTH_KEY` | unset = no auth | Bearer key for `/v1/*`; set it when exposing beyond loopback |
| `ADDR` | `127.0.0.1:8795` | Listen address |
| `DEVIN_DEFAULT_MODEL` | `swe-2-medium` | Selector used when the request model is empty or unmapped |
| `DEVIN_CLIENT_VERSION` | `3.10.27` | Client version reported in request metadata |
| `DEVIN_DUMP` | unset | Debug: write the last encoded request proto to this path (contains the api key — local debugging only) |

## Models & reasoning effort

`/v1/models` lists model **families** (`swe-2`, `swe-1-7`, …). Reasoning
effort is a request parameter, not a separate model — the standard OpenAI
shape:

```json
{"model": "swe-2", "reasoning_effort": "high"}
```

This resolves to the `swe-2-high` upstream selector. Available tiers per
family: `swe-2` ships `medium`/`high`/`max` (default `medium`); out-of-range
efforts clamp to the nearest real tier (`low`→`medium`, `xhigh`→`max`).
`swe-2-high` as a literal model name still works — an explicit suffix beats
the parameter. Names with no effort variants pass through verbatim.

## Deployment

The binary is fully static (`CGO_ENABLED=0`). Put it behind any HTTPS reverse
proxy and a supervisor; `deploy/` contains a generic systemd unit and a
Caddyfile snippet to adapt.

## Known limitations

- The signature store is in-memory: after a restart, signed turns degrade
  to unsigned text replay (the client's echoed `reasoning_content` still
  reaches the model), while unsigned-reasoning turns are unaffected.
- When a turn yields multiple signed thinking blocks, only the newest one is
  replayed upstream (matching the reference client behavior).
- Empty assistant messages are dropped; runs of consecutive same-role text
  messages are merged (the upstream rejects runs ≥ 3).

## License

MIT
