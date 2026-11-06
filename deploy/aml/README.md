# Kibisis on the Agent Memory Leaderboard

`python -m kibisis aml-serve` serves the [AML Add/Search contract](https://agentmemoryleaderboard.ai/api-guide)
(Textual track) over Kibisis vaults. The source is [`src/kibisis/aml_adapter.py`](../../src/kibisis/aml_adapter.py),
and its tests are in [`tests/test_aml_adapter.py`](../../tests/test_aml_adapter.py).

## Endpoints

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/health` (also `/`, `/v1/health`) | none |
| `POST` | `/v1/memories/add` (alias `/add`) | `Authorization: Token <key>`, `Bearer <key>` or `X-Api-Key: <key>` |
| `POST` | `/v1/memories/search` (alias `/search`) | same |

## Method

* **Storage.** There is one Kibisis vault per `user_id`, encrypted with SQLCipher when a vault passphrase is
  set (`KIBISIS_PASSPHRASE_FILE` or `KIBISIS_PASSPHRASE`). With `--plaintext` instead, the files are plain
  SQLite and evaluation data is stored unencrypted. Each message is stored verbatim as its own entry, with its
  role and timestamp in the entry metadata. The startup log line says `encrypted_at_rest=True|False`.
* **Add.** Each request is written in a single transaction, together with a marker keyed on its `request_id`.
  If a write fails, nothing from that request is stored. A retried request (same `request_id`, same
  `session_id` and messages) is acknowledged without being stored twice; the same `request_id` with a
  different payload is refused with `409` and nothing is written (markers written by adapter revisions before
  the payload digest existed carry none, so a retry under such an id is acknowledged whatever its payload).
  `success: true` is returned only after the
  commit, when the messages are already searchable. Timestamps are epoch milliseconds (`>= 1e11`); epoch
  seconds in `[1e9, 4e9)` and ISO 8601 are also accepted; any other number is `422`, as are `NaN`/`Infinity`
  and strings that are not valid Unicode.
* **Search.** The adapter runs one Kibisis BM25 query (`match="any"`, 200 candidates) over the user's messages.
  The query text is the question plus any answer options.
  * Hits are grouped by the Add request they came from.
  * Each hit is shown with the message before it.
  * Each group becomes one memory: its lines appear in conversation order under their timestamps, with `...`
    where lines are skipped.
  * Up to `top_k` groups are returned, best hit first. The Answer step keeps whatever prefix of them fits its
    context budget.
* No model is called. Stored text is never summarised or rewritten.

## Run

```sh
docker build -f deploy/aml/Dockerfile --build-arg KIBISIS_COMMIT=$(git rev-parse HEAD) -t kibisis-aml .
python -m kibisis.keys ./secrets/vault.key            # vault key, mode 600
docker run -d --name kibisis-aml -p 8080:8080 \
  -v "$PWD/aml-data:/data" -v "$PWD/secrets/vault.key:/run/secrets/vault.key:ro" \
  -e KIBISIS_PASSPHRASE_FILE=/run/secrets/vault.key \
  -e KIBISIS_AML_KEY_SHA256=<hex SHA-256 of the Memory System Key> \
  --user "$(id -u):$(id -g)" kibisis-aml
```

The server never needs the Memory System Key itself, only its SHA-256 digest
(`printf %s "$KEY" | sha256sum`). It can instead read the key from `KIBISIS_AML_KEY_FILE` or `KIBISIS_AML_KEY`.

Options (`python -m kibisis aml-serve --help`):

* `--host`: bind address. Default `127.0.0.1` (this machine only). The Docker image passes `--host 0.0.0.0` so the
  published port reaches it; run it that way outside a container only behind a firewall or reverse proxy.
* `--port` (default 8080)
* `--candidates` (default 200)
* `--context-before` (default 1)
* `--max-inflight`: requests *processed* at once (body read plus Add/Search). Further requests get `429` with
  `Retry-After`. Default 32. This does not bound open connections; the next two options do.
* `--max-connections`: connections (handler threads) accepted at once; beyond it a connection gets `503` with
  `Retry-After` and is closed. Default 256.
* `--socket-timeout`: seconds an idle or stalled connection (no request, or a body that stops arriving) is kept
  before it is closed (`408` when headers were complete). Default 30.
* `--max-open-vaults` (default 64)
* `--retention-days`: a vault not used for this long is deleted; both Add and Search count as use (a Search
  touches the vault file's modification time). Only regular files that are vaults of this server (`<32 hex>.kib`
  with the expected header) are ever deleted; a vault with a request inside it is skipped until the next sweep.
  `0` keeps everything. Default 28.

Evaluation content is never logged; each request logs one line with its operation, status and latency.
Without a credential every `POST` is `401`, whatever the path; refusals sent before the body is read (`401`,
`404`, `413`, `429`) drain a `Content-Length` body for up to two seconds so the client receives the reply
(a chunked body is not drained, and the connection closes). A `POST` with `Expect: 100-continue` gets its
`401`/`404` instead of `100 Continue`, so an unauthenticated client is never invited to send a body. Any
unexpected failure while a request's body or fields are read is answered `400`/`422`, never `500`.

The vault key needs the `sqlcipher3` driver (the image installs it). Without the driver, `aml-serve` with
a key refuses to start unless `KIBISIS_ALLOW_PLAINTEXT=1` is set, in which case the files are plain SQLite
(entry content sealed; roles, timestamps and request markers in the clear), the startup line says
`encrypted_at_rest=False` with a warning, and retention treats them as plaintext vaults.
