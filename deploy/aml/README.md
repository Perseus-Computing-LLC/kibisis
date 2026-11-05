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

* **Storage.** There is one Kibisis vault per `user_id`, encrypted with SQLCipher. Each message is stored
  verbatim as its own entry, with its role and timestamp in the entry metadata.
* **Add.** Each request is written in a single transaction, together with a marker keyed on its `request_id`.
  If a write fails, nothing from that request is stored. A retried request is acknowledged without being stored
  twice. `success: true` is returned only after the commit, when the messages are already searchable.
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

* `--candidates` (default 200)
* `--context-before` (default 1)
* `--max-inflight`: requests served at once. Further requests get `429` with `Retry-After`. Default 32.
* `--max-open-vaults` (default 64)
* `--retention-days`: vaults with no write for this long are deleted. Default 28.

Evaluation content is never logged; each request logs one line with its operation, status and latency.
