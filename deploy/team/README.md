# Shared vault over HTTP

`python -m kibisis mcp-http-serve` serves one vault and one scope to several people's agents over
MCP Streamable HTTP (`POST /mcp`). Tools, scope rules and trust rules are the stdio server's:
every write is a candidate, the scope is fixed by the server, recall output is escaped and labelled.

## Run

```
# one token per member; keep the token, put the digest line in members.json
python -m kibisis mcp-http-token alice
python -m kibisis mcp-http-token bob
cat > members.json <<'EOF'
{"members": {"alice": "<sha256>", "bob": "<sha256>"}}
EOF
chmod 600 members.json

python -m kibisis.keys vault.key            # vault key, mode 600
docker build -f deploy/team/Dockerfile --build-arg KIBISIS_COMMIT=$(git rev-parse HEAD) -t kibisis-team .
docker run -d --name kibisis-team --restart unless-stopped \
  -v "$PWD/data:/data" \
  -v "$PWD/members.json:/run/secrets/members.json:ro" \
  -v "$PWD/vault.key:/run/secrets/vault.key:ro" \
  -e KIBISIS_PASSPHRASE_FILE=/run/secrets/vault.key \
  kibisis-team
```

The server refuses to start on a vault that is not encrypted at rest unless `--plaintext` is passed.
Put it behind TLS (a reverse proxy or a tunnel); it speaks plain HTTP.

## Connect an agent

Any MCP client that speaks Streamable HTTP and can send a header:

```
url:     https://<host>/mcp
headers: Authorization: Bearer <member token>
```

## What members see

- Each member's calls run as author `mcp-agent:<name>`; recall shows that author on every entry.
- `GET /health` (no token) reports version, scope, member count and whether the vault is encrypted.
- Rotate a member: issue a new token, replace the digest in `members.json`, restart the container.
