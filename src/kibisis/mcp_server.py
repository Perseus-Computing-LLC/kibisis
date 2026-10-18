"""Model Context Protocol (MCP) server for Kibisis memory vault.

Exposes Kibisis memory, bitemporal recall, and SHA-256 Merkle chain verification
via standard JSON-RPC 2.0 over stdio for external agent environments (Cursor, Claude Desktop, VS Code, Codex).
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Union
from .models import EpistemicState
from .vault import SQLiteMemoryVault


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "kibisis-mcp"
SERVER_VERSION = "0.1.0"

TOOL_DEFINITIONS = [
    {
        "name": "kibisis_remember",
        "description": "Store a durable fact, convention, or insight in the local Kibisis memory vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Memory category (e.g. convention, insight, decision, system_invariant).",
                    "default": "general",
                },
                "key": {
                    "type": "string",
                    "description": "Unique key identifier within category.",
                },
                "content": {
                    "type": "string",
                    "description": "Content of the memory to store.",
                },
                "epistemic_state": {
                    "type": "string",
                    "description": "Epistemic state under Rubric v2.1 (verified, candidate, disputed, revoked).",
                    "enum": ["candidate", "verified", "disputed", "revoked"],
                    "default": "verified",
                },
                "scope": {
                    "type": "string",
                    "description": "Scope or tenant identifier for isolation.",
                    "default": "default",
                },
                "valid_from": {
                    "type": "number",
                    "description": "Optional bitemporal start timestamp.",
                },
                "valid_until": {
                    "type": "number",
                    "description": "Optional bitemporal expiration timestamp.",
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional JSON metadata dictionary.",
                },
            },
            "required": ["key", "content"],
        },
    },
    {
        "name": "kibisis_recall",
        "description": "Search Kibisis memory vault using FTS5 full-text search and bitemporal point-in-time filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Keyword search query.",
                },
                "scope": {
                    "type": "string",
                    "description": "Scope filter (default: 'default', '*' for all).",
                    "default": "default",
                },
                "category": {
                    "type": "string",
                    "description": "Optional category filter.",
                },
                "epistemic_state": {
                    "type": "string",
                    "description": "Filter by epistemic state (default: verified/disputed).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return.",
                    "default": 10,
                },
                "as_of_valid_time": {
                    "type": "number",
                    "description": "Bi-temporal point-in-time timestamp evaluation.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "kibisis_admit",
        "description": "Admit a candidate memory to verified status via reviewer or gate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Category of memory."},
                "key": {"type": "string", "description": "Key of memory."},
                "scope": {"type": "string", "description": "Scope of memory.", "default": "default"},
                "reviewer_id": {"type": "string", "description": "Identity of gate or reviewer.", "default": "mcp_gate"},
            },
            "required": ["category", "key"],
        },
    },
    {
        "name": "kibisis_forget",
        "description": "Archive or soft-delete a memory entity in Kibisis memory vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Category of memory."},
                "key": {"type": "string", "description": "Key of memory."},
                "scope": {"type": "string", "description": "Scope of memory.", "default": "default"},
            },
            "required": ["category", "key"],
        },
    },
    {
        "name": "kibisis_verify_ledger",
        "description": "Verify the cryptographic SHA-256 Merkle chain integrity of the Kibisis audit journal.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "kibisis_health",
        "description": "Check Kibisis memory vault status, encryption mode, and active entity counts.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


class KibisisMCPServer:
    """JSON-RPC 2.0 Model Context Protocol server exposing SQLiteMemoryVault."""

    def __init__(self, vault: Optional[SQLiteMemoryVault] = None, db_path: Optional[str] = None):
        if vault is not None:
            self.vault = vault
        else:
            resolved_path = db_path or os.environ.get("KIBISIS_DB_PATH", "/opt/data/runtime/kibisis/vault.sqlite")
            if resolved_path != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(resolved_path)), exist_ok=True)
            self.vault = SQLiteMemoryVault(resolved_path, allow_plaintext=True)

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single JSON-RPC 2.0 request or notification."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                },
            }

        if method == "notifications/initialized":
            # Notifications require no response
            return None

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": TOOL_DEFINITIONS,
                },
            }

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                res_content = self._execute_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": res_content if isinstance(res_content, str) else json.dumps(res_content, indent=2),
                            }
                        ],
                        "isError": False,
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error executing tool '{tool_name}': {str(e)}\n{traceback.format_exc()}",
                            }
                        ],
                        "isError": True,
                    },
                }

        # Unknown method error
        if req_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found",
                },
            }
        return None

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name == "kibisis_remember":
            category = args.get("category", "general")
            key = args["key"]
            content = args["content"]
            epistemic_state = args.get("epistemic_state", "verified")
            scope = args.get("scope", "default")
            valid_from = args.get("valid_from")
            valid_until = args.get("valid_until")
            meta = args.get("metadata", {})
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {"raw": meta}

            entity = self.vault.store(
                category=category,
                key=key,
                content=content,
                metadata=meta,
                epistemic_state=epistemic_state,
                valid_from=valid_from,
                valid_until=valid_until,
                scope=scope,
            )
            return {
                "status": "stored",
                "id": entity.id,
                "category": entity.category,
                "key": entity.key,
                "version": entity.version,
                "epistemic_state": entity.epistemic_state.value if isinstance(entity.epistemic_state, EpistemicState) else str(entity.epistemic_state),
                "scope": entity.scope,
            }

        elif name == "kibisis_recall":
            query = args["query"]
            scope = args.get("scope", "default")
            category = args.get("category")
            epistemic_state = args.get("epistemic_state")
            limit = int(args.get("limit", 10))
            as_of_valid_time = args.get("as_of_valid_time")

            results = self.vault.search(
                query=query,
                scope=scope,
                category=category,
                epistemic_state=epistemic_state,
                limit=limit,
                as_of_valid_time=as_of_valid_time,
            )
            return [
                {
                    "category": r.entity.category,
                    "key": r.entity.key,
                    "content": r.entity.content,
                    "epistemic_state": r.entity.epistemic_state.value if isinstance(r.entity.epistemic_state, EpistemicState) else str(r.entity.epistemic_state),
                    "scope": r.entity.scope,
                    "rank_score": r.rank_score,
                    "snippet": r.snippet,
                    "metadata": r.entity.metadata,
                }
                for r in results
            ]

        elif name == "kibisis_admit":
            category = args["category"]
            key = args["key"]
            scope = args.get("scope", "default")
            reviewer_id = args.get("reviewer_id", "mcp_gate")
            entity = self.vault.review_entity(
                category=category,
                key=key,
                verdict="verified",
                scope=scope,
                reviewer_id=reviewer_id,
            )
            return {
                "status": "verified",
                "category": entity.category,
                "key": entity.key,
                "epistemic_state": entity.epistemic_state.value if isinstance(entity.epistemic_state, EpistemicState) else str(entity.epistemic_state),
            }

        elif name == "kibisis_forget":
            category = args["category"]
            key = args["key"]
            scope = args.get("scope", "default")
            archived = self.vault.archive(category=category, key=key, scope=scope)
            return {"status": "archived" if archived else "not_found", "category": category, "key": key}

        elif name == "kibisis_verify_ledger":
            valid = self.vault.verify_audit_chain()
            return {
                "valid": valid,
                "chain_integrity": "OK" if valid else "CORRUPTED",
            }

        elif name == "kibisis_health":
            events = self.vault.list_audit_events(limit=10)
            cursor = self.vault._conn.cursor()
            cursor.execute("SELECT count(*) as c FROM entities WHERE archived = 0")
            row = cursor.fetchone()
            active_count = row["c"] if row else 0
            enc_status = self.vault.encryption_status() if callable(self.vault.encryption_status) else self.vault.encryption_status
            return {
                "status": "healthy",
                "active_entities": active_count,
                "encryption": enc_status,
                "audit_events_recorded": len(events),
            }

        else:
            raise ValueError(f"Unknown tool name: {name}")


def run_stdio_server():
    """Run MCP server over stdio reading line-delimited JSON-RPC messages."""
    server = KibisisMCPServer()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = server.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
