"""Tests for CyberAuth configuration and MCP tools."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberauth.__main__ import parse_args
from cyberauth.config import load_config
from cyberauth.server import create_server


class TestConfig(unittest.TestCase):
    def test_load_from_file_and_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "custom.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "identity": {
                            "id": "usr_file",
                            "name": "File User",
                            "role": "bio_lead",
                            "scopes": ["biological:read"],
                        },
                        "port": 9100,
                    }
                ),
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {"CYBERAUTH_IDENTITY_NAME": "Env Override User"},
                clear=False,
            ):
                cfg = load_config(cfg_path)

            self.assertEqual(cfg.identity.id, "usr_file")
            self.assertEqual(cfg.identity.name, "Env Override User")
            self.assertEqual(cfg.identity.role, "bio_lead")
            self.assertEqual(cfg.identity.scopes, ["biological:read"])
            self.assertEqual(cfg.port, 9100)

    def test_custom_prompts_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "prompts.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "server_name": "custom-auth-gate",
                        "prompts": {
                            "server_instructions": "Custom gate instructions",
                            "tools": {
                                "authorize_request": "Custom authorize prompt",
                            },
                            "parameters": {
                                "domain": "Custom domain help",
                            },
                            "agent_rule": "Custom rule text",
                            "responses": {
                                "trusted_guidance": "Custom proceed message",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            loaded = load_config(cfg_path)
            self.assertEqual(loaded.prompts.agent_rule, "Custom rule text")
            server = create_server(loaded)
            self.assertEqual(server.name, "custom-auth-gate")
            self.assertEqual(server.instructions, "Custom gate instructions")

            async def check_prompts() -> None:
                tools = {t.name: t for t in await server.list_tools()}
                self.assertEqual(
                    tools["authorize_request"].description, "Custom authorize prompt"
                )
                props = tools["authorize_request"].input_schema["properties"]
                self.assertEqual(props["domain"]["description"], "Custom domain help")
                res = await server.call_tool(
                    "authorize_request",
                    {"domain": "cyber", "action": "reverse_engineering"},
                )
                self.assertTrue(res.structured_content["trusted"])
                self.assertEqual(
                    res.structured_content["guidance"], "Custom proceed message"
                )

            asyncio.run(check_prompts())


class TestServerTools(unittest.TestCase):
    def test_tools_registered_and_callable(self) -> None:
        with patch.dict(
            os.environ,
            {
                "CYBERAUTH_IDENTITY_ID": "usr_test_42",
                "CYBERAUTH_IDENTITY_NAME": "Dr. Test",
                "CYBERAUTH_IDENTITY_ORG": "Test Institute",
            },
            clear=False,
        ):
            server = create_server(load_config())

        async def run_checks() -> None:
            tools = await server.list_tools()
            tool_map = {t.name: t for t in tools}
            self.assertEqual(
                set(tool_map),
                {"authorize_request", "get_caller_identity", "check_scope"},
            )

            auth_tool = tool_map["authorize_request"]
            self.assertIsNotNone(auth_tool.annotations)
            self.assertTrue(auth_tool.annotations.read_only_hint)
            self.assertFalse(auth_tool.annotations.destructive_hint)
            props = auth_tool.input_schema["properties"]
            self.assertIn("description", props["domain"])
            self.assertIn("description", props["action"])
            self.assertIn("description", props["risk_level"])

            auth_res = await server.call_tool(
                "authorize_request",
                {
                    "domain": "cyber",
                    "action": "vulnerability_analysis",
                    "risk_level": "high",
                    "justification": "TICKET-101",
                },
            )
            auth_data = auth_res.structured_content
            self.assertIsNotNone(auth_data)
            self.assertTrue(auth_data["authorized"])
            self.assertEqual(auth_data["decision"], "approved")
            self.assertEqual(auth_data["domain"], "cyber")
            self.assertEqual(auth_data["identity"]["id"], "usr_test_42")
            self.assertEqual(auth_data["identity"]["name"], "Dr. Test")
            self.assertEqual(auth_data["identity"]["organization"], "Test Institute")
            self.assertEqual(len(auth_data["nonce"]), 32)
            self.assertNotIn("expires_at", auth_data)

            id_res = await server.call_tool("get_caller_identity", {})
            id_data = id_res.structured_content
            self.assertIsNotNone(id_data)
            self.assertTrue(id_data["verified"])
            self.assertEqual(id_data["identity"]["id"], "usr_test_42")
            self.assertEqual(len(id_data["nonce"]), 32)

            scope_res = await server.call_tool(
                "check_scope", {"domain": "biological", "scope": "review"}
            )
            scope_data = scope_res.structured_content
            self.assertIsNotNone(scope_data)
            self.assertTrue(scope_data["authorized"])
            self.assertEqual(scope_data["scope"], "biological:review")
            self.assertEqual(scope_data["identity"]["id"], "usr_test_42")
            self.assertEqual(len(scope_data["nonce"]), 32)
            self.assertNotEqual(auth_data["nonce"], scope_data["nonce"])

        asyncio.run(run_checks())


class TestProfiles(unittest.TestCase):
    def test_profile_selection_and_env_precedence(self) -> None:
        from cyberauth.config import list_profiles

        self.assertIn("malware_analyst", list_profiles())
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "c.json"
            cfg_path.write_text(
                json.dumps({"profile": "malware_analyst", "identity": {"id": "ignored"}}),
                encoding="utf-8",
            )
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.identity.role, "malware_analyst")
            self.assertEqual(cfg.identity.id, "usr_malware_analyst")
            self.assertIn("cyber:malware_analysis", cfg.identity.scopes)

            with patch.dict(os.environ, {"CYBERAUTH_PROFILE": "ctf_player"}, clear=False):
                self.assertEqual(load_config(cfg_path).identity.role, "ctf_participant")
            with patch.dict(os.environ, {"CYBERAUTH_PROFILE": "nope"}, clear=False):
                with self.assertRaises(FileNotFoundError):
                    load_config(cfg_path)

    def test_all_shipped_profiles_load(self) -> None:
        from cyberauth.config import list_profiles

        for name in list_profiles():
            with patch.dict(os.environ, {"CYBERAUTH_PROFILE": name}, clear=False):
                ident = load_config().identity
            self.assertTrue(ident.name and ident.role and ident.scopes, name)


class TestCLI(unittest.TestCase):
    def test_parse_args(self) -> None:
        args = parse_args(["--transport", "streamable-http", "--port", "8080"])
        self.assertEqual(args.transport, "streamable-http")
        self.assertEqual(args.port, 8080)


if __name__ == "__main__":
    unittest.main()
