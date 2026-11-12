"""Cross-platform installer for CyberAuth MCP server and Antigravity integration."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load_agent_rule(config_path: Path) -> str:
    """Read the configurable agent rule text (config.py is stdlib-only)."""
    sys.path.insert(0, str(ROOT))
    from cyberauth.config import load_config

    return load_config(config_path).prompts.agent_rule


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_venv(venv_dir: Path) -> Path:
    uv_bin = shutil.which("uv")
    if uv_bin:
        print("Syncing environment with uv...")
        subprocess.run([uv_bin, "sync", "--project", str(ROOT)], check=True)
        return venv_python(venv_dir)

    py = venv_python(venv_dir)
    if not py.exists():
        print(f"Creating virtual environment at {venv_dir}...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    print("Installing cyberauth...")
    pip_check = subprocess.run(
        [str(py), "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if pip_check.returncode != 0:
        subprocess.run([str(py), "-m", "ensurepip", "--upgrade"], check=True)
    subprocess.run([str(py), "-m", "pip", "install", "-q", "-e", str(ROOT)], check=True)
    return py


def ensure_config(config_path: Path) -> None:
    if config_path.exists():
        return
    example = ROOT / "cyberauth.example.json"
    if example.exists():
        shutil.copyfile(example, config_path)
        print(f"Created {config_path} from {example.name}.")


def read_server_name(config_path: Path) -> str:
    if not config_path.is_file():
        return "cyberauth"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        name = data.get("server_name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    except (OSError, json.JSONDecodeError):
        pass
    return "cyberauth"


def register_agy_mcp(py_path: Path, config_path: Path, server_name: str) -> Path:
    mcp_cfg_path = Path.home() / ".gemini" / "config" / "mcp_config.json"
    mcp_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {"mcpServers": {}}
    if mcp_cfg_path.is_file() and mcp_cfg_path.stat().st_size > 0:
        data = json.loads(mcp_cfg_path.read_text(encoding="utf-8"))
        if not isinstance(data.get("mcpServers"), dict):
            data["mcpServers"] = {}
    data["mcpServers"][server_name] = {
        "command": str(py_path),
        "args": ["-m", "cyberauth"],
        "env": {"CYBERAUTH_CONFIG": str(config_path)},
    }
    mcp_cfg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return mcp_cfg_path


def install_agy_rule(server_name: str, rule_text: str) -> Path:
    plugin_dir = Path.home() / ".gemini" / "config" / "plugins" / server_name
    rules_dir = plugin_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.json").write_text(
        json.dumps(
            {
                "name": server_name,
                "version": "0.1.0",
                "description": "Global workflow authorization rule for CyberAuth.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (rules_dir / "AGENTS.md").write_text(rule_text, encoding="utf-8")
    return plugin_dir


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Install and configure CyberAuth")
    parser.add_argument(
        "--name",
        default=None,
        help="MCP server & plugin name (updates server_name in cyberauth.json)",
    )
    parser.add_argument(
        "--register-agy",
        action="store_true",
        help="Register the MCP server in ~/.gemini/config/mcp_config.json",
    )
    parser.add_argument(
        "--install-agy-rule",
        action="store_true",
        help="Install the global Antigravity rule plugin in ~/.gemini/config/plugins/",
    )
    args = parser.parse_args(argv)

    venv_dir = ROOT / ".venv"
    config_path = ROOT / "cyberauth.json"

    py_path = ensure_venv(venv_dir)
    ensure_config(config_path)
    if args.name:
        server_name = args.name.strip()
        if config_path.is_file():
            cfg_data = json.loads(config_path.read_text(encoding="utf-8"))
            cfg_data["server_name"] = server_name
            config_path.write_text(
                json.dumps(cfg_data, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    else:
        server_name = read_server_name(config_path)

    if args.register_agy:
        mcp_cfg = register_agy_mcp(py_path, config_path, server_name)
        print(f"Registered '{server_name}' in {mcp_cfg}")

    if args.install_agy_rule:
        plugin_dir = install_agy_rule(server_name, load_agent_rule(config_path))
        print(f"Installed Antigravity global rule plugin at {plugin_dir}")

    snippet = {
        "mcpServers": {
            server_name: {
                "command": str(py_path),
                "args": ["-m", "cyberauth"],
                "env": {"CYBERAUTH_CONFIG": str(config_path)},
            }
        }
    }
    print("\nMCP client configuration snippet:\n")
    print(json.dumps(snippet, indent=2))


if __name__ == "__main__":
    main()
