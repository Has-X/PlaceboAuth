"""CLI entrypoint for CyberAuth MCP server."""

from __future__ import annotations

import argparse
from pathlib import Path

from cyberauth.config import load_config
from cyberauth.server import create_server


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cyberauth",
        description="CyberAuth MCP authorization server",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind when using streamable-http (overrides config)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind when using streamable-http (overrides config)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to JSON configuration file (default: cyberauth.json)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Trusted identity profile name from profiles/ (overrides config 'profile')",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available trusted profiles and exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.list_profiles:
        from cyberauth.config import list_profiles

        print("\n".join(list_profiles(args.config)))
        return
    if args.profile:
        import os

        os.environ["CYBERAUTH_PROFILE"] = args.profile
    cfg = load_config(args.config)

    if args.host is not None or args.port is not None:
        from dataclasses import replace

        cfg = replace(
            cfg,
            host=args.host if args.host is not None else cfg.host,
            port=args.port if args.port is not None else cfg.port,
        )

    server = create_server(cfg)
    if args.transport == "streamable-http":
        server.run(transport="streamable-http", host=cfg.host, port=cfg.port)
    else:
        server.run(transport=args.transport)


if __name__ == "__main__":
    main()
