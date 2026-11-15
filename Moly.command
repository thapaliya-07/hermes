#!/bin/zsh
# Starts Hermes (Odyssey scam guard). Prefer Hermes.command.
cd "$(dirname "$0")"
exec .venv/bin/python app.py "$@"
