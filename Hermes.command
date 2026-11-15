#!/bin/zsh
# Double-click to start Hermes in the background. Say "Hey Hermes" and it appears.
# Odyssey scam guard — HackUTA 2026.
cd "$(dirname "$0")"
exec .venv/bin/python app.py "$@"
