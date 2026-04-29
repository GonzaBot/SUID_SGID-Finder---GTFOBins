#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

if [[ -s requirements.txt ]]; then
  python -m pip install -r requirements.txt
fi

chmod +x suid_auditor.py

echo "Setup complete."
echo "Run: source .venv/bin/activate && ./suid_auditor.py /usr/bin"
