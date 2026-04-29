#!/usr/bin/env bash

# SecurAudit Setup Script for Linux/macOS
echo "======================================"
echo " Setting up SecurAudit Environment"
echo "======================================"

# Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 could not be found. Please install Python3 to continue."
    exit 1
fi

echo "[+] Creating Python Virtual Environment..."
python3 -m venv venv

echo "[+] Activating Virtual Environment..."
source venv/bin/activate

echo "[+] Installing Dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Making the auditor script executable..."
chmod +x suid_auditor.py

echo "======================================"
echo " Setup Complete!"
echo " "
echo " To run the application:"
echo " 1. source venv/bin/activate"
echo " 2. sudo python3 suid_auditor.py"
echo " "
echo " Note: Run with sudo/root to ensure accurate stat readings."
echo "======================================"