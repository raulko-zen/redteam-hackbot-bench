#!/bin/sh
# Test double for redteam-hackbot's migrate-vault.sh: create the vault folder and the vault symlink.
cd "$(dirname "$0")/../.." || exit 1
name="${2:-vault-test}"
mkdir -p "$name/context/kb" "$name/docs" "$name/sessions" reports
ln -s "$name" vault
echo "created vault $name"
