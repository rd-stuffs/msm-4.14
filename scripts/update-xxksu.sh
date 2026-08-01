#!/bin/bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [[ -n $(git status --porcelain) ]]; then
	echo "Working tree must be clean." >&2
	exit 1
fi

url=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
	https://github.com/rd-stuffs/KernelSU/releases/latest)
tag=${url##*/}

if [[ -z $tag || $tag == latest ]]; then
	echo "Failed to resolve latest XXKSU release." >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 --branch "$tag" \
	https://github.com/rd-stuffs/KernelSU.git "$tmp/KernelSU"

rm -rf drivers/kernelsu
cp -a "$tmp/KernelSU/kernel" drivers/kernelsu
git add -A drivers/kernelsu

if git diff --cached --quiet -- drivers/kernelsu; then
	echo "XXKSU is already at $tag."
	exit
fi

git commit -m "drivers: Update XXKSU to $tag"
