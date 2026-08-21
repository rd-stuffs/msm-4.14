#!/bin/bash
#
# Prebuilt kernel tree export script
# Copyright (C) 2026 Richard R.

set -euo pipefail

trap 'printf "\nInterrupted.\n"; exit 1' INT

REMOTE="git@github.com:rd-stuffs/device_xiaomi_surya-kernel.git"
TAG=$(date '+%d%m%Y')
WD="$(pwd)"

kernel="out/arch/arm64/boot/Image.gz"
dtb="out/arch/arm64/boot/dts/qcom/sdmmagpie.dtb"
dtbo="out/arch/arm64/boot/dtbo.img"

if [ ! -f "$kernel" ] || [ ! -f "$dtb" ] || [ ! -f "$dtbo" ]; then
	printf "Missing build artifacts, run build.sh first.\n"
	exit 1
fi

if [ ! -d out/usr ]; then
	printf "Missing kernel headers, run build.sh first.\n"
	exit 1
fi

RELEASE="false"
for arg in "$@"; do
	case $arg in
	-r | --release)
		RELEASE="true"
		;;
	*)
		printf "Unknown argument: %s\n" "$arg"
		exit 1
		;;
	esac
done

rm -rf out/prebuilt
mkdir -p out/prebuilt/kernel-headers/usr
mkdir -p out/prebuilt/dtb
cp "$kernel" "$dtbo" out/prebuilt
cp "$dtb" out/prebuilt/dtb
rsync -a --exclude='*.install*' out/usr/include out/usr/techpack out/prebuilt/kernel-headers/usr

VERSION=$(sed -n 's/^VERSION = *//p' Makefile)
PATCHLEVEL=$(sed -n 's/^PATCHLEVEL = *//p' Makefile)
SUBLEVEL=$(sed -n 's/^SUBLEVEL = *//p' Makefile)

cat > out/prebuilt/kernel-headers/Makefile << EOF
VERSION = $VERSION
PATCHLEVEL = $PATCHLEVEL
SUBLEVEL = $SUBLEVEL

headers_install:
	@mkdir -p \$(O)/usr
	@rsync -mrq \$(shell pwd)/* \$(O)/

all:
	@true
EOF

INFO="HEAD: $(git rev-parse --verify HEAD)
$("$WD/tc/gcc-arm64/bin/aarch64-elf-gcc" --version | head -n1)"

if [[ $RELEASE == "true" ]]; then
	if [ ! -d out/prebuilt-release ]; then
		git clone -b main "$REMOTE" out/prebuilt-release
	fi
	rm -rf out/prebuilt-release/*
	cp -r out/prebuilt/. out/prebuilt-release

	git -C out/prebuilt-release add -A
	git -C out/prebuilt-release commit -q -m "surya-kernel: Update prebuilts $TAG" -m "$INFO"
	git -C out/prebuilt-release tag "$TAG"
	git -C out/prebuilt-release push origin main
	git -C out/prebuilt-release push origin "$TAG"
else
	git -C out/prebuilt init -q
	git -C out/prebuilt checkout -qb staging
	git -C out/prebuilt add -A
	git -C out/prebuilt commit -q -m "surya-kernel: Import prebuilt artifacts" -m "$INFO"
	git -C out/prebuilt push -qf "$REMOTE" staging
fi

printf "%s\nPrebuilt artifacts exported successfully.\n" "$INFO"
