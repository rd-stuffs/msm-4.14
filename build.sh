#!/bin/bash
#
# Compile script for FSociety kernel
# Copyright (C) 2020-2021 Adithya R.

set -euo pipefail

trap 'printf "\nInterrupted.\n"; exit 1' INT

ZIPNAME="FSociety-surya-$(date '+%Y%m%d-%H%M').zip"
LLVM_REV="22"
TC_DIR="$(pwd)/tc/clang-$LLVM_REV"
AK3_DIR="$(pwd)/AnyKernel3"
DEFCONFIG="surya_defconfig"

if git rev-parse --is-inside-work-tree &>/dev/null; then
	sha=$(git rev-parse --verify HEAD)
	ZIPNAME="${ZIPNAME::-4}-${sha:0:8}.zip"
fi

export PATH="$TC_DIR/bin:$PATH"

if [ ! -d "$TC_DIR" ]; then
	printf "Cloning Slim LLVM to %s...\n" "$TC_DIR"
	git clone --depth=1 -b "$LLVM_REV" \
		https://bitbucket.org/rdxzv/clang-standalone.git "$TC_DIR"
fi

if [ ! -d "$AK3_DIR" ]; then
	printf "Cloning AnyKernel3 to %s...\n" "$AK3_DIR"
	git clone --depth=1 -b FSociety \
		https://github.com/rd-stuffs/AnyKernel3.git "$AK3_DIR"
fi

if [[ ${1:-} == -rf || ${1:-} == --regen-full ]]; then
	make "$DEFCONFIG"
	cp out/.config arch/arm64/configs/"$DEFCONFIG"
	printf "\nSuccessfully regenerated full defconfig at %s\n" "$DEFCONFIG"
	exit
fi

CLEAN="false"
KSU="false"

for arg in "$@"; do
	case $arg in
		-c | --clean)
			CLEAN="true"
			;;
		-s | --su)
			KSU="true"
			;;
		*)
			printf "Unknown argument: %s\n" "$arg"
			exit 1
			;;
	esac
done

if [[ $CLEAN == "true" ]]; then
	printf "Cleaning output directory...\n"
	rm -rf out
fi

printf "Building surya defconfig...\n"
make "$DEFCONFIG" &>/dev/null

if [[ $KSU == "true" ]]; then
	printf "Building KernelSU variant...\n"
	ZIPNAME="${ZIPNAME/FSociety-surya/FSociety-KSU}"
	scripts/config --file out/.config -e KSU -e KSU_ALLOWLIST_WORKAROUND
	make olddefconfig &>/dev/null
fi

printf "\n"
SECONDS=0
make -j"$(nproc --all)" LLVM=1 2> >(tee log.txt >&2)
BUILD_TIME=$SECONDS

kernel="out/arch/arm64/boot/Image.gz-dtb"
dtbo="out/arch/arm64/boot/dtbo.img"
dtbo_miui="out/arch/arm64/boot/dtbo-miui.img"

if [ ! -f "$kernel" ] || [ ! -f "$dtbo" ] || [ ! -f "$dtbo_miui" ]; then
	printf "\nMissing build artifacts, aborting.\n"
	exit 1
fi

printf "\nKernel compiled successfully! Zipping up...\n"
cp "$kernel" "$dtbo" "$dtbo_miui" "$AK3_DIR"
cd "$AK3_DIR"
zip -r9 "../$ZIPNAME" * -x .git modules\* patch\* ramdisk\* README.md \*placeholder &>/dev/null
rm -f Image.gz-dtb dtbo.img dtbo-miui.img
cd ..
printf "\nCompleted in %d minute(s) and %d second(s)!\n" $((BUILD_TIME / 60)) $((BUILD_TIME % 60))
printf "Zip: %s\n" "$ZIPNAME"
