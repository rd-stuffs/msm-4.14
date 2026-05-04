#!/bin/bash
#
# Compile script for FSociety kernel
# Copyright (C) 2020-2021 Adithya R.

set -euo pipefail

trap 'printf "\nInterrupted.\n"; exit 1' INT

WD="$(pwd)"
ZIPNAME="Void-Project-surya-$(date '+%Y%m%d-%H%M').zip"
DEFCONFIG="surya_defconfig"

GCC64_DIR="$WD/tc/gcc-arm64"
GCC32_DIR="$WD/tc/gcc-arm"
GCC_RELEASES_API="https://api.github.com/repos/mvaisakh/gcc-build/releases/latest"
GCC_DOWNLOAD_URL="https://github.com/mvaisakh/gcc-build/releases/download"
GCC_TAG="$(curl -fsSL "$GCC_RELEASES_API" | grep -m1 '"tag_name"' | cut -d'"' -f4)"

AK3_DIR="$WD/AnyKernel3"
AK3_URL="https://github.com/rd-stuffs/AnyKernel3"

if git rev-parse --is-inside-work-tree &>/dev/null; then
	SHA=$(git rev-parse --verify HEAD)
	ZIPNAME="${ZIPNAME::-4}-${SHA:0:8}.zip"
fi

if [ -d "$GCC64_DIR" ] && [ -d "$GCC32_DIR" ]; then
	GCC_INSTALLED_DATE="$("$GCC64_DIR/bin/aarch64-elf-gcc" --version | grep -o '[0-9]\{8\}')"
	GCC_INSTALLED_DATE="${GCC_INSTALLED_DATE:6:2}${GCC_INSTALLED_DATE:4:2}${GCC_INSTALLED_DATE:0:4}"
	if [[ $GCC_INSTALLED_DATE != "$GCC_TAG" ]]; then
		printf "Eva GCC update available (%s). Update? [y/N] " "$GCC_TAG"
		read -r GCC_UPDATE
		if [[ ${GCC_UPDATE,,} == y ]]; then
			rm -rf "$GCC64_DIR" "$GCC32_DIR"
		fi
	fi
fi

if [ ! -d "$GCC64_DIR" ] || [ ! -d "$GCC32_DIR" ]; then
	if [ ! -d "$GCC64_DIR" ]; then
		printf "Downloading Eva GCC arm64 (%s)...\n" "$GCC_TAG"
		mkdir -p "$GCC64_DIR"
		curl -fL# "$GCC_DOWNLOAD_URL/$GCC_TAG/eva-gcc-arm64-$GCC_TAG.xz" |
			tar xf - --strip-components=1 -C "$GCC64_DIR"
	fi

	if [ ! -d "$GCC32_DIR" ]; then
		printf "Downloading Eva GCC arm (%s)...\n" "$GCC_TAG"
		mkdir -p "$GCC32_DIR"
		curl -fL# "$GCC_DOWNLOAD_URL/$GCC_TAG/eva-gcc-arm-$GCC_TAG.xz" |
			tar xf - --strip-components=1 -C "$GCC32_DIR"
	fi
fi

if [ ! -d "$AK3_DIR" ]; then
	printf "Cloning AnyKernel3 to %s...\n" "$AK3_DIR"
	git clone --depth=1 -b FSociety "$AK3_URL" "$AK3_DIR"
fi

KBUILD_COMPILER_STRING="$("$GCC64_DIR/bin/aarch64-elf-gcc" --version | head -n1)"
PATH="$GCC64_DIR/bin:$GCC32_DIR/bin:$PATH"

export KBUILD_COMPILER_STRING PATH

MAKE=(
	make
	CROSS_COMPILE="aarch64-elf-"
	CROSS_COMPILE_COMPAT="arm-eabi-"
	LD="$GCC64_DIR/bin/aarch64-elf-ld"
	AR="aarch64-elf-gcc-ar"
	AS="aarch64-elf-as"
	NM="aarch64-elf-nm"
	OBJDUMP="aarch64-elf-objdump"
	OBJCOPY="aarch64-elf-objcopy"
	CC="aarch64-elf-gcc"
	LLVM=0
	LLVM_IAS=0
)

if [[ ${1:-} == -rf || ${1:-} == --regen-full ]]; then
	"${MAKE[@]}" $DEFCONFIG
	cp out/.config arch/arm64/configs/$DEFCONFIG
	printf "\nSuccessfully regenerated full defconfig at %s\n" $DEFCONFIG
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
"${MAKE[@]}" $DEFCONFIG &>/dev/null

if [[ $KSU == "true" ]]; then
	printf "Building KernelSU variant...\n"
	ZIPNAME="${ZIPNAME/Void-Project-surya/Void-Project-KSU}"
	scripts/config --file out/.config -e KSU
	"${MAKE[@]}" olddefconfig &>/dev/null
fi

printf "\n"
SECONDS=0
"${MAKE[@]}" -j"$(nproc --all)" 2> >(tee log.txt >&2)
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
zip -r9 "../$ZIPNAME" ./* -x .git modules\* patch\* ramdisk\* README.md \*placeholder &>/dev/null
rm -f Image.gz-dtb dtbo.img dtbo-miui.img
cd ..
printf "\nCompleted in %d minute(s) and %d second(s)!\n" $((BUILD_TIME / 60)) $((BUILD_TIME % 60))
printf "Zip: %s\n" "$ZIPNAME"
