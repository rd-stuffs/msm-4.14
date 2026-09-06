#!/bin/bash
#
# Compile script for FSociety kernel
# Copyright (C) 2020-2021 Adithya R.

set -euo pipefail

trap 'echo -e "\nInterrupted."; exit 1' INT

WD="$(pwd)"
ZIPNAME="FSociety-surya-$(date '+%Y%m%d-%H%M').zip"
DEFCONFIG="surya_defconfig"

CLEAN="false"
LTO="false"
KSU="false"

if [[ ${1:-} != -r && ${1:-} != --regen && ${1:-} != -rf && ${1:-} != --regen-full ]]; then
	for arg in "$@"; do
		case $arg in
		-c | --clean)
			CLEAN="true"
			;;
		-l | --lto)
			LTO="true"
			;;
		-s | --su)
			KSU="true"
			;;
		*)
			echo "Unknown argument: $arg"
			exit 1
			;;
		esac
	done
fi

GCC64_DIR="$WD/tc/gcc-arm64"
GCC32_DIR="$WD/tc/gcc-arm"
GCC_RELEASES_API="https://api.github.com/repos/mvaisakh/gcc-build/releases/latest"
GCC_DOWNLOAD_URL="https://github.com/mvaisakh/gcc-build/releases/download"
GCC_TAG="$(curl -fsSL "$GCC_RELEASES_API" 2>/dev/null | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"

AK3_DIR="$WD/AnyKernel3"
AK3_URL="https://github.com/rd-stuffs/AnyKernel3"

if git rev-parse --is-inside-work-tree &>/dev/null; then
	SHA=$(git rev-parse --verify HEAD)
	ZIPNAME="${ZIPNAME::-4}-${SHA:0:8}.zip"
fi

if [ -d "$GCC64_DIR" ] && [ -d "$GCC32_DIR" ]; then
	if [ -n "$GCC_TAG" ]; then
		GCC_INSTALLED_TAG=""
		if [ -f "$GCC64_DIR/.eva_tag" ]; then
			GCC_INSTALLED_TAG=$(cat "$GCC64_DIR/.eva_tag")
		fi

		if [[ "$GCC_INSTALLED_TAG" != "$GCC_TAG" ]]; then
			echo -n "Eva GCC update available ($GCC_TAG). Update? [y/N] "
			read -r GCC_UPDATE
			if [[ ${GCC_UPDATE,,} == y ]]; then
				rm -rf "$GCC64_DIR" "$GCC32_DIR"
			fi
		fi
	fi
fi

if [ ! -d "$GCC64_DIR" ] || [ ! -d "$GCC32_DIR" ]; then
	if [ -z "$GCC_TAG" ]; then
		echo "No internet connection and toolchain is missing, aborting."
		exit 1
	fi
	if [ ! -d "$GCC64_DIR" ]; then
		echo "Downloading Eva GCC arm64 ($GCC_TAG)..."
		mkdir -p "$GCC64_DIR"
		curl -fL# "$GCC_DOWNLOAD_URL/$GCC_TAG/eva-gcc-arm64-$GCC_TAG.xz" |
			tar xf - --strip-components=1 -C "$GCC64_DIR"
		echo "$GCC_TAG" > "$GCC64_DIR/.eva_tag"
	fi

	if [ ! -d "$GCC32_DIR" ]; then
		echo "Downloading Eva GCC arm ($GCC_TAG)..."
		mkdir -p "$GCC32_DIR"
		curl -fL# "$GCC_DOWNLOAD_URL/$GCC_TAG/eva-gcc-arm-$GCC_TAG.xz" |
			tar xf - --strip-components=1 -C "$GCC32_DIR"
		echo "$GCC_TAG" > "$GCC32_DIR/.eva_tag"
	fi
fi

if [ ! -d "$AK3_DIR" ]; then
	echo "Cloning AnyKernel3 to $AK3_DIR..."
	git clone --depth=1 -b FSociety "$AK3_URL" "$AK3_DIR"
fi

KBUILD_COMPILER_STRING="$("$GCC64_DIR/bin/aarch64-elf-gcc" --version | head -n1)"
PATH="$GCC64_DIR/bin:$GCC32_DIR/bin:$PATH"

CC="aarch64-elf-gcc"
if command -v ccache &>/dev/null; then
	export CCACHE_DIR="$WD/.ccache"
	export CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-2G}"
	export CCACHE_BASEDIR="$WD"
	CC="ccache $CC"
fi

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
	CC="$CC"
	LLVM=0
	LLVM_IAS=0
)

if [[ ${1:-} == -r || ${1:-} == --regen ]]; then
	"${MAKE[@]}" $DEFCONFIG savedefconfig
	cp out/defconfig arch/arm64/configs/$DEFCONFIG
	echo -e "\nSuccessfully regenerated defconfig at $DEFCONFIG"
	exit
fi

if [[ ${1:-} == -rf || ${1:-} == --regen-full ]]; then
	"${MAKE[@]}" $DEFCONFIG
	cp out/.config arch/arm64/configs/$DEFCONFIG
	echo -e "\nSuccessfully regenerated full defconfig at $DEFCONFIG"
	exit
fi

if [[ $CLEAN == "true" ]]; then
	echo "Cleaning output directory..."
	rm -rf out
fi

echo "Building surya defconfig..."
"${MAKE[@]}" $DEFCONFIG &>/dev/null

if [[ $LTO == "true" ]]; then
	scripts/config --file out/.config -e LTO_GCC
	"${MAKE[@]}" olddefconfig &>/dev/null
fi

if [[ $KSU == "true" ]]; then
	echo "Building KernelSU variant..."
	ZIPNAME="${ZIPNAME/FSociety-surya/FSociety-KSU}"
	scripts/config --file out/.config \
		-e KSU \
		-e KSU_TAMPER_SYSCALL_TABLE \
		-d KSU_FEATURE_SULOG \
		-e KSU_THRONE_TRACKER_ALWAYS_THREADED
	"${MAKE[@]}" olddefconfig &>/dev/null
fi

echo
SECONDS=0
"${MAKE[@]}" -j"$(nproc --all)" 2> >(tee log.txt >&2)
BUILD_TIME=$SECONDS

kernel="out/arch/arm64/boot/Image.gz"
dtb="out/arch/arm64/boot/dtb.img"
dtbo="out/arch/arm64/boot/dtbo.img"
dtbo_miui="out/arch/arm64/boot/dtbo-miui.img"

if [ ! -f "$kernel" ] || [ ! -f "$dtb" ] || [ ! -f "$dtbo" ] || [ ! -f "$dtbo_miui" ]; then
	echo -e "\nMissing build artifacts, aborting."
	exit 1
fi

echo -e "\nKernel compiled successfully! Zipping up..."
cp "$kernel" "$dtb" "$dtbo" "$dtbo_miui" "$AK3_DIR"
cd "$AK3_DIR"
zip -r1 "../$ZIPNAME" ./* -x .git modules\* patch\* ramdisk\* README.md \*placeholder &>/dev/null
rm -f Image.gz dtb.img dtbo.img dtbo-miui.img
cd ..
echo -e "\nCompleted in $((BUILD_TIME / 60)) minute(s) and $((BUILD_TIME % 60)) second(s)!"
echo "Zip: $ZIPNAME"
