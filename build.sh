#!/bin/bash
#
# Compile script for RDKernel
# Copyright (C) 2020-2023 Adithya R.

SECONDS=0 # builtin bash timer
ZIPNAME="RDKernel-surya-$(date '+%Y%m%d-%H%M').zip"
TC_DIR="$(pwd)/tc/clang-r450784e"
AK3_DIR="$(pwd)/AnyKernel3"
DEFCONFIG="surya_defconfig"

if test -z "$(git rev-parse --show-cdup 2>/dev/null)" &&
   head=$(git rev-parse --verify HEAD 2>/dev/null); then
   ZIPNAME="${ZIPNAME::-4}-$(echo $head | cut -c1-8).zip"
fi

MAKE_PARAMS="O=out ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 \
	CROSS_COMPILE=aarch64-linux-gnu- \
	CROSS_COMPILE_COMPAT=arm-linux-gnueabi-"

export PATH="$TC_DIR/bin:$PATH"

if ! [ -d "$TC_DIR" ]; then
	echo "AOSP clang not found! Cloning to $TC_DIR..."
	if ! git clone --depth=1 -b 14 https://gitlab.com/ThankYouMario/android_prebuilts_clang-standalone "$TC_DIR"; then
		echo "Cloning failed! Aborting..."
		exit 1
	fi
fi

if [[ $1 = "-r" || $1 = "--regen" ]]; then
   make $MAKE_PARAMS $DEFCONFIG savedefconfig
   cp out/defconfig arch/arm64/configs/$DEFCONFIG
   echo -e "\nSuccessfully regenerated defconfig at arch/arm64/configs/$DEFCONFIG"
   exit
fi

if [[ $1 = "-rf" || $1 = "--regen-full" ]]; then
   make $MAKE_PARAMS $DEFCONFIG
   cp out/.config arch/arm64/configs/$DEFCONFIG
   echo -e "\nSuccessfully regenerated full defconfig at arch/arm64/configs/$DEFCONFIG"
   exit
fi

if [[ $1 = "-c" || $1 = "--clean" ]]; then
   rm -rf out
   echo "Cleaned output folder"
fi

mkdir -p out
make $MAKE_PARAMS $DEFCONFIG

echo -e "\nStarting compilation...\n"
make -j$(nproc --all) $MAKE_PARAMS Image.gz dtb.img dtbo.img 2> >(tee log.txt >&2) || exit $?

kernel="out/arch/arm64/boot/Image.gz"
dtb="out/arch/arm64/boot/dtb.img"
dtbo="out/arch/arm64/boot/dtbo.img"

if [ ! -f "$kernel" ] || [ ! -f "$dtb" ] || [ ! -f "$dtbo" ]; then
	echo -e "\nCompilation failed!"
	exit 1
fi

echo -e "\nKernel compiled succesfully! Zipping up...\n"
if [ -d "$AK3_DIR" ]; then
	cp -r $AK3_DIR AnyKernel3
	git -C AnyKernel3 checkout RDKernel &> /dev/null
elif ! git clone -q https://github.com/rd-stuffs/AnyKernel3 -b RDKernel; then
	echo -e "\nAnyKernel3 repo not found locally and couldn't clone from GitHub! Aborting..."
	exit 1
fi
cp $kernel $dtb $dtbo AnyKernel3
rm -rf out/arch/arm64/boot
cd AnyKernel3
zip -r9 "../$ZIPNAME" * -x '*.git*' README.md *placeholder
cd ..
rm -rf AnyKernel3
echo -e "\nCompleted in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s) !"
echo "$(realpath $ZIPNAME)"
