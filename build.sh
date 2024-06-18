#!/bin/bash
#
# Compile script for AOSP kernels
# Copyright (C) 2020-2023 Adithya R.

SECONDS=0 # builtin bash timer
ZIPNAME="kernel-surya-$(date '+%Y%m%d-%H%M').zip"
TC_DIR="$(pwd)/tc/clang-neutron"
AK3_DIR="$(pwd)/AnyKernel3"
DEFCONFIG="surya_defconfig"

if test -z "$(git rev-parse --show-cdup 2>/dev/null)" &&
   head=$(git rev-parse --verify HEAD 2>/dev/null); then
   ZIPNAME="${ZIPNAME::-4}-$(echo $head | cut -c1-8).zip"
fi

MAKE_PARAMS="O=out ARCH=arm64 CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
   CLANG_TRIPLE=aarch64-linux-gnu- \
   CROSS_COMPILE=aarch64-linux-gnu-"

PATH="$TC_DIR/bin:$PATH"

if ! [ -d "$TC_DIR" ]; then
   echo "Neutron Clang not found! Downloading to $TC_DIR..."
   mkdir -p "$TC_DIR" && cd "$TC_DIR"
   curl -LO "https://raw.githubusercontent.com/Neutron-Toolchains/antman/main/antman"
   bash ./antman -S
   cd ../..
fi

cd "$TC_DIR" && bash ./antman -U && cd ../..

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
   git -C AnyKernel3 checkout master &> /dev/null
elif ! git clone --depth=1 -q https://github.com/rd-stuffs/AnyKernel3 -b master; then
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
echo "$ZIPNAME"
