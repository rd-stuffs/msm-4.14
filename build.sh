#!/bin/bash
#
# Compile script for FSociety kernel
# Copyright (C) 2020-2021 Adithya R.

SECONDS=0
ZIPNAME="FSociety-surya-$(date '+%Y%m%d-%H%M').zip"
LLVM_REV="22"
TC_DIR="$(pwd)/tc/clang-$LLVM_REV"
AK3_DIR="$(pwd)/android/AnyKernel3"
DEFCONFIG="surya_defconfig"

if test -z "$(git rev-parse --show-cdup 2>/dev/null)" &&
   head=$(git rev-parse --verify HEAD 2>/dev/null); then
	ZIPNAME="${ZIPNAME::-4}-$(echo $head | cut -c1-8).zip"
fi

export PATH="$TC_DIR/bin:$PATH"

if ! [ -d "$TC_DIR" ]; then
	echo "Slim LLVM not found! Cloning to $TC_DIR..."
	if ! git clone --depth=1 -b $LLVM_REV https://bitbucket.org/rdxzv/clang-standalone.git "$TC_DIR"; then
		echo "Cloning failed! Aborting..."
		exit 1
	fi
fi

if ! [ -d "$AK3_DIR" ]; then
	echo "AnyKernel3 not found! Cloning to $AK3_DIR..."
	if ! git clone --depth=1 -b FSociety https://github.com/rd-stuffs/AnyKernel3.git "$AK3_DIR"; then
		echo "Cloning failed! Aborting..."
		exit 1
	fi
fi

if [[ $1 = "-rf" || $1 = "--regen-full" ]]; then
	make $DEFCONFIG
	cp out/.config arch/arm64/configs/$DEFCONFIG
	echo -e "\nSuccessfully regenerated full defconfig at $DEFCONFIG"
	exit
fi

CLEAN=false
KSU=false

for arg in "$@"; do
	case $arg in
		-c|--clean)
			CLEAN=true
			;;
		-s|--su)
			KSU=true
			;;
		*)
			echo "Unknown argument: $arg"
			exit 1
			;;
	esac
done

if [[ "$CLEAN" = true ]]; then
	rm -rf out
fi

echo -e "\nStarting compilation...\n"
make $DEFCONFIG

if [[ "$KSU" = true ]]; then
	echo -e "\nBuilding with KernelSU support...\n"
	ZIPNAME="${ZIPNAME/FSociety-surya/FSociety-KSU}"
	scripts/config --file out/.config -e KSU -e KSU_MANUAL_HOOK
	make olddefconfig
fi

make -j$(nproc --all) LLVM=1 Image.gz dtb.img dtbo.img 2> >(tee log.txt >&2) || exit $?

kernel="out/arch/arm64/boot/Image.gz"
dtb="out/arch/arm64/boot/dtb.img"
dtbo="out/arch/arm64/boot/dtbo.img"

if [ -f "$kernel" ] && [ -f "$dtb" ] && [ -f "$dtbo" ]; then
	echo -e "\nKernel compiled successfully! Zipping up...\n"
	cp -r $AK3_DIR AnyKernel3
	cp $kernel $dtb $dtbo AnyKernel3
	cd AnyKernel3
	git checkout FSociety &> /dev/null
	zip -r9 "../$ZIPNAME" * -x .git modules\* patch\* ramdisk\* README.md *placeholder
	cd ..
	rm -rf AnyKernel3
	echo -e "\nCompleted in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s) !"
	echo "Zip: $ZIPNAME"
else
	echo -e "\nCompilation failed!"
	exit 1
fi
