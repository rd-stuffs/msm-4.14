#!/usr/bin/env python3
#
# Compile and prebuilt export script for FSociety kernel
#

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

WD = Path(__file__).resolve().parent
DEFCONFIG = "surya_defconfig"
GCC64 = WD / "tc/gcc-arm64"
GCC32 = WD / "tc/gcc-arm"
GCC_API = "https://api.github.com/repos/mvaisakh/gcc-build/releases/latest"
GCC_DOWNLOAD = "https://github.com/mvaisakh/gcc-build/releases/download"
AK3 = WD / "AnyKernel3"
AK3_URL = "https://github.com/rd-stuffs/AnyKernel3"
AK3_BRANCH = "FSociety"
PREBUILT_REMOTE = "git@github.com:rd-stuffs/device_xiaomi_surya-kernel.git"


def run(cmd, **kwargs):
    kwargs.setdefault("check", True)
    if isinstance(cmd, str) and "shell" not in kwargs:
        kwargs["shell"] = True
    return subprocess.run(cmd, **kwargs)


def get_sha():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def get_remote_gcc_tag():
    cache = GCC64.parent / ".eva_tag_cache"
    if cache.is_file() and (time.time() - cache.stat().st_mtime < 3600):
        return cache.read_text().strip()
    try:
        headers = {"User-Agent": "build.py"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"
        req = urllib.request.Request(GCC_API, headers=headers)
        with urllib.request.urlopen(req, timeout=3) as r:
            tag = json.loads(r.read().decode("utf-8")).get("tag_name", "")
            if tag:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(tag)
            return tag
    except Exception:
        return cache.read_text().strip() if cache.is_file() else ""


def ensure_toolchains(auto_update=False):
    tag = get_remote_gcc_tag()
    tag_file = GCC64 / ".eva_tag"
    installed = tag_file.read_text().strip() if tag_file.is_file() else ""

    if installed and tag and installed != tag:
        should_update = auto_update or (
            sys.stdin.isatty() and input(f"Eva GCC update available ({tag}). Update? [y/N] ").strip().lower() == "y"
        )
        if should_update:
            shutil.rmtree(GCC64, ignore_errors=True)
            shutil.rmtree(GCC32, ignore_errors=True)

    if not GCC64.is_dir() or not GCC32.is_dir():
        if not tag:
            sys.exit("No internet connection and toolchain is missing, aborting.")
        for arch, d in (("arm64", GCC64), ("arm", GCC32)):
            if not d.is_dir():
                print(f"Downloading Eva GCC {arch} ({tag})...")
                d.mkdir(parents=True, exist_ok=True)
                url = f"{GCC_DOWNLOAD}/{tag}/eva-gcc-{arch}-{tag}.xz"
                run(f"curl -fL# '{url}' | tar xf - --strip-components=1 -C '{d}'")
                (d / ".eva_tag").write_text(f"{tag}\n")


def get_compiler_string():
    return subprocess.check_output([str(GCC64 / "bin/aarch64-elf-gcc"), "--version"], text=True).splitlines()[0]


def setup_env():
    gcc64_bin = GCC64 / "bin"
    gcc32_bin = GCC32 / "bin"
    os.environ["PATH"] = f"{gcc64_bin}:{gcc32_bin}:{os.environ.get('PATH', '')}"

    cc = "aarch64-elf-gcc"
    if shutil.which("ccache"):
        os.environ["CCACHE_DIR"] = str(WD / ".ccache")
        os.environ.setdefault("CCACHE_MAXSIZE", "5G")
        os.environ["CCACHE_BASEDIR"] = str(WD)
        cc = f"ccache {cc}"

    return [
        "make",
        "CROSS_COMPILE=aarch64-elf-",
        "CROSS_COMPILE_COMPAT=arm-eabi-",
        f"LD={gcc64_bin}/aarch64-elf-ld",
        "AR=aarch64-elf-gcc-ar",
        "AS=aarch64-elf-as",
        "NM=aarch64-elf-nm",
        "OBJDUMP=aarch64-elf-objdump",
        "OBJCOPY=aarch64-elf-objcopy",
        f"CC={cc}",
        "LLVM=0",
        "LLVM_IAS=0",
    ]


def package_ak3(zip_name, artifacts):
    with zipfile.ZipFile(WD / zip_name, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        for root, dirs, files in os.walk(AK3):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("modules", "patch", "ramdisk")]
            for f in files:
                if f == "README.md" or f.endswith("placeholder") or f.startswith("."):
                    continue
                path = Path(root) / f
                zf.write(path, path.relative_to(AK3))
        for art in artifacts:
            zf.write(art, art.name)


def export_prebuilt():
    boot = Path("out/arch/arm64/boot")
    artifacts = [boot / "Image.gz", boot / "dtbo.img", boot / "dts/qcom/sdmmagpie.dtb"]
    if not all(p.is_file() for p in artifacts):
        sys.exit("Missing build artifacts, run build.py first.")

    if not Path("out/usr/include").is_dir():
        print("Installing kernel headers...")
        run("make ARCH=arm64 O=out CROSS_COMPILE=aarch64-elf- headers_install", stdout=subprocess.DEVNULL)

    prebuilt = Path("out/prebuilt")
    shutil.rmtree(prebuilt, ignore_errors=True)
    (prebuilt / "kernel-headers/usr").mkdir(parents=True, exist_ok=True)
    (prebuilt / "dtb").mkdir(parents=True, exist_ok=True)

    (prebuilt / artifacts[0].name).hardlink_to(artifacts[0])
    (prebuilt / artifacts[1].name).hardlink_to(artifacts[1])
    (prebuilt / "dtb" / artifacts[2].name).hardlink_to(artifacts[2])

    run("rsync -a --exclude='*.install*' out/usr/include out/usr/techpack out/prebuilt/kernel-headers/usr")

    mf = Path("Makefile").read_text()
    v = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(.*)", mf, re.M))
    (prebuilt / "kernel-headers/Makefile").write_text(
        f"VERSION = {v.get('VERSION', '')}\nPATCHLEVEL = {v.get('PATCHLEVEL', '')}\nSUBLEVEL = {v.get('SUBLEVEL', '')}\n\n"
        "headers_install:\n\t@mkdir -p $(O)/usr\n\t@rsync -mrq $(shell pwd)/* $(O)/\n\nall:\n\t@true\n"
    )

    info = f"HEAD: {get_sha()}\n{get_compiler_string()}"
    run(["git", "-C", prebuilt, "init", "-q"])
    run(["git", "-C", prebuilt, "checkout", "-qb", "staging"])
    run(["git", "-C", prebuilt, "add", "-A"])
    run(["git", "-C", prebuilt, "commit", "-q", "-m", "surya-kernel: Import prebuilt artifacts", "-m", info])
    run(["git", "-C", prebuilt, "push", "-qf", PREBUILT_REMOTE, "staging"])
    print(f"{info}\nPrebuilt artifacts exported successfully.")


def main():
    os.chdir(WD)

    parser = argparse.ArgumentParser(description="Compile script and prebuilt exporter for FSociety kernel.")
    parser.add_argument("-c", "--clean", action="store_true", help="clean output directory before compilation")
    parser.add_argument("-l", "--lto", action="store_true", help="enable GCC Link-Time Optimization (LTO)")
    parser.add_argument("-s", "--su", action="store_true", help="build KernelSU variant")
    parser.add_argument("-j", "--jobs", type=int, help="parallel make jobs (default: 10 for LTO, 12 for non-LTO)")
    parser.add_argument("-u", "--update", action="store_true", help="automatically update toolchain if a newer version is available")
    parser.add_argument("-r", "--regen", action="store_true", help="standalone: regenerate savedefconfig and exit")
    parser.add_argument("-rf", "--regen-full", action="store_true", help="standalone: regenerate full defconfig and exit")
    parser.add_argument("-p", "--prebuilt", action="store_true", help="standalone: export prebuilt kernel artifacts to staging branch")

    args = parser.parse_args()
    args.jobs = args.jobs or (10 if args.lto else 12)

    ensure_toolchains(auto_update=args.update)
    make_cmd = setup_env()

    if args.regen or args.regen_full:
        target = [DEFCONFIG] if args.regen_full else [DEFCONFIG, "savedefconfig"]
        run(make_cmd + target)
        src = "out/.config" if args.regen_full else "out/defconfig"
        shutil.copy2(src, f"arch/arm64/configs/{DEFCONFIG}")
        print(f"\nSuccessfully regenerated {'full ' if args.regen_full else ''}defconfig at {DEFCONFIG}")
        return

    if args.prebuilt:
        export_prebuilt()
        return

    os.environ["KBUILD_COMPILER_STRING"] = get_compiler_string()

    if not AK3.is_dir():
        print(f"Cloning AnyKernel3 to {AK3}...")
        run(f"git clone --depth=1 -b {AK3_BRANCH} {AK3_URL} '{AK3}'")

    prefix = "FSociety-KSU" if args.su else "FSociety-surya"
    zipname = f"{prefix}-{datetime.now():%Y%m%d-%H%M}-{get_sha()[:8]}.zip"

    if args.clean:
        print("Cleaning output directory...")
        shutil.rmtree("out", ignore_errors=True)

    print("Building surya defconfig...")
    run(make_cmd + [DEFCONFIG], stdout=subprocess.DEVNULL)

    cfg_modified = False
    if args.lto:
        run("./scripts/config --file out/.config -e LTO_GCC")
        cfg_modified = True

    if args.su:
        print("Building KernelSU variant...")
        run("./scripts/config --file out/.config -e KSU -e KSU_TAMPER_SYSCALL_TABLE -d KSU_FEATURE_SULOG -e KSU_THRONE_TRACKER_ALWAYS_THREADED")
        cfg_modified = True

    if cfg_modified:
        run(make_cmd + ["olddefconfig"], stdout=subprocess.DEVNULL)

    t0 = time.time()
    with open("log.txt", "wb") as log_f:
        proc = subprocess.Popen(make_cmd + [f"-j{args.jobs}"], stderr=subprocess.PIPE)
        try:
            while chunk := proc.stderr.read1(65536):
                sys.stderr.buffer.write(chunk)
                sys.stderr.buffer.flush()
                log_f.write(chunk)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

    if proc.returncode != 0:
        sys.exit(f"\nBuild failed with exit code {proc.returncode}.")

    boot = Path("out/arch/arm64/boot")
    artifacts = [boot / f for f in ("Image.gz", "dtb.img", "dtbo.img", "dtbo-miui.img")]
    if not all(p.is_file() for p in artifacts):
        sys.exit("\nMissing build artifacts, aborting.")

    print("\nKernel compiled successfully! Zipping up...")
    package_ak3(zipname, artifacts)

    elapsed = int(time.time() - t0)
    print(f"\nCompleted in {elapsed // 60} minute(s) and {elapsed % 60} second(s)!\nZip: {zipname}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
