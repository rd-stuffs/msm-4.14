// SPDX-License-Identifier: GPL-2.0-only

#include <linux/crc32.h>
#include <linux/kernel.h>
#include <linux/linkage.h>

#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>

// The minimum input length to consider the 4-way interleaved code path
static const size_t min_len = 1024;

asmlinkage u32 crc32_le_arm64(u32 crc, unsigned char const *p, size_t len);
asmlinkage u32 crc32c_le_arm64(u32 crc, unsigned char const *p, size_t len);
asmlinkage u32 crc32_be_arm64(u32 crc, unsigned char const *p, size_t len);

asmlinkage u32 crc32_le_arm64_4way(u32 crc, unsigned char const *p, size_t len);
asmlinkage u32 crc32c_le_arm64_4way(u32 crc, unsigned char const *p, size_t len);
asmlinkage u32 crc32_be_arm64_4way(u32 crc, unsigned char const *p, size_t len);

u32 __pure crc32_le(u32 crc, unsigned char const *p, size_t len)
{
	if (len >= min_len && (elf_hwcap & HWCAP_PMULL) && may_use_simd()) {
		kernel_neon_begin();
		crc = crc32_le_arm64_4way(crc, p, len);
		kernel_neon_end();

		p += round_down(len, 64);
		len %= 64;

		if (!len)
			return crc;
	}

	return crc32_le_arm64(crc, p, len);
}

u32 __pure __crc32c_le(u32 crc, unsigned char const *p, size_t len)
{
	if (len >= min_len && (elf_hwcap & HWCAP_PMULL) && may_use_simd()) {
		kernel_neon_begin();
		crc = crc32c_le_arm64_4way(crc, p, len);
		kernel_neon_end();

		p += round_down(len, 64);
		len %= 64;

		if (!len)
			return crc;
	}

	return crc32c_le_arm64(crc, p, len);
}

u32 __pure crc32_be(u32 crc, unsigned char const *p, size_t len)
{
	if (len >= min_len && (elf_hwcap & HWCAP_PMULL) && may_use_simd()) {
		kernel_neon_begin();
		crc = crc32_be_arm64_4way(crc, p, len);
		kernel_neon_end();

		p += round_down(len, 64);
		len %= 64;

		if (!len)
			return crc;
	}

	return crc32_be_arm64(crc, p, len);
}
