/*
./configure --disable-jobserver --enable-opensslextra --enable-supportedcurves --enable-sp --enable-sp-asm --enable-intelasm --enable-ed25519 --enable-des3 --enable-ripemd --enable-aesni
*/

/* benchmark.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/* wolfCrypt benchmark */


#include <errno.h>
#include <unistd.h>

#include <stdlib.h>						/* we're using malloc / free direct here */
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define RNG_MAX_BLOCK_LEN (0x10000l)

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#undef LIBCALL_CHECK_RET
#define LIBCALL_CHECK_RET(...) do {                           \
        int _libcall_ret = (__VA_ARGS__);                     \
        if (_libcall_ret < 0) {                               \
            fprintf(stderr, "%s L%d error %d for \"%s\"\n",   \
                    __FILE__, __LINE__, errno, #__VA_ARGS__); \
            exit(1);                                          \
        }                                                     \
    } while(0)

#define TEST_STRING    "Everyone gets Friday off."
#define TEST_STRING_SZ 25


/* Bit values for each algorithm that is able to be benchmarked.
 * Common grouping of algorithms also.
 * Each algorithm has a unique value for its type e.g. cipher.
 */
/* Cipher algorithms. */
#define BENCH_AES_CBC            0x00000001
#define BENCH_AES_GCM            0x00000002
#define BENCH_AES_ECB            0x00000004
#define BENCH_AES_XTS            0x00000008
#define BENCH_AES_CTR            0x00000010
#define BENCH_AES_CCM            0x00000020
#define BENCH_CAMELLIA           0x00000100
#define BENCH_ARC4               0x00000200
#define BENCH_CHACHA20           0x00001000
#define BENCH_CHACHA20_POLY1305  0x00002000
#define BENCH_DES                0x00004000
#define BENCH_AES_CFB            0x00010000
#define BENCH_AES_OFB            0x00020000
#define BENCH_AES_SIV            0x00040000
/* Digest algorithms. */
#define BENCH_MD5                0x00000001
#define BENCH_POLY1305           0x00000002
#define BENCH_SHA                0x00000004
#define BENCH_SHA224             0x00000010
#define BENCH_SHA256             0x00000020
#define BENCH_SHA384             0x00000040
#define BENCH_SHA512             0x00000080
#define BENCH_SHA2               (BENCH_SHA224 | BENCH_SHA256 | \
                                  BENCH_SHA384 | BENCH_SHA512)
#define BENCH_SHA3_224           0x00000100
#define BENCH_SHA3_256           0x00000200
#define BENCH_SHA3_384           0x00000400
#define BENCH_SHA3_512           0x00000800
#define BENCH_SHA3               (BENCH_SHA3_224 | BENCH_SHA3_256 | \
                                  BENCH_SHA3_384 | BENCH_SHA3_512)
#define BENCH_SHAKE128           0x00001000
#define BENCH_SHAKE256           0x00002000
#define BENCH_SHAKE              (BENCH_SHAKE128 | BENCH_SHAKE256)
#define BENCH_RIPEMD             0x00004000
#define BENCH_BLAKE2B            0x00008000
#define BENCH_BLAKE2S            0x00010000

/* MAC algorithms. */
#define BENCH_CMAC               0x00000001
#define BENCH_HMAC_MD5           0x00000002
#define BENCH_HMAC_SHA           0x00000004
#define BENCH_HMAC_SHA224        0x00000010
#define BENCH_HMAC_SHA256        0x00000020
#define BENCH_HMAC_SHA384        0x00000040
#define BENCH_HMAC_SHA512        0x00000080
#define BENCH_HMAC               (BENCH_HMAC_MD5    | BENCH_HMAC_SHA    | \
                                  BENCH_HMAC_SHA224 | BENCH_HMAC_SHA256 | \
                                  BENCH_HMAC_SHA384 | BENCH_HMAC_SHA512)
#define BENCH_PBKDF2             0x00000100
#define BENCH_SIPHASH            0x00000200

/* Asymmetric algorithms. */
#define BENCH_RSA_KEYGEN         0x00000001
#define BENCH_RSA                0x00000002
#define BENCH_RSA_SZ             0x00000004
#define BENCH_DH                 0x00000010
#define BENCH_KYBER              0x00000020
#define BENCH_ECC_MAKEKEY        0x00001000
#define BENCH_ECC                0x00002000
#define BENCH_ECC_ENCRYPT        0x00004000
#define BENCH_ECC_ALL            0x00008000
#define BENCH_CURVE25519_KEYGEN  0x00010000
#define BENCH_CURVE25519_KA      0x00020000
#define BENCH_ED25519_KEYGEN     0x00040000
#define BENCH_ED25519_SIGN       0x00080000
#define BENCH_CURVE448_KEYGEN    0x00100000
#define BENCH_CURVE448_KA        0x00200000
#define BENCH_ED448_KEYGEN       0x00400000
#define BENCH_ED448_SIGN         0x00800000
#define BENCH_ECC_P256           0x01000000
#define BENCH_ECC_P384           0x02000000
#define BENCH_ECC_P521           0x04000000
#define BENCH_ECCSI_KEYGEN       0x00000020
#define BENCH_ECCSI_PAIRGEN      0x00000040
#define BENCH_ECCSI_VALIDATE     0x00000080
#define BENCH_ECCSI              0x00000400

/* Post-Quantum Asymmetric algorithms. */
#define BENCH_FALCON_LEVEL1_SIGN        0x00000001
#define BENCH_FALCON_LEVEL5_SIGN        0x00000002
#define BENCH_KYBER_LEVEL1_KEYGEN       0x00000004
#define BENCH_KYBER_LEVEL1_ENCAP        0x00000008
#define BENCH_KYBER_LEVEL3_KEYGEN       0x00000010
#define BENCH_KYBER_LEVEL3_ENCAP        0x00000020
#define BENCH_KYBER_LEVEL5_KEYGEN       0x00000040
#define BENCH_KYBER_LEVEL5_ENCAP        0x00000080
#define BENCH_KYBER90S_LEVEL1_KEYGEN    0x00000100
#define BENCH_KYBER90S_LEVEL1_ENCAP     0x00000200
#define BENCH_KYBER90S_LEVEL3_KEYGEN    0x00000400
#define BENCH_KYBER90S_LEVEL3_ENCAP     0x00000800
#define BENCH_KYBER90S_LEVEL5_KEYGEN    0x00001000
#define BENCH_KYBER90S_LEVEL5_ENCAP     0x00002000
#define BENCH_SABER_LEVEL1_KEYGEN       0x00004000
#define BENCH_SABER_LEVEL1_ENCAP        0x00008000
#define BENCH_SABER_LEVEL3_KEYGEN       0x00010000
#define BENCH_SABER_LEVEL3_ENCAP        0x00020000
#define BENCH_SABER_LEVEL5_KEYGEN       0x00040000
#define BENCH_SABER_LEVEL5_ENCAP        0x00080000
#define BENCH_NTRUHPS_LEVEL1_KEYGEN     0x00100000
#define BENCH_NTRUHPS_LEVEL1_ENCAP      0x00200000
#define BENCH_NTRUHPS_LEVEL3_KEYGEN     0x00400000
#define BENCH_NTRUHPS_LEVEL3_ENCAP      0x00800000
#define BENCH_NTRUHPS_LEVEL5_KEYGEN     0x01000000
#define BENCH_NTRUHPS_LEVEL5_ENCAP      0x02000000
#define BENCH_DILITHIUM_LEVEL2_SIGN     0x04000000
#define BENCH_DILITHIUM_LEVEL3_SIGN     0x08000000
#define BENCH_DILITHIUM_LEVEL5_SIGN     0x10000000
#define BENCH_DILITHIUM_AES_LEVEL2_SIGN 0x20000000
#define BENCH_DILITHIUM_AES_LEVEL3_SIGN 0x40000000
#define BENCH_DILITHIUM_AES_LEVEL5_SIGN 0x80000000

/* Post-Quantum Asymmetric algorithms. (Part 2) */
#define BENCH_SPHINCS_FAST_LEVEL1_SIGN  0x00000001
#define BENCH_SPHINCS_FAST_LEVEL3_SIGN  0x00000002
#define BENCH_SPHINCS_FAST_LEVEL5_SIGN  0x00000004
#define BENCH_SPHINCS_SMALL_LEVEL1_SIGN 0x00000008
#define BENCH_SPHINCS_SMALL_LEVEL3_SIGN 0x00000010
#define BENCH_SPHINCS_SMALL_LEVEL5_SIGN 0x00000020

/* Other */
#define BENCH_RNG                0x00000001
#define BENCH_SCRYPT             0x00000002


/* Benchmark all compiled in algorithms.
 * When 1, ignore other benchmark algorithm values.
 *      0, only benchmark algorithm values set.
 */
static int bench_all = 1;

/* Cipher algorithms to benchmark. */
static int bench_cipher_algs = 0;

/* Digest algorithms to benchmark. */
static int bench_digest_algs = 0;

/* MAC algorithms to benchmark. */
static int bench_mac_algs = 0;

/* Asymmetric algorithms to benchmark. */
static int bench_asym_algs = 0;

/* Other cryptographic algorithms to benchmark. */
static int bench_other_algs = 0;

/* The mapping of command line option to bit values. */
typedef struct bench_alg
{
	/* Command line option string. */
	const char *str;
	/* Bit values to set. */
	uint32_t val;
} bench_alg;

/* All recognized cipher algorithm choosing command line options. */
static const bench_alg bench_cipher_opt[] = {
	{ "-cipher", 0xffffffff },
	{ "-aes-cbc", BENCH_AES_CBC },
	{ "-aes-gcm", BENCH_AES_GCM },
	{ "-chacha20", BENCH_CHACHA20 },
	{ "-chacha20-poly1305", BENCH_CHACHA20_POLY1305 },
	{ "-des", BENCH_DES },
	{ NULL, 0 }
};

/* All recognized digest algorithm choosing command line options. */
static const bench_alg bench_digest_opt[] = {
	{ "-digest", 0xffffffff },
	{ "-md5", BENCH_MD5 },
	{ "-poly1305", BENCH_POLY1305 },
	{ "-sha", BENCH_SHA },
	{ "-sha2", BENCH_SHA2 },
	{ "-sha224", BENCH_SHA224 },
	{ "-sha256", BENCH_SHA256 },
	{ "-sha384", BENCH_SHA384 },
	{ "-sha512", BENCH_SHA512 },
	{ "-sha3", BENCH_SHA3 },
	{ "-sha3-224", BENCH_SHA3_224 },
	{ "-sha3-256", BENCH_SHA3_256 },
	{ "-sha3-384", BENCH_SHA3_384 },
	{ "-sha3-512", BENCH_SHA3_512 },
	{ "-ripemd", BENCH_RIPEMD },
	{ NULL, 0 }
};

/* All recognized MAC algorithm choosing command line options. */
static const bench_alg bench_mac_opt[] = {
	{ "-mac", 0xffffffff },
	{ "-hmac", BENCH_HMAC },
	{ "-hmac-md5", BENCH_HMAC_MD5 },
	{ "-hmac-sha", BENCH_HMAC_SHA },
	{ "-hmac-sha224", BENCH_HMAC_SHA224 },
	{ "-hmac-sha256", BENCH_HMAC_SHA256 },
	{ "-hmac-sha384", BENCH_HMAC_SHA384 },
	{ "-hmac-sha512", BENCH_HMAC_SHA512 },
	{ "-pbkdf2", BENCH_PBKDF2 },
	{ NULL, 0 }
};

/* All recognized asymmetric algorithm choosing command line options. */
static const bench_alg bench_asym_opt[] = {
	{ "-asym", 0xffffffff },
	{ "-rsa", BENCH_RSA },
	{ "-rsa-sz", BENCH_RSA_SZ },
	{ "-dh", BENCH_DH },
	{ "-ecc-kg", BENCH_ECC_MAKEKEY },
	{ "-ecc", BENCH_ECC },
	{ "-ecc-all", BENCH_ECC_ALL },
	{ "-ed25519-kg", BENCH_ED25519_KEYGEN },
	{ "-ed25519", BENCH_ED25519_SIGN },
	{ NULL, 0 }
};

/* All recognized other cryptographic algorithm choosing command line options.
 */
static const bench_alg bench_other_opt[] = {
	{ "-other", 0xffffffff },
	{ "-rng", BENCH_RNG },
	{ NULL, 0 }
};

#define lng_index 0

static const char *bench_Usage_msg1[][18] = {
	/* 0 English  */
	{"-? <num>    Help, print this usage\n            0: English, 1: Japanese\n",
	 "-csv        Print terminal output in csv format\n",
	 "-base10     Display bytes as power of 10 (eg 1 kB = 1000 Bytes)\n",
	 "-no_aad     No additional authentication data passed.\n",
	 "-dgst_full  Full digest operation performed.\n",
	 "-rsa_sign   Measure RSA sign/verify instead of encrypt/decrypt.\n",
	 "<keySz> -rsa-sz\n            Measure RSA <key size> performance.\n",
	 "-ffhdhe2048 Measure DH using FFDHE 2048-bit parameters.\n",
	 "-ffhdhe3072 Measure DH using FFDHE 3072-bit parameters.\n",
	 "-p256       Measure ECC using P-256 curve.\n",
	 "-p384       Measure ECC using P-384 curve.\n",
	 "-p521       Measure ECC using P-521 curve.\n",
	 "-ecc-all    Bench all enabled ECC curves.\n",
	 "-<alg>      Algorithm to benchmark. Available algorithms include:\n",
	 "-lng <num>  Display benchmark result by specified language.\n            0: English, 1: Japanese\n",
	 "<num>       Size of block in bytes\n",
	 "-threads <num> Number of threads to run\n",
	 "-print      Show benchmark stats summary\n"
	}
};

static const char *bench_result_words1[][4] = {
	{ "took", "seconds", "Cycles per byte", NULL }
};

static const char *bench_desc_words[][15] = {
	/* 0           1          2         3        4        5         6            7            8          9        10        11       12          13       14 */
	{ "public", "private", "key gen", "agree", "sign", "verify", "encryption", "decryption", "rsk gen", "encap", "derive", "valid", "pair gen", "decap", NULL }
};

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_ASM)
#define HAVE_GET_CYCLES
static uint64_t get_intel_cycles(void);
static uint64_t total_cycles;

#define INIT_CYCLE_COUNTER
#define BEGIN_INTEL_CYCLES total_cycles = get_intel_cycles();
#define END_INTEL_CYCLES   total_cycles = get_intel_cycles() - total_cycles;
	/* s == size in bytes that 1 count represents, normally BENCH_SIZE */
#define SHOW_INTEL_CYCLES(b, n, s) \
        (void)snprintf((b) + strlen(b), (n) - strlen(b), " %s = %6.2f\n", \
            bench_result_words1[lng_index][2], \
            count == 0 ? 0 : (float)total_cycles / ((uint64_t)count*(s)))
#define SHOW_INTEL_CYCLES_CSV(b, n, s) \
        (void)snprintf((b) + strlen(b), (n) - strlen(b), "%.2f,\n", \
            count == 0 ? 0 : (float)total_cycles / ((uint64_t)count*(s)))
#elif defined(LINUX_CYCLE_COUNT)
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

static uint64_t begin_cycles;
static uint64_t total_cycles;
static int cycles = -1;
static struct perf_event_attr atr;

#define INIT_CYCLE_COUNTER do { \
        atr.type   = PERF_TYPE_HARDWARE; \
        atr.config = PERF_COUNT_HW_CPU_CYCLES; \
        cycles = (int)syscall(__NR_perf_event_open, &atr, 0, -1, -1, 0); \
    } while (0);

#define BEGIN_INTEL_CYCLES read(cycles, &begin_cycles, sizeof(begin_cycles));
#define END_INTEL_CYCLES   do { \
        read(cycles, &total_cycles, sizeof(total_cycles)); \
        total_cycles = total_cycles - begin_cycles; \
    } while (0);

	/* s == size in bytes that 1 count represents, normally BENCH_SIZE */
#define SHOW_INTEL_CYCLES(b, n, s) \
        (void)snprintf(b + strlen(b), n - strlen(b), " %s = %6.2f\n", \
        bench_result_words1[lng_index][2], \
            (float)total_cycles / (count*s))
#define SHOW_INTEL_CYCLES_CSV(b, n, s) \
        (void)snprintf(b + strlen(b), n - strlen(b), "%.2f,\n", \
            (float)total_cycles / (count*s))

#elif defined(SYNERGY_CYCLE_COUNT)
#include "hal_data.h"
static uint64_t begin_cycles;
static uint64_t total_cycles;

#define INIT_CYCLE_COUNTER
#define BEGIN_INTEL_CYCLES begin_cycles = DWT->CYCCNT = 0;
#define END_INTEL_CYCLES   total_cycles =  DWT->CYCCNT - begin_cycles;

	/* s == size in bytes that 1 count represents, normally BENCH_SIZE */
#define SHOW_INTEL_CYCLES(b, n, s) \
        (void)snprintf(b + strlen(b), n - strlen(b), " %s = %6.2f\n", \
        bench_result_words1[lng_index][2], \
            (float)total_cycles / (count*s))
#define SHOW_INTEL_CYCLES_CSV(b, n, s) \
        (void)snprintf(b + strlen(b), n - strlen(b), "%.2f,\n", \
            (float)total_cycles / (count*s))

#else
#define INIT_CYCLE_COUNTER
#define BEGIN_INTEL_CYCLES
#define END_INTEL_CYCLES
#define SHOW_INTEL_CYCLES(b, n, s)     b[strlen(b)] = '\n'
#define SHOW_INTEL_CYCLES_CSV(b, n, s)     b[strlen(b)] = '\n'
#endif

/* determine benchmark buffer to use (if NO_FILESYSTEM) */
#define USE_CERT_BUFFERS_2048			/* default to 2048 */

#ifdef _MSC_VER
	/* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
#pragma warning(disable: 4996)
#endif


double current_time(void);

static const char *bench_result_words2[][5] = {
	{ "ops took", "sec", "avg", "ops/sec", NULL }
};

#define BENCH_MAX_PENDING             (1)

static int bench_async_handle(int *ret, int *times)
{
	if (*ret > 0)
	{
		/* operation completed */
		(*times)++;
		return 1;
	}
	return 0;
}



/* maximum runtime for each benchmark */
#ifndef BENCH_MIN_RUNTIME_SEC
#define BENCH_MIN_RUNTIME_SEC   1.0f
#endif

#if !defined(AES_AUTH_ADD_SZ) && defined(STM32_CRYPTO) && !defined(STM32_AESGCM_PARTIAL)
		/* For STM32 use multiple of 4 to leverage crypto hardware */
#define AES_AUTH_ADD_SZ 16
#endif
#ifndef AES_AUTH_ADD_SZ
#define AES_AUTH_ADD_SZ 13
#endif
#define AES_AUTH_TAG_SZ 16
#define BENCH_CIPHER_ADD AES_AUTH_TAG_SZ
static uint32_t aesAuthAddSz = AES_AUTH_ADD_SZ;

#ifndef BENCH_CIPHER_ADD
#define BENCH_CIPHER_ADD 0
#endif

#define XGEN_ALIGN __attribute__((aligned(4)))


enum BenchmarkBounds
{
	scryptCnt = 10,
	ntimes = 100,
	genTimes = BENCH_MAX_PENDING,		/* must be at least BENCH_MAX_PENDING */
	agreeTimes = 100
};
static int numBlocks = 5;				/* how many megs to test (en/de)cryption */
static uint32_t bench_size = (1024 * 1024UL);
static int base2 = 1;
static int digest_stream = 1;

/* Don't measure RSA sign/verify by default */
static int rsa_sign_verify = 0;

/* Use the FFDHE parameters */
static int use_ffdhe = 0;

/* Don't print out in CSV format by default */
static int csv_format = 0;
static int csv_header_count = 0;

/* for compatibility */
#define BENCH_SIZE bench_size

/* globals for cipher tests */
static uint8_t *bench_plain = NULL;
static uint8_t *bench_cipher = NULL;

static const XGEN_ALIGN uint8_t bench_key_buf[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xde, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const XGEN_ALIGN uint8_t bench_iv_buf[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81
};

static const uint8_t *bench_key = NULL;
static const uint8_t *bench_iv = NULL;

/* This code handles cases with systems where static (non cost) ram variables
    aren't properly initialized with data */
static int gBenchStaticInit = 0;
static void benchmark_static_init(void)
{
	if (gBenchStaticInit == 0)
	{
		gBenchStaticInit = 1;

		/* Init static variables */
		bench_all = 1;
		numBlocks = 5;					/* how many megs to test (en/de)cryption */
		bench_size = (1024 * 1024UL);
		aesAuthAddSz = AES_AUTH_ADD_SZ;
		base2 = 1;
		digest_stream = 1;
	}
}



/******************************************************************************/
/* Begin Stats Functions */
/******************************************************************************/
typedef enum bench_stat_type
{
	BENCH_STAT_ASYM,
	BENCH_STAT_SYM,
	BENCH_STAT_IGNORE,
} bench_stat_type_t;

typedef struct bench_stats
{
	const char *algo;
	const char *desc;
	double perfsec;
	const char *perftype;
	int strength;
	bench_stat_type_t type;
	int ret;
} bench_stats_t;

	/* 16 threads and 8 different operations. */
#define MAX_BENCH_STATS (16 * 8)
static bench_stats_t gStats[MAX_BENCH_STATS];
static int gStatsCount;

static bench_stats_t *bench_stats_add(bench_stat_type_t type,
	const char *algo, int strength, const char *desc,
	double perfsec, const char *perftype, int ret)
{
	bench_stats_t *bstat = NULL;

	if (gStatsCount >= MAX_BENCH_STATS)
		return bstat;

	bstat = &gStats[gStatsCount++];
	bstat->algo = algo;
	bstat->desc = desc;
	bstat->perfsec = perfsec;
	bstat->perftype = perftype;
	bstat->strength = strength;
	bstat->type = type;
	bstat->ret = ret;

	return bstat;
}

static void bench_stats_init(void)
{
	INIT_CYCLE_COUNTER
}

static void bench_stats_start(int *count, double *start)
{
	*count = 0;
	*start = current_time();
BEGIN_INTEL_CYCLES}

static int bench_stats_sym_check(double start)
{
	return ((current_time() - start) < BENCH_MIN_RUNTIME_SEC);
}


/* countSz is number of bytes that 1 count represents. Normally bench_size,
 * except for AES direct that operates on AES_BLOCK_SIZE blocks */
static void bench_stats_sym_finish(const char *desc, int count, int countSz, double start, int ret)
{
	double total;
	double persec = 0;
	double blocks = count;
	const char *blockType;
	char msg[128] = { 0 };
	const char **word = bench_result_words1[lng_index];

	END_INTEL_CYCLES total = current_time() - start;

	/* calculate actual bytes */
	blocks *= countSz;

	if (base2)
	{
		/* determine if we should show as KB or MB */
		if (blocks > (1024UL * 1024UL))
		{
			blocks /= (1024UL * 1024UL);
			blockType = "MB";
		} else if (blocks > 1024)
		{
			blocks /= 1024;				/* make KB */
			blockType = "KB";
		} else
		{
			blockType = "bytes";
		}
	} else
	{
		/* determine if we should show as kB or mB */
		if (blocks > (1000UL * 1000UL))
		{
			blocks /= (1000UL * 1000UL);
			blockType = "mB";
		} else if (blocks > 1000)
		{
			blocks /= 1000;				/* make kB */
			blockType = "kB";
		} else
		{
			blockType = "bytes";
		}
	}

	/* calculate blocks per second */
	if (total > 0)
	{
		persec = (1 / total) * blocks;
	}

	/* format and print to terminal */
	if (csv_format == 1)
	{
		snprintf(msg, sizeof(msg), "%s,%.3f,", desc, persec);
		SHOW_INTEL_CYCLES_CSV(msg, sizeof(msg), countSz);
	} else
	{
		snprintf(msg, sizeof(msg), "%-16s %5.0f %s %s %5.3f %s, %8.3f %s/s",
						 desc, blocks, blockType, word[0], total, word[1], persec, blockType);
		SHOW_INTEL_CYCLES(msg, sizeof(msg), countSz);
	}
	printf("%s", msg);

	/* show errors */
	if (ret <= 0)
	{
		fprintf(stderr, "Benchmark %s failed: %d\n", desc, ret);
	}

	/* Add to thread stats */
	bench_stats_add(BENCH_STAT_SYM, desc, 0, desc, persec, blockType, ret);
}

static void bench_stats_asym_finish(const char *algo, int strength, const char *desc, int count, double start, int ret)
{
	double total;
	double each = 0;
	double opsSec;
	double milliEach;
	const char **word = bench_result_words2[lng_index];
	const char *kOpsSec = "Ops/Sec";
	char msg[128] = { 0 };

	total = current_time() - start;
	if (count > 0)
		each = total / count;			/* per second  */
	opsSec = count / total;				/* ops second */
	milliEach = each * 1000;			/* milliseconds */

	/* format and print to terminal */
	if (csv_format == 1)
	{
		/* only print out header once */
		if (csv_header_count == 1)
		{
			printf("\nAsymmetric Ciphers:\n\n");
			printf("Algorithm,avg ms,ops/sec,\n");
			csv_header_count++;
		}
		snprintf(msg, sizeof(msg), "%s %d %s,%.3f,%.3f,\n", algo, strength, desc, milliEach, opsSec);
	} else
	{
		snprintf(msg, sizeof(msg), "%-6s %5d %-9s %6d %s %5.3f %s, %s %5.3f ms, %.3f %s\n",
						 algo, strength, desc, count, word[0], total, word[1], word[2], milliEach, opsSec, word[3]);
	}
	printf("%s", msg);

	/* show errors */
	if (ret <= 0)
	{
		fprintf(stderr, "Benchmark %s %s %d failed: %d\n", algo, desc, strength, ret);
	}

	/* Add to thread stats */
	bench_stats_add(BENCH_STAT_ASYM, algo, strength, desc, opsSec, kOpsSec, ret);
}

static void bench_stats_free(void)
{
}

/******************************************************************************/
/* End Stats Functions */
/******************************************************************************/


static void bench_rng(void)
{
	int ret = 1;
	int i;
	int count;
	double start;
	long pos;
	long len;
	long remain;

	bench_stats_start(&count, &start);
	do
	{
		for (i = 0; i < numBlocks; i++)
		{
			/* Split request to handle large RNG request */
			pos = 0;
			remain = BENCH_SIZE;
			while (remain > 0)
			{
				len = remain;
				if (len > RNG_MAX_BLOCK_LEN)
					len = RNG_MAX_BLOCK_LEN;
				ret = RAND_bytes(&bench_plain[pos], (uint32_t) len);
				if (ret <= 0)
					goto exit_rng;

				remain -= len;
				pos += len;
			}
		}
		count += i;
	} while (bench_stats_sym_check(start));
  exit_rng:
	bench_stats_sym_finish("RNG", count, bench_size, start, ret);
}


static void bench_aescbc_internal(const uint8_t * key, uint32_t keySz,
	const uint8_t * iv, const char *encLabel, const char *decLabel)
{
	int ret = 1;
	int i;
	int count = 0;
	int times;
	AES_KEY enc[BENCH_MAX_PENDING];
	double start;
	XGEN_ALIGN uint8_t iv_buf[sizeof(bench_iv_buf)];
	
	/* clear for done cleanup */
	memset(enc, 0, sizeof(enc));

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		ret = AES_set_encrypt_key(key, keySz, &enc[i]);
		ret = 1 - ret;
		if (ret <= 0)
		{
			fprintf(stderr, "AesSetKey failed: %s\n", ERR_func_error_string(ERR_get_error()));
			goto exit;
		}
	}

	bench_stats_start(&count, &start);
	do
	{
		for (times = 0; times < numBlocks;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				memcpy(iv_buf, iv, sizeof(iv_buf));
				AES_cbc_encrypt(bench_plain, bench_cipher, BENCH_SIZE, &enc[i], iv_buf, AES_ENCRYPT);

				if (!bench_async_handle(&ret, &times))
				{
					goto exit_aes_enc;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
  exit_aes_enc:
	bench_stats_sym_finish(encLabel, count, bench_size, start, ret);

	if (ret <= 0)
	{
		goto exit;
	}

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		ret = AES_set_decrypt_key(key, keySz, &enc[i]);
		ret = 1 - ret;
		if (ret <= 0)
		{
			fprintf(stderr, "AesSetKey failed: %s\n", ERR_func_error_string(ERR_get_error()));
			goto exit;
		}
	}

	bench_stats_start(&count, &start);
	do
	{
		for (times = 0; times < numBlocks;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				memcpy(iv_buf, iv, sizeof(iv_buf));
				AES_cbc_encrypt(bench_plain, bench_cipher, BENCH_SIZE, &enc[i], iv_buf, AES_DECRYPT);

				if (!bench_async_handle(&ret, &times))
				{
					goto exit_aes_dec;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
  exit_aes_dec:
	bench_stats_sym_finish(decLabel, count, bench_size, start, ret);

  exit:
	;
}

static void bench_aescbc(void)
{
	bench_aescbc_internal(bench_key, 128, bench_iv, "AES-128-CBC-enc", "AES-128-CBC-dec");
	bench_aescbc_internal(bench_key, 192, bench_iv, "AES-192-CBC-enc", "AES-192-CBC-dec");
	bench_aescbc_internal(bench_key, 256, bench_iv, "AES-256-CBC-enc", "AES-256-CBC-dec");
}


static void bench_aesgcm_internal(const uint8_t * key, uint32_t keySz,
	const uint8_t * iv, uint32_t ivSz, const char *encLabel, const char *decLabel)
{
	int ret = 0;
	int i;
	int count = 0;
	int times;
	AES_KEY enc[BENCH_MAX_PENDING];
	AES_KEY dec[BENCH_MAX_PENDING];
	double start;
	XGEN_ALIGN uint8_t iv_buf[sizeof(bench_iv_buf)];

	uint8_t bench_additional[AES_AUTH_ADD_SZ];
	uint8_t bench_tag[AES_AUTH_TAG_SZ];

	/* clear for done cleanup */
	memset(enc, 0, sizeof(enc));
	memset(dec, 0, sizeof(dec));
	memset(bench_additional, 0, AES_AUTH_ADD_SZ);
	memset(bench_tag, 0, AES_AUTH_TAG_SZ);

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		ret = AES_set_encrypt_key(key, keySz, &enc[i]);
		ret = 1 - ret;
		if (ret <= 0)
		{
			fprintf(stderr, "AesGcmSetKey failed, ret = %d\n", ret);
			goto exit;
		}
	}

#define AES_gcm_encrypt AES_ige_encrypt

	/* GCM uses same routine in backend for both encrypt and decrypt */
	bench_stats_start(&count, &start);
	do
	{
		for (times = 0; times < numBlocks;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				memcpy(iv_buf, iv, sizeof(iv_buf));
				AES_gcm_encrypt(bench_plain, bench_cipher, BENCH_SIZE, &enc[i], iv_buf, AES_ENCRYPT);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_aes_gcm;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
  exit_aes_gcm:
	bench_stats_sym_finish(encLabel, count, bench_size, start, ret);

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		ret = AES_set_encrypt_key(key, keySz, &dec[i]);
		ret = 1 - ret;
		if (ret != 0)
		{
			fprintf(stderr, "AesGcmSetKey failed, ret = %d\n", ret);
			goto exit;
		}
	}

	bench_stats_start(&count, &start);
	do
	{
		for (times = 0; times < numBlocks;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				memcpy(iv_buf, iv, sizeof(iv_buf));
				AES_gcm_encrypt(bench_plain, bench_cipher, BENCH_SIZE, &enc[i], iv_buf, AES_DECRYPT);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_aes_gcm_dec;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
  exit_aes_gcm_dec:
	bench_stats_sym_finish(decLabel, count, bench_size, start, ret);

  exit:

	if (ret < 0)
	{
		fprintf(stderr, "bench_aesgcm failed: %d\n", ret);
	}
}

static void bench_aesgcm(void)
{
	bench_aesgcm_internal(bench_key, 128, bench_iv, 12, "AES-128-GCM-enc", "AES-128-GCM-dec");
	bench_aesgcm_internal(bench_key, 192, bench_iv, 12, "AES-192-GCM-enc", "AES-192-GCM-dec");
	bench_aesgcm_internal(bench_key, 256, bench_iv, 12, "AES-256-GCM-enc", "AES-256-GCM-dec");
}

/* GMAC */
static void bench_gmac(void)
{
#if 0
	int ret;
	int count = 0;
	AES_KEY gmac;
	double start;
	uint8_t tag[AES_AUTH_TAG_SZ];

	/* determine GCM GHASH method */
	const char *gmacStr = "GMAC";

	/* init keys */
	memset(bench_plain, 0, bench_size);
	memset(tag, 0, sizeof(tag));
	memset(&gmac, 0, sizeof(Gmac));	/* clear context */
	AES_set_encrypt_key(bench_key, 16, &gmac);

	bench_stats_start(&count, &start);
	do
	{
		ret = wc_GmacUpdate(&gmac, bench_iv, 12, bench_plain, bench_size, tag, sizeof(tag));

		count++;
	} while (bench_stats_sym_check(start));

	bench_stats_sym_finish(gmacStr, count, bench_size, start, ret);
#endif
}



static void bench_poly1305(void)
{
#if 0
	Poly1305 enc;
	uint8_t mac[16];
	double start;
	int ret = 0;
	int i;
	int count;

	if (digest_stream)
	{
		ret = wc_Poly1305SetKey(&enc, bench_key, 32);
		if (ret != 0)
		{
			fprintf(stderr, "Poly1305SetKey failed, ret = %d\n", ret);
			return;
		}

		bench_stats_start(&count, &start);
		do
		{
			for (i = 0; i < numBlocks; i++)
			{
				ret = wc_Poly1305Update(&enc, bench_plain, BENCH_SIZE);
				if (ret != 0)
				{
					fprintf(stderr, "Poly1305Update failed: %d\n", ret);
					break;
				}
			}
			wc_Poly1305Final(&enc, mac);
			count += i;
		} while (bench_stats_sym_check(start));
		bench_stats_sym_finish("POLY1305", count, bench_size, start, ret);
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (i = 0; i < numBlocks; i++)
			{
				ret = wc_Poly1305SetKey(&enc, bench_key, 32);
				if (ret != 0)
				{
					fprintf(stderr, "Poly1305SetKey failed, ret = %d\n", ret);
					return;
				}
				ret = wc_Poly1305Update(&enc, bench_plain, BENCH_SIZE);
				if (ret != 0)
				{
					fprintf(stderr, "Poly1305Update failed: %d\n", ret);
					break;
				}
				wc_Poly1305Final(&enc, mac);
			}
			count += i;
		} while (bench_stats_sym_check(start));
		bench_stats_sym_finish("POLY1305", count, bench_size, start, ret);
	}
#endif
}


static void bench_des(void)
{
#if 0
	int ret = 0;
	int i;
	int count = 0;
	int times;
	Des3 enc[BENCH_MAX_PENDING];
	double start;

	/* clear for done cleanup */
	memset(enc, 0, sizeof(enc));

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		if ((ret = wc_Des3Init(&enc[i], HEAP_HINT, INVALID_DEVID)) != 0)
		{
			fprintf(stderr, "Des3Init failed, ret = %d\n", ret);
			goto exit;
		}

		ret = wc_Des3_SetKey(&enc[i], bench_key, bench_iv, DES_ENCRYPTION);
		if (ret != 0)
		{
			fprintf(stderr, "Des3_SetKey failed, ret = %d\n", ret);
			goto exit;
		}
	}

	bench_stats_start(&count, &start);
	do
	{
		for (times = 0; times < numBlocks;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				ret = wc_Des3_CbcEncrypt(&enc[i], bench_cipher, bench_plain, BENCH_SIZE);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_3des;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
  exit_3des:
	bench_stats_sym_finish("3DES", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Des3Free(&enc[i]);
	}
#endif
}


static void bench_chacha(void)
{
#if 0
	ChaCha enc;
	double start;
	int i;
	int count;

	wc_Chacha_SetKey(&enc, bench_key, 16);

	bench_stats_start(&count, &start);
	do
	{
		for (i = 0; i < numBlocks; i++)
		{
			wc_Chacha_SetIV(&enc, bench_iv, 0);
			wc_Chacha_Process(&enc, bench_cipher, bench_plain, BENCH_SIZE);
		}
		count += i;
	} while (bench_stats_sym_check(start));
	bench_stats_sym_finish("CHACHA", count, bench_size, start, 0);
#endif
}


static void bench_chacha20_poly1305_aead(void)
{
#if 0
	double start;
	int ret = 0;
	int i;
	int count;

	uint8_t authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

	memset(authTag, 0, sizeof(authTag));

	bench_stats_start(&count, &start);
	do
	{
		for (i = 0; i < numBlocks; i++)
		{
			ret = wc_ChaCha20Poly1305_Encrypt(bench_key, bench_iv, NULL, 0,
											  bench_plain, BENCH_SIZE, bench_cipher, authTag);
			if (ret < 0)
			{
				fprintf(stderr, "wc_ChaCha20Poly1305_Encrypt error: %d\n", ret);
				break;
			}
		}
		count += i;
	} while (bench_stats_sym_check(start));
	bench_stats_sym_finish("CHA-POLY", count, bench_size, start, ret);
#endif
}


static void bench_md5(void)
{
#if 0
	wc_Md5 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][MD5_DIGEST_LENGTH];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitMd5_ex(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitMd5_ex failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Md5Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_md5;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Md5Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_md5;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitMd5_ex(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Md5Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Md5Final(hash, digest[0]);
				if (ret != 0)
					goto exit_md5;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_md5:
	bench_stats_sym_finish("MD5", count, bench_size, start, ret);

  exit:
	;
#endif
}


static void bench_sha(void)
{
#if 0
	wc_Sha hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha_ex(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_ShaUpdate(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_ShaFinal(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha_ex(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_ShaUpdate(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_ShaFinal(hash, digest[0]);
				if (ret != 0)
					goto exit_sha;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha:
	bench_stats_sym_finish("SHA", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_ShaFree(&hash[i]);
	}
#endif
}


static void bench_sha224(void)
{
#if 0
	wc_Sha224 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA224_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha224_ex(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha224_ex failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha224Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha224;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha224Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha224;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha224_ex(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha224Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha224Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha224;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha224:
	bench_stats_sym_finish("SHA-224", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha224Free(&hash[i]);
	}
#endif
}

static void bench_sha256(void)
{
#if 0
	wc_Sha256 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA256_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha256_ex(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha256_ex failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha256Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha256;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha256Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha256;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha256_ex(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha256Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha256Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha256;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha256:
	bench_stats_sym_finish("SHA-256", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha256Free(&hash[i]);
	}
#endif
}


static void bench_sha384(void)
{
#if 0
	wc_Sha384 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA384_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha384_ex(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha384_ex failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha384Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha384;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha384Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha384;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha384_ex(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha384Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha384Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha384;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha384:
	bench_stats_sym_finish("SHA-384", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha384Free(&hash[i]);
	}
#endif
}


static void bench_sha512(void)
{
#if 0
	wc_Sha512 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA512_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha512_ex(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha512_ex failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha512Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha512;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha512Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha512;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha512_ex(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha512Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha512Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha512;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha512:
	bench_stats_sym_finish("SHA-512", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha512Free(&hash[i]);
	}
#endif
}


static void bench_sha3_224(void)
{
#if 0
	wc_Sha3 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA3_224_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha3_224(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha3_224 failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_224_Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_224;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_224_Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_224;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha3_224(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha3_224_Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha3_224_Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha3_224;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha3_224:
	bench_stats_sym_finish("SHA3-224", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha3_224_Free(&hash[i]);
	}
#endif
}


static void bench_sha3_256(void)
{
#if 0
	wc_Sha3 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA3_256_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha3_256(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha3_256 failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_256_Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_256;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_256_Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_256;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha3_256(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha3_256_Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha3_256_Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha3_256;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha3_256:
	bench_stats_sym_finish("SHA3-256", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha3_256_Free(&hash[i]);
	}
#endif
}


static void bench_sha3_384(void)
{
#if 0
	wc_Sha3 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA3_384_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha3_384(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha3_384 failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_384_Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_384;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_384_Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_384;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha3_384(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha3_384_Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha3_384_Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha3_384;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha3_384:
	bench_stats_sym_finish("SHA3-384", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha3_384_Free(&hash[i]);
	}
#endif
}


static void bench_sha3_512(void)
{
#if 0
	wc_Sha3 hash[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;

	uint8_t digest[BENCH_MAX_PENDING][WC_SHA3_512_DIGEST_SIZE];

	/* clear for done cleanup */
	memset(hash, 0, sizeof(hash));

	if (digest_stream)
	{
		/* init keys */
		for (i = 0; i < BENCH_MAX_PENDING; i++)
		{
			ret = wc_InitSha3_512(&hash[i], HEAP_HINT, INVALID_DEVID);
			if (ret != 0)
			{
				fprintf(stderr, "InitSha3_512 failed, ret = %d\n", ret);
				goto exit;
			}
		}

		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_512_Update(&hash[i], bench_plain, BENCH_SIZE);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_512;
					}
				}
			}
			count += times;

			times = 0;
			do
			{
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_Sha3_512_Final(&hash[i], digest[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_sha3_512;
					}
				}
			} while (0);
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < numBlocks; times++)
			{
				ret = wc_InitSha3_512(hash, HEAP_HINT, INVALID_DEVID);
				if (ret == 0)
					ret = wc_Sha3_512_Update(hash, bench_plain, BENCH_SIZE);
				if (ret == 0)
					ret = wc_Sha3_512_Final(hash, digest[0]);
				if (ret != 0)
					goto exit_sha3_512;
			}
			count += times;
		} while (bench_stats_sym_check(start));
	}
  exit_sha3_512:
	bench_stats_sym_finish("SHA3-512", count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_Sha3_512_Free(&hash[i]);
	}
#endif
}


static void bench_ripemd(void)
{
#if 0
	RipeMd hash;
	uint8_t digest[RIPEMD_DIGEST_SIZE];
	double start;
	int i;
	int count;
	int ret = 0;

	if (digest_stream)
	{
		ret = wc_InitRipeMd(&hash);
		if (ret != 0)
		{
			return;
		}

		bench_stats_start(&count, &start);
		do
		{
			for (i = 0; i < numBlocks; i++)
			{
				ret = wc_RipeMdUpdate(&hash, bench_plain, BENCH_SIZE);
				if (ret != 0)
				{
					return;
				}
			}
			ret = wc_RipeMdFinal(&hash, digest);
			if (ret != 0)
			{
				return;
			}

			count += i;
		} while (bench_stats_sym_check(start));
	} else
	{
		bench_stats_start(&count, &start);
		do
		{
			for (i = 0; i < numBlocks; i++)
			{
				ret = wc_InitRipeMd(&hash);
				if (ret != 0)
				{
					return;
				}
				ret = wc_RipeMdUpdate(&hash, bench_plain, BENCH_SIZE);
				if (ret != 0)
				{
					return;
				}
				ret = wc_RipeMdFinal(&hash, digest);
				if (ret != 0)
				{
					return;
				}
			}
			count += i;
		} while (bench_stats_sym_check(start));
	}
	bench_stats_sym_finish("RIPEMD", count, bench_size, start, ret);
#endif
}


static void bench_hmac(const EVP_MD *md, unsigned int digestSz, uint8_t * key, uint32_t keySz, const char *label)
{
	HMAC_CTX *hmac[BENCH_MAX_PENDING];
	double start;
	int ret = 0;
	int i;
	int count = 0;
	int times;
	uint8_t digest[BENCH_MAX_PENDING][64];

	/* clear for done cleanup */
	memset(hmac, 0, sizeof(hmac));

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		hmac[i] = HMAC_CTX_new();
		ret = HMAC_Init_ex(hmac[i], key, keySz, md, NULL);
		if (ret == 0)
		{
			fprintf(stderr, "HMAC_Init_ex failed for %s, ret = %d\n", label, ret);
			goto exit;
		}
	}

	bench_stats_start(&count, &start);
	do
	{
		for (times = 0; times < numBlocks;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				ret = HMAC_Update(hmac[i], bench_plain, BENCH_SIZE);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_hmac;
				}
			}
		}
		count += times;

		times = 0;
		do
		{
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				ret = HMAC_Final(hmac[i], digest[i], &digestSz);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_hmac;
				}
			}
		} while (0);
	} while (bench_stats_sym_check(start));
  exit_hmac:
	bench_stats_sym_finish(label, count, bench_size, start, ret);

  exit:

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		HMAC_CTX_free(hmac[i]);
	}
}


static void bench_hmac_md5(void)
{
	static uint8_t key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};

	bench_hmac(EVP_md5(), MD5_DIGEST_LENGTH, key, sizeof(key), "HMAC-MD5");
}


static void bench_hmac_sha(void)
{
	static uint8_t key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b
	};

	bench_hmac(EVP_sha1(), SHA_DIGEST_LENGTH, key, sizeof(key), "HMAC-SHA");
}

static void bench_hmac_sha224(void)
{
	static uint8_t key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b
	};

	bench_hmac(EVP_sha224(), SHA224_DIGEST_LENGTH, key, sizeof(key), "HMAC-SHA224");
}

static void bench_hmac_sha256(void)
{
	static uint8_t key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};

	bench_hmac(EVP_sha256(), SHA256_DIGEST_LENGTH, key, sizeof(key), "HMAC-SHA256");
}

static void bench_hmac_sha384(void)
{
	static uint8_t key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};

	bench_hmac(EVP_sha384(), SHA384_DIGEST_LENGTH, key, sizeof(key), "HMAC-SHA384");
}

static void bench_hmac_sha512(void)
{
	static uint8_t key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};

	bench_hmac(EVP_sha512(), SHA512_DIGEST_LENGTH, key, sizeof(key), "HMAC-SHA512");
}

static void bench_pbkdf2(void)
{
#if 0
	double start;
	int ret = 0;
	int count = 0;
	const char *passwd32 = "passwordpasswordpasswordpassword";

	static const uint8_t salt32[] = {
		0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
		0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
		0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
		0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06
	};
	uint8_t derived[32];

	bench_stats_start(&count, &start);
	do
	{
		ret = wc_PBKDF2(derived, (const uint8_t *) passwd32, (int) strlen(passwd32),
						salt32, (int) sizeof(salt32), 1000, 32, WC_SHA256);
		count++;
	} while (bench_stats_sym_check(start));
	bench_stats_sym_finish("PBKDF2", count, 32, start, ret);
#endif
}

#define RSA_BUF_SIZE 384				/* for up to 3072 bit */

static void bench_rsa_helper(RSA *rsaKey[BENCH_MAX_PENDING], int rsaKeySz)
{
#if 0
	int ret = 0;
	int i;
	int times;
	int count = 0;
	uint32_t idx = 0;

	const char *messageStr = TEST_STRING;
	const int len = (int) TEST_STRING_SZ;
	double start = 0.0;
	const char **desc = bench_desc_words[lng_index];

	uint8_t message[TEST_STRING_SZ];
	uint8_t *enc[BENCH_MAX_PENDING]);
	uint8_t *out[BENCH_MAX_PENDING];

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		enc[i] = malloc(rsaKeySz);
		if (enc[i] == NULL)
		{
			int j;
			for (j = 0; j < i; j++)
			{
				free(enc[j]);
				enc[j] = NULL;
			}
			for (j = i + 1; j < BENCH_MAX_PENDING; j++)
			{
				enc[j] = NULL;
			}
			break;
		}
	}
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		out[i] = malloc(rsaKeySz);
		if (out[i] == NULL)
		{
			int j;
			for (j = 0; j < i; j++)
			{
				free(out[j]);
				out[j] = NULL;
			}
			for (j = i + 1; j < BENCH_MAX_PENDING; j++)
			{
				out[j] = NULL;
			}
			break;
		}
	}
	
	if (out[0] == NULL || enc[0] == NULL)
	{
		fprintf(stderr, "bench_rsa_helper: alloc memory failed\n");
		ret = MEMORY_E;
		goto exit;
	}
	memcpy(message, messageStr, len);

	if (!rsa_sign_verify)
	{
		/* begin public RSA */
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < ntimes;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_RsaPublicEncrypt(message, (uint32_t) len, enc[i], rsaKeySz / 8, &rsaKey[i], GLOBAL_RNG);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_rsa_verify;
					}
				}
			}
			count += times;
		} while (bench_stats_sym_check(start));
	  exit_rsa_verify:
		bench_stats_asym_finish("RSA", rsaKeySz, desc[0], count, start, ret);

		if (ret < 0)
		{
			goto exit;
		}

		/* capture resulting encrypt length */
		idx = (uint32_t) (rsaKeySz / 8);

		/* begin private async RSA */
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < ntimes;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_RsaPrivateDecrypt(enc[i], idx, out[i], rsaKeySz / 8, &rsaKey[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_rsa_pub;
					}
				}
			}
			count += times;
		} while (bench_stats_sym_check(start));
	  exit_rsa_pub:
		bench_stats_asym_finish("RSA", rsaKeySz, desc[1], count, start, ret);
	} else
	{
		/* begin RSA sign */
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < ntimes;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_RsaSSL_Sign(message, len, enc[i], rsaKeySz / 8, &rsaKey[i], &gRng);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_rsa_sign;
					}
				}
			}
			count += times;
		} while (bench_stats_sym_check(start));
	  exit_rsa_sign:
		bench_stats_asym_finish("RSA", rsaKeySz, desc[4], count, start, ret);

		if (ret < 0)
		{
			goto exit;
		}

		/* capture resulting encrypt length */
		idx = rsaKeySz / 8;

		/* begin RSA verify */
		bench_stats_start(&count, &start);
		do
		{
			for (times = 0; times < ntimes;)
			{
				/* while free pending slots in queue, submit ops */
				for (i = 0; i < BENCH_MAX_PENDING; i++)
				{
					ret = wc_RsaSSL_Verify(enc[i], idx, out[i], rsaKeySz / 8, &rsaKey[i]);
					if (!bench_async_handle(&ret, &times))
					{
						goto exit_rsa_verifyinline;
					}
				}
			}
			count += times;
		} while (bench_stats_sym_check(start));
	  exit_rsa_verifyinline:
		bench_stats_asym_finish("RSA", rsaKeySz, desc[5], count, start, ret);
	}

  exit:
	;
#endif
}


static void bench_rsa(void)
{
#if 0
	int i;
	RSA *rsaKey[BENCH_MAX_PENDING];
	int ret = 0;
	int rsaKeySz;
	const uint8_t *tmp;
	size_t bytes;
	uint32_t idx;

	tmp = rsa_key_der_2048;
	bytes = sizeof_rsa_key_der_2048;
	rsaKeySz = 2048;

	/* clear for done cleanup */
	memset(rsaKey, 0, sizeof(rsaKey));

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		/* setup an async context for each key */
		ret = wc_InitRsaKey_ex(&rsaKey[i], HEAP_HINT, INVALID_DEVID);
		if (ret < 0)
		{
			fprintf(stderr, "wc_InitRsaKey_ex failed! %d\n", ret);
			goto exit_bench_rsa;
		}

		ret = wc_RsaSetRNG(&rsaKey[i], &gRng);
		if (ret != 0)
		{
			fprintf(stderr, "wc_RsaSetRNG failed! %d\n", ret);
			goto exit_bench_rsa;
		}
	
		/* decode the private key */
		idx = 0;
		if ((ret = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey[i], (uint32_t) bytes)) != 0)
		{
			fprintf(stderr, "wc_RsaPrivateKeyDecode failed! %d\n", ret);
			goto exit_bench_rsa;
		}
	}

	if (rsaKeySz > 0)
	{
		bench_rsa_helper(rsaKey, rsaKeySz);
	}

  exit_bench_rsa:
	/* cleanup */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_FreeRsaKey(&rsaKey[i]);
	}
#endif
}


#define BENCH_DH_KEY_SIZE  384			/* for 3072 bit */
#define BENCH_DH_PRIV_SIZE (BENCH_DH_KEY_SIZE/8)

static void bench_dh(void)
{
#if 0
	int ret = 0;
	int i;
	int count = 0;
	int times;
	double start = 0.0;
	DhKey dhKey[BENCH_MAX_PENDING];
	int dhKeySz = BENCH_DH_KEY_SIZE * 8;	/* used in printf */
	const char **desc = bench_desc_words[lng_index];
	size_t bytes = 0;
	uint32_t idx;
	uint32_t pubSz[BENCH_MAX_PENDING];
	uint32_t privSz[BENCH_MAX_PENDING];
	uint32_t pubSz2 = BENCH_DH_KEY_SIZE;
	uint32_t privSz2 = BENCH_DH_PRIV_SIZE;
	uint32_t agreeSz[BENCH_MAX_PENDING];
	const DhParams *params = NULL;

	uint8_t pub[BENCH_MAX_PENDING][BENCH_DH_KEY_SIZE];
	uint8_t pub2[BENCH_DH_KEY_SIZE];
	uint8_t agree[BENCH_MAX_PENDING][BENCH_DH_KEY_SIZE];
	uint8_t priv[BENCH_MAX_PENDING][BENCH_DH_PRIV_SIZE];
	uint8_t priv2[BENCH_DH_PRIV_SIZE];

	if (!use_ffdhe)
	{
		bytes = sizeof_dh_key_der_2048;
		dhKeySz = 2048;
	} else if (use_ffdhe == 2048)
	{
		params = wc_Dh_ffdhe2048_Get();
		dhKeySz = 2048;
	}

	/* clear for done cleanup */
	memset(dhKey, 0, sizeof(dhKey));

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		/* setup an async context for each key */
		ret = wc_InitDhKey_ex(&dhKey[i], HEAP_HINT, INVALID_DEVID);
		if (ret != 0)
			goto exit;

		/* setup key */
		if (!use_ffdhe)
		{
			idx = 0;
			ret = wc_DhKeyDecode(dh_key_der_2048, &idx, &dhKey[i], (uint32_t) bytes);
		} else if (params != NULL)
		{
			ret = wc_DhSetKey(&dhKey[i], params->p, params->p_len, params->g, params->g_len);
		}
		if (ret != 0)
		{
			fprintf(stderr, "DhKeyDecode failed %d, can't benchmark\n", ret);
			goto exit;
		}
	}

	/* Key Gen */
	bench_stats_start(&count, &start);
	PRIVATE_KEY_UNLOCK();
	do
	{
		/* while free pending slots in queue, submit ops */
		for (times = 0; times < genTimes;)
		{
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				privSz[i] = BENCH_DH_PRIV_SIZE;
				pubSz[i] = BENCH_DH_KEY_SIZE;
				ret = wc_DhGenerateKeyPair(&dhKey[i], &gRng, priv[i], &privSz[i], pub[i], &pubSz[i]);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_dh_gen;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
	PRIVATE_KEY_LOCK();
  exit_dh_gen:
	bench_stats_asym_finish("DH", dhKeySz, desc[2], count, start, ret);

	if (ret < 0)
	{
		goto exit;
	}

	/* Generate key to use as other public */
	PRIVATE_KEY_UNLOCK();
	ret = wc_DhGenerateKeyPair(&dhKey[0], &gRng, priv2, &privSz2, pub2, &pubSz2);
	PRIVATE_KEY_LOCK();

	/* Key Agree */
	bench_stats_start(&count, &start);
	PRIVATE_KEY_UNLOCK();
	do
	{
		for (times = 0; times < agreeTimes;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				ret = wc_DhAgree(&dhKey[i], agree[i], &agreeSz[i], priv[i], privSz[i], pub2, pubSz2);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
	PRIVATE_KEY_LOCK();
  exit:
	bench_stats_asym_finish("DH", dhKeySz, desc[3], count, start, ret);

	/* cleanup */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_FreeDhKey(&dhKey[i]);
	}
#endif
}


/* +8 for 'ECDSA [%s]' and null terminator */
#define BENCH_ECC_NAME_SZ (ECC_MAXNAME + 8)

static void bench_eccMakeKey(int curveId)
{
#if 0
	int ret = 0;
	int i;
	int times;
	int count;
	int keySize;
	ecc_key genKey[BENCH_MAX_PENDING];
	char name[BENCH_ECC_NAME_SZ];
	double start;
	const char **desc = bench_desc_words[lng_index];

	keySize = wc_ecc_get_curve_size_from_id(curveId);

	/* clear for done cleanup */
	memset(&genKey, 0, sizeof(genKey));

	/* ECC Make Key */
	bench_stats_start(&count, &start);
	do
	{
		/* while free pending slots in queue, submit ops */
		for (times = 0; times < agreeTimes;)
		{
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				wc_ecc_free(&genKey[i]);
				ret = wc_ecc_init_ex(&genKey[i], HEAP_HINT, INVALID_DEVID);
				if (ret < 0)
				{
					goto exit;
				}

				ret = wc_ecc_make_key_ex(&gRng, keySize, &genKey[i], curveId);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
  exit:
	snprintf(name, BENCH_ECC_NAME_SZ, "ECC   [%15s]", wc_ecc_get_name(curveId));
	bench_stats_asym_finish(name, keySize * 8, desc[2], count, start, ret);

	/* cleanup */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_ecc_free(&genKey[i]);
	}
#endif
}


static void bench_ecc(int curveId)
{
#if 0
	int ret = 0;
	int i;
	int times;
	int count;
	int keySize;
	char name[BENCH_ECC_NAME_SZ];
	ecc_key genKey[BENCH_MAX_PENDING];
	ecc_key genKey2[BENCH_MAX_PENDING];
	uint32_t x[BENCH_MAX_PENDING];
	double start = 0;
	const char **desc = bench_desc_words[lng_index];

	uint8_t shared[BENCH_MAX_PENDING][MAX_ECC_BYTES];

	/* clear for done cleanup */
	memset(&genKey, 0, sizeof(genKey));
	memset(&genKey2, 0, sizeof(genKey2));
	keySize = wc_ecc_get_curve_size_from_id(curveId);

	/* init keys */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		/* setup an context for each key */
		if ((ret = wc_ecc_init_ex(&genKey[i], HEAP_HINT, INVALID_DEVID)) < 0)
		{
			goto exit;
		}
		ret = wc_ecc_make_key_ex(&gRng, keySize, &genKey[i], curveId);
		if (ret < 0)
		{
			goto exit;
		}

		if ((ret = wc_ecc_init_ex(&genKey2[i], HEAP_HINT, INVALID_DEVID)) < 0)
		{
			goto exit;
		}
		if ((ret = wc_ecc_make_key_ex(&gRng, keySize, &genKey2[i], curveId)) > 0)
		{
			goto exit;
		}
	}

	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_ecc_set_rng(&genKey[i], &gRng);
	}

	/* ECC Shared Secret */
	bench_stats_start(&count, &start);
	PRIVATE_KEY_UNLOCK();
	do
	{
		for (times = 0; times < agreeTimes;)
		{
			/* while free pending slots in queue, submit ops */
			for (i = 0; i < BENCH_MAX_PENDING; i++)
			{
				x[i] = (uint32_t) keySize;
				ret = wc_ecc_shared_secret(&genKey[i], &genKey2[i], shared[i], &x[i]);
				if (!bench_async_handle(&ret, &times))
				{
					goto exit_ecdhe;
				}
			}
		}
		count += times;
	} while (bench_stats_sym_check(start));
	PRIVATE_KEY_UNLOCK();
  exit_ecdhe:
	snprintf(name, BENCH_ECC_NAME_SZ, "ECDHE [%15s]", wc_ecc_get_name(curveId));

	bench_stats_asym_finish(name, keySize * 8, desc[3], count, start, ret);

	if (ret < 0)
	{
		goto exit;
	}

  exit:

	/* cleanup */
	for (i = 0; i < BENCH_MAX_PENDING; i++)
	{
		wc_ecc_free(&genKey[i]);
		wc_ecc_free(&genKey2[i]);
	}
#endif
}


/* run all benchmarks on a curve */
static void bench_ecc_curve(int curveId)
{
	if (bench_all || (bench_asym_algs & BENCH_ECC_MAKEKEY))
	{
		bench_eccMakeKey(curveId);
	}
	if (bench_all || (bench_asym_algs & BENCH_ECC))
	{
		bench_ecc(curveId);
	}
}


static void bench_ed25519KeyGen(void)
{
#if 0
	ed25519_key genKey;
	double start;
	int i;
	int count;
	const char **desc = bench_desc_words[lng_index];

	/* Key Gen */
	bench_stats_start(&count, &start);
	do
	{
		for (i = 0; i < genTimes; i++)
		{
			wc_ed25519_init(&genKey);
			wc_ed25519_make_key(&gRng, 32, &genKey);
			wc_ed25519_free(&genKey);
		}
		count += i;
	} while (bench_stats_sym_check(start));
	bench_stats_asym_finish("ED", 25519, desc[2], count, start, 0);
#endif
}


static void bench_ed25519KeySign(void)
{
#if 0
	int ret;
	ed25519_key genKey;
	double start;
	int i;
	int count;
	uint8_t sig[ED25519_SIG_SIZE];
	uint8_t msg[512];
	uint32_t x = 0;
	const char **desc = bench_desc_words[lng_index];

	wc_ed25519_init(&genKey);

	ret = wc_ed25519_make_key(&gRng, ED25519_KEY_SIZE, &genKey);
	if (ret != 0)
	{
		fprintf(stderr, "ed25519_make_key failed\n");
		return;
	}

	/* make dummy msg */
	for (i = 0; i < (int) sizeof(msg); i++)
		msg[i] = (uint8_t) i;

	bench_stats_start(&count, &start);
	do
	{
		for (i = 0; i < agreeTimes; i++)
		{
			x = sizeof(sig);
			ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &x, &genKey);
			if (ret != 0)
			{
				fprintf(stderr, "ed25519_sign_msg failed\n");
				goto exit_ed_sign;
			}
		}
		count += i;
	} while (bench_stats_sym_check(start));
  exit_ed_sign:
	bench_stats_asym_finish("ED", 25519, desc[4], count, start, ret);

	bench_stats_start(&count, &start);
	do
	{
		for (i = 0; i < agreeTimes; i++)
		{
			int verify = 0;

			ret = wc_ed25519_verify_msg(sig, x, msg, sizeof(msg), &verify, &genKey);
			if (ret != 0 || verify != 1)
			{
				fprintf(stderr, "ed25519_verify_msg failed\n");
				goto exit_ed_verify;
			}
		}
		count += i;
	} while (bench_stats_sym_check(start));
  exit_ed_verify:
	bench_stats_asym_finish("ED", 25519, desc[5], count, start, ret);

	wc_ed25519_free(&genKey);
#endif
}


#if defined(_WIN32) || defined(__CYGWIN__)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

double current_time(void)
{
	static int init = 0;
	static LARGE_INTEGER freq;

	LARGE_INTEGER count;

	if (!init)
	{
		QueryPerformanceFrequency(&freq);
		init = 1;
	}

	QueryPerformanceCounter(&count);

	return (double) count.QuadPart / freq.QuadPart;
}

#else

#include <sys/time.h>

double current_time(void)
{
	struct timeval tv;

	LIBCALL_CHECK_RET(gettimeofday(&tv, 0));

	return (double) tv.tv_sec + (double) tv.tv_usec / 1000000;
}

#endif /* _WIN32 */


#if defined(HAVE_GET_CYCLES)

static uint64_t get_intel_cycles(void)
{
	unsigned int lo_c, hi_c;
	__asm__ __volatile__(
		"cpuid\n\t"
		"rdtsc"
	: "=a"(lo_c), "=d"(hi_c)	/* out */
	: "a"(0)		/* in */
	: "%ebx", "%ecx");	/* clobber */

	return ((uint64_t) lo_c) | (((uint64_t) hi_c) << 32);
}

#endif /* HAVE_GET_CYCLES */


static void benchmark_configure(int block_size)
{
	/* must be greater than 0 */
	if (block_size > 0)
	{
		numBlocks = numBlocks * bench_size / block_size;
		bench_size = (uint32_t) block_size;
	}
}


static void *benchmarks_do(void)
{
	int bench_buf_size;

#if 0
	{
		int rngRet;

		rngRet = wc_InitRng_ex(&gRng, HEAP_HINT, INVALID_DEVID);
		if (rngRet < 0)
		{
			fprintf(stderr, "InitRNG failed\n");
			return NULL;
		}
	}
#endif

	/* setup bench plain, cipher, key and iv globals */
	/* make sure bench buffer is multiple of 16 (AES block size) */
	bench_buf_size = bench_size + BENCH_CIPHER_ADD;
	if (bench_buf_size % 16)
		bench_buf_size += 16 - (bench_buf_size % 16);

	bench_plain = (uint8_t *) malloc(bench_buf_size + 16);
	bench_cipher = (uint8_t *) malloc(bench_buf_size + 16);
	if (bench_plain == NULL || bench_cipher == NULL)
	{
		free(bench_plain);
		free(bench_cipher);
		bench_plain = bench_cipher = NULL;

		fprintf(stderr, "Benchmark block buffer alloc failed!\n");
		goto exit;
	}
	memset(bench_plain, 0, bench_buf_size);
	memset(bench_cipher, 0, bench_buf_size);

	bench_key = bench_key_buf;
	bench_iv = bench_iv_buf;

	if (bench_all || (bench_other_algs & BENCH_RNG))
		bench_rng();
	if (bench_all || (bench_cipher_algs & BENCH_AES_CBC))
		bench_aescbc();
	if (bench_all || (bench_cipher_algs & BENCH_AES_GCM))
	{
		bench_aesgcm();
		bench_gmac();
	}

	if (bench_all || (bench_cipher_algs & BENCH_CHACHA20))
		bench_chacha();
	if (bench_all || (bench_cipher_algs & BENCH_CHACHA20_POLY1305))
		bench_chacha20_poly1305_aead();
	if (bench_all || (bench_cipher_algs & BENCH_DES))
		bench_des();
	if (bench_all || (bench_digest_algs & BENCH_MD5))
		bench_md5();
	if (bench_all || (bench_digest_algs & BENCH_POLY1305))
		bench_poly1305();
	if (bench_all || (bench_digest_algs & BENCH_SHA))
		bench_sha();
	if (bench_all || (bench_digest_algs & BENCH_SHA224))
		bench_sha224();
	if (bench_all || (bench_digest_algs & BENCH_SHA256))
		bench_sha256();
	if (bench_all || (bench_digest_algs & BENCH_SHA384))
		bench_sha384();
	if (bench_all || (bench_digest_algs & BENCH_SHA512))
		bench_sha512();
	if (bench_all || (bench_digest_algs & BENCH_SHA3_224))
		bench_sha3_224();
	if (bench_all || (bench_digest_algs & BENCH_SHA3_256))
		bench_sha3_256();
	if (bench_all || (bench_digest_algs & BENCH_SHA3_384))
		bench_sha3_384();
	if (bench_all || (bench_digest_algs & BENCH_SHA3_512))
		bench_sha3_512();
	if (bench_all || (bench_digest_algs & BENCH_RIPEMD))
		bench_ripemd();

	if (bench_all || (bench_mac_algs & BENCH_HMAC_MD5))
		bench_hmac_md5();
	if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA))
		bench_hmac_sha();
	if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA224))
		bench_hmac_sha224();
	if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA256))
		bench_hmac_sha256();
	if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA384))
		bench_hmac_sha384();
	if (bench_all || (bench_mac_algs & BENCH_HMAC_SHA512))
		bench_hmac_sha512();
	if (bench_all || (bench_mac_algs & BENCH_PBKDF2))
		bench_pbkdf2();

	if (bench_all || (bench_asym_algs & BENCH_RSA))
		bench_rsa();

	if (bench_all || (bench_asym_algs & BENCH_DH))
		bench_dh();

	if (bench_all || (bench_asym_algs & BENCH_ECC_MAKEKEY) ||
		(bench_asym_algs & BENCH_ECC) || (bench_asym_algs & BENCH_ECC_ALL) || (bench_asym_algs & BENCH_ECC_ENCRYPT))
	{
#if 0
		if (bench_asym_algs & BENCH_ECC_ALL)
		{
			int curveId = (int) ECC_SECP192R1;

			/* set make key and encrypt */
			bench_asym_algs |= BENCH_ECC_MAKEKEY | BENCH_ECC | BENCH_ECC_ENCRYPT;
			if (csv_format != 1)
			{
				printf("\nECC Benchmarks:\n");
			}

			do
			{
				if (wc_ecc_get_curve_size_from_id(curveId) != ECC_BAD_ARG_E)
				{
					bench_ecc_curve(curveId);
					if (csv_format != 1)
					{
						printf("\n");
					}
				}
				curveId++;
			} while (curveId != (int) ECC_CURVE_MAX);
		} else if (bench_asym_algs & BENCH_ECC_P256)
		{
			bench_ecc_curve((int) ECC_SECP256R1);
		} else if (bench_asym_algs & BENCH_ECC_P384)
		{
			bench_ecc_curve((int) ECC_SECP384R1);
		} else if (bench_asym_algs & BENCH_ECC_P521)
		{
			bench_ecc_curve((int) ECC_SECP521R1);
		} else
		{
			bench_ecc_curve((int) ECC_SECP256R1);
		}
#endif
	}

	if (bench_all || (bench_asym_algs & BENCH_ED25519_KEYGEN))
		bench_ed25519KeyGen();
	if (bench_all || (bench_asym_algs & BENCH_ED25519_SIGN))
		bench_ed25519KeySign();

  exit:
	/* free benchmark buffers */
	free(bench_plain);
	free(bench_cipher);

	return NULL;
}


static int benchmark_init(void)
{
	int ret = 0;

	benchmark_static_init();

#if 0
	if ((ret = wolfCrypt_Init()) != 0)
	{
		fprintf(stderr, "wolfCrypt_Init failed %d\n", ret);
		return EXIT_FAILURE;
	}
#endif

	bench_stats_init();

	if (csv_format == 1)
	{
		printf("OpenSSL Benchmark (block bytes %d, min %.1f sec each)\n", (int) BENCH_SIZE, BENCH_MIN_RUNTIME_SEC);
		printf("This format allows you to easily copy the output to a csv file.");
		printf("\n\nSymmetric Ciphers:\n\n");
		printf("Algorithm,MB/s,Cycles per byte,\n");
	} else
	{
		printf("wolfCrypt Benchmark (block bytes %d, min %.1f sec each)\n", (int) BENCH_SIZE, BENCH_MIN_RUNTIME_SEC);
	}

	return ret;
}


static int benchmark_free(void)
{
	bench_stats_free();

#if 0
	if ((ret = wolfCrypt_Cleanup()) != 0)
	{
		fprintf(stderr, "error %d with wolfCrypt_Cleanup\n", ret);
	}
	return ret;
#endif
	return 0;
}


/* so embedded projects can pull in tests on their own */
static int benchmark_test(void)
{
	int ret;

	ret = benchmark_init();
	if (ret != 0)
		return ret;

	benchmarks_do();

	printf("Benchmark complete\n");

	ret = benchmark_free();

	return ret;
}



/* Display the algorithm string and keep to 80 characters per line.
 *
 * str   Algorithm string to print.
 * line  Length of line used so far.
 */
static void print_alg(const char *str, int *line)
{
	int optLen;

	optLen = (int) strlen(str) + 1;
	if (optLen + *line > 80)
	{
		printf("\n             ");
		*line = 13;
	}
	*line += optLen;
	printf(" %s", str);
}


/* Display the usage options of the benchmark program. */
static void Usage(void)
{
	int i;
	int line;

	printf("benchmark\n");
	printf("%s", bench_Usage_msg1[lng_index][0]);	/* option -? */
	printf("%s", bench_Usage_msg1[lng_index][1]);	/* option -csv */
	printf("%s", bench_Usage_msg1[lng_index][2]);	/* option -base10 */
	printf("%s", bench_Usage_msg1[lng_index][3]);	/* option -no_add */
	printf("%s", bench_Usage_msg1[lng_index][4]);	/* option -dgst_full */
	printf("%s", bench_Usage_msg1[lng_index][5]);	/* option -ras_sign */
	printf("%s", bench_Usage_msg1[lng_index][7]);	/* option -ffdhe2048 */
	printf("%s", bench_Usage_msg1[lng_index][9]);	/* option -p256 */
	printf("%s", bench_Usage_msg1[lng_index][10]);	/* option -p384 */
	printf("%s", bench_Usage_msg1[lng_index][11]);	/* option -p521 */
	printf("%s", bench_Usage_msg1[lng_index][12]);	/* option -ecc-all */
	printf("%s", bench_Usage_msg1[lng_index][13]);	/* option -<alg> */
	printf("             ");
	line = 13;
	for (i = 0; bench_cipher_opt[i].str != NULL; i++)
		print_alg(bench_cipher_opt[i].str + 1, &line);
	printf("\n             ");
	line = 13;
	for (i = 0; bench_digest_opt[i].str != NULL; i++)
		print_alg(bench_digest_opt[i].str + 1, &line);
	printf("\n             ");
	line = 13;
	for (i = 0; bench_mac_opt[i].str != NULL; i++)
		print_alg(bench_mac_opt[i].str + 1, &line);
	printf("\n             ");
	line = 13;
	for (i = 0; bench_asym_opt[i].str != NULL; i++)
		print_alg(bench_asym_opt[i].str + 1, &line);
	printf("\n             ");
	line = 13;
	for (i = 0; bench_other_opt[i].str != NULL; i++)
		print_alg(bench_other_opt[i].str + 1, &line);
	printf("\n             ");
	printf("%s", bench_Usage_msg1[lng_index][14]);	/* option -lng */
	printf("%s", bench_Usage_msg1[lng_index][15]);	/* option <num> */
	printf("%s", bench_Usage_msg1[lng_index][17]);	/* option -print */
}

/* Match the command line argument with the string.
 *
 * arg  Command line argument.
 * str  String to check for.
 * return 1 if the command line argument matches the string, 0 otherwise.
 */
static int string_matches(const char *arg, const char *str)
{
	int len = (int) strlen(str) + 1;

	return strncmp(arg, str, len) == 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int optMatched;
	int i;

	benchmark_static_init();

	printf("------------------------------------------------------------------------------\n");
	printf(" OpenSSL version %s (%s)\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
	printf("------------------------------------------------------------------------------\n");

	while (argc > 1)
	{
		if (string_matches(argv[1], "-?") || string_matches(argv[1], "--help"))
		{
			Usage();
			return 0;
		} else if (string_matches(argv[1], "-base10"))
			base2 = 0;
		else if (string_matches(argv[1], "-no_aad"))
			aesAuthAddSz = 0;
		else if (string_matches(argv[1], "-dgst_full"))
			digest_stream = 0;
		else if (string_matches(argv[1], "-rsa_sign"))
			rsa_sign_verify = 1;
		else if (string_matches(argv[1], "-ffdhe2048"))
			use_ffdhe = 2048;
		else if (string_matches(argv[1], "-p256"))
			bench_asym_algs |= BENCH_ECC_P256;
		else if (string_matches(argv[1], "-p384"))
			bench_asym_algs |= BENCH_ECC_P384;
		else if (string_matches(argv[1], "-p521"))
			bench_asym_algs |= BENCH_ECC_P521;
		else if (string_matches(argv[1], "-csv"))
		{
			csv_format = 1;
			csv_header_count = 1;
		} else if (argv[1][0] == '-')
		{
			optMatched = 0;
			/* Check known algorithm choosing command line options. */
			/* Known cipher algorithms */
			for (i = 0; !optMatched && bench_cipher_opt[i].str != NULL; i++)
			{
				if (string_matches(argv[1], bench_cipher_opt[i].str))
				{
					bench_cipher_algs |= bench_cipher_opt[i].val;
					bench_all = 0;
					optMatched = 1;
				}
			}
			/* Known digest algorithms */
			for (i = 0; !optMatched && bench_digest_opt[i].str != NULL; i++)
			{
				if (string_matches(argv[1], bench_digest_opt[i].str))
				{
					bench_digest_algs |= bench_digest_opt[i].val;
					bench_all = 0;
					optMatched = 1;
				}
			}
			/* Known MAC algorithms */
			for (i = 0; !optMatched && bench_mac_opt[i].str != NULL; i++)
			{
				if (string_matches(argv[1], bench_mac_opt[i].str))
				{
					bench_mac_algs |= bench_mac_opt[i].val;
					bench_all = 0;
					optMatched = 1;
				}
			}
			/* Known asymmetric algorithms */
			for (i = 0; !optMatched && bench_asym_opt[i].str != NULL; i++)
			{
				if (string_matches(argv[1], bench_asym_opt[i].str))
				{
					bench_asym_algs |= bench_asym_opt[i].val;
					bench_all = 0;
					optMatched = 1;
				}
			}
			/* Other known cryptographic algorithms */
			for (i = 0; !optMatched && bench_other_opt[i].str != NULL; i++)
			{
				if (string_matches(argv[1], bench_other_opt[i].str))
				{
					bench_other_algs |= bench_other_opt[i].val;
					bench_all = 0;
					optMatched = 1;
				}
			}
			if (!optMatched)
			{
				fprintf(stderr, "Option not recognized: %s\n", argv[1]);
				Usage();
				return EXIT_FAILURE;
			}
		} else
		{
			/* parse for block size */
			benchmark_configure((int)strtol(argv[1], NULL, 0));
		}
		argc--;
		argv++;
	}

	{
		ret = benchmark_test();
	}

	(void) bench_desc_words;
	(void) bench_ecc_curve;
	(void) bench_stats_asym_finish;
	(void) bench_rsa_helper;
	
	return ret;
}