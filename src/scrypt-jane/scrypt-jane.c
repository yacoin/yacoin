
/*
	scrypt-jane by Andrew M, https://github.com/floodyberry/scrypt-jane

	Public Domain or MIT License, whichever is easier
*/

#include <string.h>

#if defined( _WINDOWS )
    #ifdef _MSC_VER
        #include <stdio.h>
        #ifdef _DEBUG
            // let's find out about our CPU
            #define SCRYPT_TEST_SPEED
        #endif
    #else   // for gcc on Windows
        #if !defined( QT_GUI )
            extern "C" {
        #endif
    #endif
#endif

#include "scrypt-jane.h"
#include "code/scrypt-jane-portable.h"
#include "code/scrypt-jane-hash.h"
#include "code/scrypt-jane-romix.h"
#include "code/scrypt-jane-test-vectors.h"


#define scrypt_maxN 30  /* (1 << (30 + 1)) = ~2 billion */
#if (SCRYPT_BLOCK_BYTES == 64)
#define scrypt_r_32kb 8 /* (1 << 8) = 256 * 2 blocks in a chunk * 64 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 128)
#define scrypt_r_32kb 7 /* (1 << 7) = 128 * 2 blocks in a chunk * 128 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 256)
#define scrypt_r_32kb 6 /* (1 << 6) = 64 * 2 blocks in a chunk * 256 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 512)
#define scrypt_r_32kb 5 /* (1 << 5) = 32 * 2 blocks in a chunk * 512 bytes = Max of 32kb in a chunk */
#endif
#define scrypt_maxr scrypt_r_32kb /* 32kb */
#define scrypt_maxp 25  /* (1 << 25) = ~33 million */

#include <stdio.h>
#include <malloc.h>

#ifdef _MSC_VER
    #ifdef _DEBUG
//_____________________________________________________________________________
//_____________________________________________________________________________
// cpuid.cpp 
// processor: x86, x64
// Use the __cpuid intrinsic to get information about a CPU

#include <stdio.h>
#include <string.h>
#include <intrin.h>

const char* szFeatures[] =
{
    "x87 FPU On Chip",
    "Virtual-8086 Mode Enhancement",
    "Debugging Extensions",
    "Page Size Extensions",
    "Time Stamp Counter",
    "RDMSR and WRMSR Support",
    "Physical Address Extensions",
    "Machine Check Exception",
    "CMPXCHG8B Instruction",
    "APIC On Chip",
    "Unknown1",
    "SYSENTER and SYSEXIT",
    "Memory Type Range Registers",
    "PTE Global Bit",
    "Machine Check Architecture",
    "Conditional Move/Compare Instruction",
    "Page Attribute Table",
    "Page Size Extension",
    "Processor Serial Number",
    "CFLUSH Extension",
    "Unknown2",
    "Debug Store",
    "Thermal Monitor and Clock Ctrl",
    "MMX Technology",
    "FXSAVE/FXRSTOR",
    "SSE Extensions",
    "SSE2 Extensions",
    "Self Snoop",
    "Hyper-threading Technology",
    "Thermal Monitor",
    "Unknown4",
    "Pend. Brk. EN."
};

void mainCPUtest(void)
{
    char CPUString[0x20];
    char CPUBrandString[0x40];
    int CPUInfo[4] = {-1};
    int nSteppingID = 0;
    int nModel = 0;
    int nFamily = 0;
    int nProcessorType = 0;
    int nExtendedmodel = 0;
    int nExtendedfamily = 0;
    int nBrandIndex = 0;
    int nCLFLUSHcachelinesize = 0;
    int nAPICPhysicalID = 0;
    int nFeatureInfo = 0;
    int nCacheLineSize = 0;
    int nL2Associativity = 0;
    int nCacheSizeK = 0;
    int nRet = 0;
    unsigned    nIds, nExIds, i;
    BOOL    bSSE3NewInstructions = FALSE;
    BOOL    bMONITOR_MWAIT = FALSE;
    BOOL    bCPLQualifiedDebugStore = FALSE;
    BOOL    bThermalMonitor2 = FALSE;


    // __cpuid with an InfoType argument of 0 returns the number of
    // valid Ids in CPUInfo[0] and the CPU identification string in
    // the other three array elements. The CPU identification string is
    // not in linear order. The code below arranges the information 
    // in a human readable form.
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    memset(CPUString, 0, sizeof(CPUString));
    *((int*)CPUString) = CPUInfo[1];
    *((int*)(CPUString+4)) = CPUInfo[3];
    *((int*)(CPUString+8)) = CPUInfo[2];

    // Get the information associated with each valid Id
    for (i=0; i<=nIds; ++i)
    {
        __cpuid(CPUInfo, i);
        printf_s("\nFor InfoType %d\n", i); 
        printf_s("CPUInfo[0] = 0x%x\n", CPUInfo[0]);
        printf_s("CPUInfo[1] = 0x%x\n", CPUInfo[1]);
        printf_s("CPUInfo[2] = 0x%x\n", CPUInfo[2]);
        printf_s("CPUInfo[3] = 0x%x\n", CPUInfo[3]);

        // Interpret CPU feature information.
        if  (i == 1)
        {
            nSteppingID = CPUInfo[0] & 0xf;
            nModel = (CPUInfo[0] >> 4) & 0xf;
            nFamily = (CPUInfo[0] >> 8) & 0xf;
            nProcessorType = (CPUInfo[0] >> 12) & 0x3;
            nExtendedmodel = (CPUInfo[0] >> 16) & 0xf;
            nExtendedfamily = (CPUInfo[0] >> 20) & 0xff;
            nBrandIndex = CPUInfo[1] & 0xff;
            nCLFLUSHcachelinesize = ((CPUInfo[1] >> 8) & 0xff) * 8;
            nAPICPhysicalID = (CPUInfo[1] >> 24) & 0xff;
            bSSE3NewInstructions = (CPUInfo[2] & 0x1) || FALSE;
            bMONITOR_MWAIT = (CPUInfo[2] & 0x8) || FALSE;
            bCPLQualifiedDebugStore = (CPUInfo[2] & 0x10) || FALSE;
            bThermalMonitor2 = (CPUInfo[2] & 0x100) || FALSE;
            nFeatureInfo = CPUInfo[3];
        }
    }

    // Calling __cpuid with 0x80000000 as the InfoType argument
    // gets the number of valid extended IDs.
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    memset(CPUBrandString, 0, sizeof(CPUBrandString));

    // Get the information associated with each extended ID.
    for (i=0x80000000; i<=nExIds; ++i)
    {
        __cpuid(CPUInfo, i);
        printf_s("\nFor InfoType %x\n", i); 
        printf_s("CPUInfo[0] = 0x%x\n", CPUInfo[0]);
        printf_s("CPUInfo[1] = 0x%x\n", CPUInfo[1]);
        printf_s("CPUInfo[2] = 0x%x\n", CPUInfo[2]);
        printf_s("CPUInfo[3] = 0x%x\n", CPUInfo[3]);

        // Interpret CPU brand string and cache information.
        if  (i == 0x80000002)
            memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
        else if  (i == 0x80000003)
            memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
        else if  (i == 0x80000004)
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
        else if  (i == 0x80000006)
        {
            nCacheLineSize = CPUInfo[2] & 0xff;
            nL2Associativity = (CPUInfo[2] >> 12) & 0xf;
            nCacheSizeK = (CPUInfo[2] >> 16) & 0xffff;
        }
    }

    // Display all the information in user-friendly format.

    printf_s("\n\nCPU String: %s\n", CPUString);

    if  (nIds >= 1)
    {
        if  (nSteppingID)
            printf_s("Stepping ID = %d\n", nSteppingID);
        if  (nModel)
            printf_s("Model = %d\n", nModel);
        if  (nFamily)
            printf_s("Family = %d\n", nFamily);
        if  (nProcessorType)
            printf_s("Processor Type = %d\n", nProcessorType);
        if  (nExtendedmodel)
            printf_s("Extended model = %d\n", nExtendedmodel);
        if  (nExtendedfamily)
            printf_s("Extended family = %d\n", nExtendedfamily);
        if  (nBrandIndex)
            printf_s("Brand Index = %d\n", nBrandIndex);
        if  (nCLFLUSHcachelinesize)
            printf_s("CLFLUSH cache line size = %d\n",
                     nCLFLUSHcachelinesize);
        if  (nAPICPhysicalID)
            printf_s("APIC Physical ID = %d\n", nAPICPhysicalID);

if  (nFeatureInfo || bSSE3NewInstructions ||
             bMONITOR_MWAIT || bCPLQualifiedDebugStore ||
             bThermalMonitor2)
        {
            printf_s("\nThe following features are supported:\n");

if  (bSSE3NewInstructions)
printf_s("\tSSE3 New Instructions\n");
if  (bMONITOR_MWAIT)
printf_s("\tMONITOR/MWAIT\n");
if  (bCPLQualifiedDebugStore)
printf_s("\tCPL Qualified Debug Store\n");
if  (bThermalMonitor2)
printf_s("\tThermal Monitor 2\n");

            i = 0;
            nIds = 1;
            while (i < (sizeof(szFeatures)/sizeof(const char*)))
            {
                if  (nFeatureInfo & nIds)
                {
                    printf_s("\t");
                    printf_s(szFeatures[i]);
                    printf_s("\n");
                }

                nIds <<= 1;
                ++i;
            }
        }
    }

    if  (nExIds >= 0x80000004)
        printf_s("\nCPU Brand String: %s\n", CPUBrandString);

    if  (nExIds >= 0x80000006)
    {
        printf_s("Cache Line Size = %d\n", nCacheLineSize);
        printf_s("L2 Associativity = %d\n", nL2Associativity);
        printf_s("Cache Size = %dK\n", nCacheSizeK);
    }

return;
}
//_____________________________________________________________________________
//_____________________________________________________________________________
    #endif
#endif

static void
scrypt_fatal_error_default(const char *msg) {
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static scrypt_fatal_errorfn scrypt_fatal_error = scrypt_fatal_error_default;

void
scrypt_set_fatal_error_default(scrypt_fatal_errorfn fn) {
	scrypt_fatal_error = fn;
}

static int
scrypt_power_on_self_test() {
	const scrypt_test_setting *t;
	uint8_t test_digest[64];
	uint32_t i;
	int res = 7, scrypt_valid;

#ifdef _MSC_VER
    #ifdef _DEBUG
        //mainCPUtest();    //if you are curious about your CPU
    #endif
#endif
	if (!scrypt_test_mix()) 
    {
#if !defined(SCRYPT_TEST)
		scrypt_fatal_error("scrypt: mix function power-on-self-test failed");
#endif
		res &= ~1;
	}

	if (!scrypt_test_hash()) 
    {
#if !defined(SCRYPT_TEST)
		scrypt_fatal_error("scrypt: hash function power-on-self-test failed");
#endif
		res &= ~2;
	}

	for (i = 0, scrypt_valid = 1; post_settings[i].pw; i++) 
    {
		t = post_settings + i;
		scrypt((uint8_t *)t->pw, strlen(t->pw), (uint8_t *)t->salt, strlen(t->salt), t->Nfactor, t->rfactor, t->pfactor, test_digest, sizeof(test_digest));
		scrypt_valid &= scrypt_verify(post_vectors[i], test_digest, sizeof(test_digest));
	}
	
	if (!scrypt_valid) 
    {
#if !defined(SCRYPT_TEST)
		scrypt_fatal_error("scrypt: scrypt power-on-self-test failed");
#endif
		res &= ~4;
	}

	return res;
}

typedef struct scrypt_aligned_alloc_t {
	uint8_t *mem, *ptr;
} scrypt_aligned_alloc;

#if defined(SCRYPT_TEST_SPEED)
static uint8_t *mem_base = (uint8_t *)0;
static size_t mem_bump = 0;

/* allocations are assumed to be multiples of 64 bytes and total allocations not to exceed ~1.01gb */
static scrypt_aligned_alloc
scrypt_alloc(uint64_t size) {
	scrypt_aligned_alloc aa;
	if (!mem_base) {
		mem_base = (uint8_t *)malloc((1024 * 1024 * 1024) + (1024 * 1024) + (SCRYPT_BLOCK_BYTES - 1));
		if (!mem_base)
			scrypt_fatal_error("scrypt: out of memory");
		mem_base = (uint8_t *)(((size_t)mem_base + (SCRYPT_BLOCK_BYTES - 1)) & ~(SCRYPT_BLOCK_BYTES - 1));
	}
	aa.mem = mem_base + mem_bump;
	aa.ptr = aa.mem;
	mem_bump += (size_t)size;
	return aa;
}

static void
scrypt_free(scrypt_aligned_alloc *aa) {
	mem_bump = 0;
}
#else
static scrypt_aligned_alloc
scrypt_alloc(uint64_t size) {
	static const size_t max_alloc = (size_t)-1;
	scrypt_aligned_alloc aa;
	size += (SCRYPT_BLOCK_BYTES - 1);
	if (size > max_alloc)
		scrypt_fatal_error("scrypt: not enough address space on this CPU to allocate required memory");
	aa.mem = (uint8_t *)malloc((size_t)size);
	aa.ptr = (uint8_t *)(((size_t)aa.mem + (SCRYPT_BLOCK_BYTES - 1)) & ~(SCRYPT_BLOCK_BYTES - 1));
	if (!aa.mem)
		scrypt_fatal_error("scrypt: out of memory");
	return aa;
}

static void
scrypt_free(scrypt_aligned_alloc *aa) {
	free(aa->mem);
}
#endif


void
scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint8_t Nfactor, uint8_t rfactor, uint8_t pfactor, uint8_t *out, size_t bytes) {
	scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t N, r, p, chunk_bytes, i;

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
	scrypt_ROMixfn scrypt_ROMix = scrypt_getROMix();
#endif

#if !defined(SCRYPT_TEST)
	static int power_on_self_test = 0;
	if (!power_on_self_test) {
		power_on_self_test = 1;
		if (!scrypt_power_on_self_test())
			scrypt_fatal_error("scrypt: power on self test failed");
	}
#endif

	if (Nfactor > scrypt_maxN)
		scrypt_fatal_error("scrypt: N out of range");
	if (rfactor > scrypt_maxr)
		scrypt_fatal_error("scrypt: r out of range");
	if (pfactor > scrypt_maxp)
		scrypt_fatal_error("scrypt: p out of range");

	N = (1 << (Nfactor + 1));
	r = (1 << rfactor);
	p = (1 << pfactor);

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;
	V = scrypt_alloc((uint64_t)N * chunk_bytes);
	YX = scrypt_alloc((p + 1) * chunk_bytes);

	/* 1: X = PBKDF2(password, salt) */
	Y = YX.ptr;
	X = Y + chunk_bytes;
	scrypt_pbkdf2(password, password_len, salt, salt_len, 1, X, chunk_bytes * p);

	/* 2: X = ROMix(X) */
	for (i = 0; i < p; i++)
		scrypt_ROMix((scrypt_mix_word_t *)(X + (chunk_bytes * i)), (scrypt_mix_word_t *)Y, (scrypt_mix_word_t *)V.ptr, N, r);

	/* 3: Out = PBKDF2(password, X) */
	scrypt_pbkdf2(password, password_len, X, chunk_bytes * p, 1, out, bytes);

	scrypt_ensure_zero(YX.ptr, (p + 1) * chunk_bytes);

	scrypt_free(&V);
	scrypt_free(&YX);
}
#if defined( _WINDOWS )
    #ifdef _MSC_VER
    #else
        #if !defined( QT_GUI )
        }
        #endif
    #endif
#endif
