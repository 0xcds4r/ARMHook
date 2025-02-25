#include "main.h"
#include "ARMHook.h"
#include <sys/mman.h>
#include <unistd.h> 

// ARM32 (AArch32) hook procedure
#define HOOK_PROC_ARM32 "\x01\xB4\x01\xB4\x01\x48\x01\x90\x01\xBD\x00\xBF\x00\x00\x00\x00"
// ARM64 (AArch64) hook procedure
#define HOOK_PROC_ARM64 "\xE1\x0F\x00\xF8\xE1\x07\x00\xF8\x60\x00\x00\xD4\x00\x00\x00\x00"

uintptr_t arm_mmap_start    = 0;
uintptr_t arm_mmap_end      = 0;
uintptr_t local_trampoline  = 0;
uintptr_t remote_trampoline = 0;

#if defined(__arm__)
#define IS_ARM32 1
#define IS_ARM64 0
#elif defined(__aarch64__)
#define IS_ARM32 0
#define IS_ARM64 1
#else
#error "Unsupported architecture"
#endif

uintptr_t ARMHook::getLibraryAddress(const char* library) {
    char filename[0xFF] = {0}, buffer[2048] = {0};
    FILE *fp = 0;
    uintptr_t address = 0;

    sprintf(filename, "/proc/%d/maps", getpid());
    fp = fopen(filename, "rt");
    if (!fp) goto done;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, library)) {
            address = (uintptr_t)strtoul(buffer, 0, 16);
            break;
        }
    }

done:
    if (fp) fclose(fp);
    return address;
}

void ARMHook::InitialiseTrampolines(uintptr_t dest, uintptr_t size) {
    local_trampoline   = dest;
    remote_trampoline  = local_trampoline + size;

    size_t page_size = sysconf(_SC_PAGESIZE);
    arm_mmap_start = (uintptr_t)mmap(0, page_size, PROT_WRITE | PROT_READ | PROT_EXEC,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect((void*)(arm_mmap_start & ~(page_size-1)), page_size, 
             PROT_READ | PROT_EXEC | PROT_WRITE);
    arm_mmap_end = arm_mmap_start + page_size;
}

void ARMHook::unprotect(uintptr_t ptr) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    mprotect((void*)(ptr & ~(page_size-1)), page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void ARMHook::writeMem(uintptr_t dest, uintptr_t src, size_t size) {
    ARMHook::unprotect(dest);
    memcpy((void*)dest, (void*)src, size);
    cacheflush(dest, dest + size, 0);
}

void ARMHook::makeRet(uintptr_t dest) {
    if (IS_ARM32) {
        ARMHook::writeMem(dest, (uintptr_t)"\xF7\x46", 2); // MOV PC, LR (ARM32)
    } else if (IS_ARM64) {
        ARMHook::writeMem(dest, (uintptr_t)"\xC0\x03\x5F\xD6", 4); // RET (ARM64)
    }
}

void ARMHook::readMem(uintptr_t dest, uintptr_t src, size_t size) {
    ARMHook::unprotect(src);
    memcpy((void*)dest, (void*)src, size);
}

void ARMHook::makeNOP(uintptr_t addr, unsigned int count) {
    ARMHook::unprotect(addr);
    if (IS_ARM32) {
        for (uintptr_t ptr = addr; ptr != (addr + (count * 2)); ptr += 2) {
            *(char*)ptr = 0x00;
            *(char*)(ptr + 1) = 0x46; // MOV R8, R8 (ARM32 NOP)
        }
    } else if (IS_ARM64) {
        for (uintptr_t ptr = addr; ptr != (addr + (count * 4)); ptr += 4) {
            *(uint32_t*)ptr = 0xD503201F; // NOP (ARM64)
        }
    }
}

void ARMHook::writeMemHookProc(uintptr_t addr, uintptr_t func) {
    char code[16];
    if (IS_ARM32) {
        memcpy(code, HOOK_PROC_ARM32, 16);
        *(uint32_t*)&code[12] = (func | 1); // Thumb mode bit
    } else if (IS_ARM64) {
        memcpy(code, HOOK_PROC_ARM64, 16);
        *(uint64_t*)&code[8] = func; // 64-bit address
    }
    ARMHook::writeMem(addr, (uintptr_t)code, 16);
}

void ARMHook::JMPCode(uintptr_t func, uintptr_t addr) {
    if (IS_ARM32) {
        // ARM32 (Thumb) two-part branch instruction
        // Max range: ±16MB (22-bit offset)
        int32_t offset = addr - func - 4; // Account for PC offset in ARM32
        uint32_t code = ((offset >> 12) & 0x7FF) | 0xF000 |          // Upper 11 bits
                       ((((offset >> 1) & 0x7FF) | 0xB800) << 16); // Lower 11 bits
        ARMHook::writeMem(func, (uintptr_t)&code, 4);
    } else if (IS_ARM64) {
        // ARM64 uses B instruction with ±128MB range (26-bit offset)
        int64_t offset = addr - func;
        if (offset >= -0x08000000 && offset <= 0x07FFFFFF) {
            // Direct branch is possible
            uint32_t code = 0x14000000 | ((offset >> 2) & 0x03FFFFFF); // B instruction
            ARMHook::writeMem(func, (uintptr_t)&code, 4);
        } else {
            // Large jump (>128MB): Use trampoline with LDR and BR
            // Allocate space in trampoline area if available
            if (remote_trampoline < (local_trampoline + 16) || 
                arm_mmap_end < (arm_mmap_start + 16)) {
                std::terminate(); // Not enough space
            }

            // Write trampoline code: LDR X16, [PC, #0]; BR X16; <64-bit addr>
            uint32_t tramp_code[4] = {
                0x58000050,        // LDR X16, [PC, #0]
                0xD61F0200,        // BR X16
                (uint32_t)(addr & 0xFFFFFFFF),      // Lower 32 bits of target addr
                (uint32_t)(addr >> 32)              // Upper 32 bits of target addr
            };
            ARMHook::writeMem(local_trampoline, (uintptr_t)tramp_code, 16);

            // Branch to trampoline
            offset = local_trampoline - func;
            if (offset >= -0x08000000 && offset <= 0x07FFFFFF) {
                uint32_t code = 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
                ARMHook::writeMem(func, (uintptr_t)&code, 4);
            } else {
                // If trampoline is still too far (extremely rare), fail gracefully
                std::terminate();
            }

            local_trampoline += 16; // Update trampoline pointer
        }
    }
}

void ARMHook::installHook(uintptr_t addr, uintptr_t func, uintptr_t *orig) {
    size_t min_size = IS_ARM64 ? 0x40 : 0x20;
    if (remote_trampoline < (local_trampoline + (IS_ARM64 ? 0x20 : 0x10)) || 
        arm_mmap_end < (arm_mmap_start + min_size))
        return std::terminate();

    size_t copy_size = IS_ARM64 ? 8 : 4;
    ARMHook::readMem(arm_mmap_start, addr, copy_size);
    ARMHook::writeMemHookProc(arm_mmap_start + copy_size, addr + copy_size);
    *orig = arm_mmap_start + (IS_ARM32 ? 1 : 0); // Thumb bit for ARM32 only
    arm_mmap_start += min_size;

    ARMHook::JMPCode(addr, local_trampoline);
    ARMHook::writeMemHookProc(local_trampoline, func);
    local_trampoline += IS_ARM64 ? 32 : 16;
}

void ARMHook::installMethodHook(uintptr_t addr, uintptr_t func) {
    ARMHook::unprotect(addr);
    *(uintptr_t*)addr = func; // Works for both (size differs)
}

void ARMHook::putCode(uintptr_t addr, uintptr_t point, uintptr_t func) {
    ARMHook::unprotect(addr + point);
    *(uintptr_t*)(addr + point) = func;
}

void ARMHook::injectCode(uintptr_t addr, uintptr_t func, int reg) {
    if (IS_ARM32) {
        char injectCode[12];
        injectCode[0] = 0x01;
        injectCode[1] = 0xA0 + reg;
        injectCode[2] = (0x08 * reg) + reg;
        injectCode[3] = 0x68;
        injectCode[4] = 0x87 + (0x08 * reg);
        injectCode[5] = 0x46;
        injectCode[6] = injectCode[4];
        injectCode[7] = injectCode[5];
        *(uintptr_t*)&injectCode[8] = func;
        ARMHook::writeMem(addr, (uintptr_t)injectCode, 12);
    } else if (IS_ARM64) {
        uint32_t injectCode[4];
        injectCode[0] = 0xD2800000 | (reg & 0x1F); // MOV Xreg, #0
        injectCode[1] = 0xF9400000 | (reg & 0x1F); // LDR Xreg, [X0]
        injectCode[2] = 0xD61F0000 | ((reg & 0x1F) << 5); // BR Xreg
        injectCode[3] = (uint32_t)(func & 0xFFFFFFFF); // Lower 32 bits of func
        ARMHook::writeMem(addr, (uintptr_t)injectCode, 16); // Need extra handling for full 64-bit
    }
}
