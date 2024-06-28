#define _GNU_SOURCE

#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <immintrin.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <cpuid.h>
#include "xom.h"
#include "modxom.h"

#if (defined(__x86_64__) || defined(_M_X64))
#define XOM_BASE_ADDRESS        0x420000000000
#else
#define XOM_BASE_ADDRESS        0x42000000ul
#endif

#define LIBXOM_ENVVAR           "LIBXOM_LOCK"
#define LIBXOM_ENVVAR_LOCK_ALL  "all"
#define LIBXOM_ENVVAR_LOCK_LIBS "libs"

#define TEXT_TYPE_EXECUTABLE    1
#define TEXT_TYPE_SHARED        (1 << 1)
#define TEXT_TYPE_VDSO          (1 << 2)

#define PAGE_SIZE               0x1000
#define PAGE_SHIFT              12
#define MAX_ORDER               11
#define ALLOC_CHUNK_SIZE        ((1 << (MAX_ORDER - 1)) << PAGE_SHIFT)

#define SIZE_CEIL(S)            ((((S) >> PAGE_SHIFT) + ((S) & (PAGE_SIZE - 1) ? 1 : 0) ) << PAGE_SHIFT)
#define min(x, y)               ((x) < (y) ? (x) : (y))
#define countof(X)              (sizeof(X) / sizeof(*(X)))

extern char **__environ;

struct xombuf {
    void *address;
    size_t allocated_size;
    pid_t pid;
    uint8_t locked;
    uint8_t marked;
    uint8_t xom_mode;
} typedef _xombuf, *p_xombuf;

struct xom_subpages {
    void *address;
    uint8_t xom_mode;
    uint32_t *lock_status;
    size_t num_subpages;
    int8_t references;
} typedef _xom_subpages, *p_xom_subpages;

// Describes an executable memory region
struct {
    char *text_base;                  // Start of memory region, must be page-aligned
    char *text_end;                   // End of memory region, must be page-aligned
    unsigned char type;               // Type of memory region (main executable, shared library or libc)
    unsigned char jump_into_backup;   // Do we have to jump into backup code when unmapping this region?
} typedef text_region;

int32_t xomfd = -1;
int subpage_pkey = -1;

static jmp_buf reg_clear_recovery_buffer;
static pthread_mutex_t full_reg_clear_lock;
static pthread_mutexattr_t full_reg_clear_lock_attr;
static __sighandler_t old_sig_handler;

static volatile uint8_t initialized = 0;
static pthread_mutex_t lib_lock;
static unsigned int xom_mode = XOM_MODE_UNSUPPORTED;
static void *xom_base_addr = NULL;
static unsigned char migrate_dlopen = 0;
static pid_t libxom_pid = 0;

static void *(*dlopen_original)(const char *, int) = NULL;

static void *(*dlmopen_original)(Lmid_t, const char *, int) = NULL;

#define wrap_call(T, F) {           \
    T r;                            \
    __libxom_prologue();            \
    r = F;                          \
    __libxom_epilogue();            \
    return r;                       \
}

static inline void unblock_signal(const int signum) {
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, signum);
    sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

static void full_reg_clear_handler(int signum) {
    unblock_signal(signum);
    longjmp(reg_clear_recovery_buffer, 1);
}

int expect_full_reg_clear__(void) {
    int lock_status;

    // Make sure that all callee-saved registers are backed up to memory
    volatile register uintptr_t r12 asm("r12") = 0;
    volatile register uintptr_t r13 asm("r13") = r12;
    volatile register uintptr_t r14 asm("r14") = r13;
    volatile register uintptr_t r15 asm("r15") = r14;
    volatile register uintptr_t rbx asm("rbx") = r15;
    volatile register uintptr_t rdi asm("rdi") = rbx;
    volatile register uintptr_t rsi asm("rsi") = rdi;
    r12 = rsi;

    lock_status = pthread_mutex_lock(&full_reg_clear_lock);

    if (lock_status == EDEADLK) {
        if (xomfd >= 0) {
            signal(SIGSEGV, old_sig_handler);
            pthread_mutex_unlock(&full_reg_clear_lock);
        }
        return 0;
    }
    if (lock_status)
        return 0;

    if (xomfd >= 0) {
        old_sig_handler = signal(SIGSEGV, full_reg_clear_handler);
        setjmp(reg_clear_recovery_buffer);
    }

    return 1;
}

static uint8_t is_pku_supported(void) {
    unsigned long a, b, c, d;

    __cpuid_count(7, 0, a, b, c, d);

    return (uint8_t) (c >> 3) & 1;
}

static void __libxom_prologue() {
    pthread_mutex_lock(&lib_lock);
    if (xomfd >= 0 && libxom_pid != getpid()) {
        close(xomfd);
        xomfd = open(XOM_FILE, O_RDWR);
        libxom_pid = getpid();
    }
}

static inline void __libxom_epilogue() {
    pthread_mutex_unlock(&lib_lock);
}

#if (defined(__x86_64__) || defined(_M_X64))

static int migrate_skip_type(unsigned int);

void *dlopen(const char *filename, int flags) {
    void *ret;

    if (!dlopen_original)
        return NULL;
    ret = dlopen_original(filename, flags);
    if (!migrate_dlopen)
        return ret;
    if (ret)
        migrate_skip_type(TEXT_TYPE_VDSO);
    return ret;
}


void *dlmopen(Lmid_t lmid, const char *filename, int flags) {
    void *ret;
    if (!dlmopen_original)
        return NULL;
    ret = dlmopen_original(lmid, filename, flags);
    if (!migrate_dlopen)
        return ret;
    if (ret)
        migrate_skip_type(TEXT_TYPE_VDSO);
    return ret;
}

#endif

/**
 * Parse the /proc/<pid>/maps file to find all executable memory segments
 *
 * @returns An array of text_region structs, which is terminated by an
 *  entry with .type = 0. The caller must free this array
*/
static text_region *explore_text_regions() {
    const unsigned long vdso_base = getauxval(AT_SYSINFO_EHDR);
    const static char mpath[] = "/proc/self/maps";
    char perms[3] = {0,};
    char *line = NULL;
    unsigned i;
    int status;
    size_t start, end, last = 0, len = 0;
    ssize_t count = 0;
    FILE *maps;
    text_region *regions;


    maps = fopen(mpath, "r");
    if (!maps)
        return NULL;

    // Get amount of executable memory regions
    while (getline(&line, &len, maps) > 0) {
        status = sscanf(line, "%lx-%lx %c%c%c", &start, &end, &perms[0], &perms[1], &perms[2]);
        free(line);
        line = NULL;
        if (status != 5)
            continue;
        count += perms[2] == 'x' ? 1 : 0;
    }
    rewind(maps);

    // We need this buffer until it was used once, which may be never
    regions = malloc(sizeof(*regions) * (count + 1));
    if (!regions) {
        fclose(maps);
        return NULL;
    }

    count = 0;
    while (getline(&line, &len, maps) > 0) {
        status = sscanf(line, "%lx-%lx %c%c%c", &start, &end, &perms[0], &perms[1], &perms[2]);
        free(line);
        line = NULL;
        if (status != 5)
            continue;
        if (perms[2] != 'x')
            continue;

        regions[count].text_base = (char *) start;
        regions[count].text_end = (char *) end;

        if (!count)
            regions[count].type = TEXT_TYPE_EXECUTABLE;
        else if (regions[count].text_base == (char *) vdso_base)
            regions[count].type = TEXT_TYPE_VDSO;
        else
            regions[count].type = TEXT_TYPE_SHARED;

        regions[count].jump_into_backup = (start <= (size_t) explore_text_regions &&
                                           end > (size_t) explore_text_regions) ? 1 : 0;
        count++;
    }
    fclose(maps);

    regions[count].type = 0;

    return regions;
}

#if (defined(__x86_64__) || defined(_M_X64))

/**
 * Unmap the code specified by space, remap it as xom, and fill it with the data in dest
 *
 * @param space A text_region describing the code section that should be remapped
 * @param dest A backup buffer containing the code in space. It must have the same size
 * @param fd The /proc/xom file descriptor
 *
 * @returns 0 upon success, a negative value otherwise
*/
static __attribute__((optimize("O0"))) int remap_no_libc(text_region *space, char *dest, int32_t fd) {
    int status;
    unsigned int i, c = 0;
    char *remapping = space->text_base, *rptr;
    ssize_t size_left = space->text_end - space->text_base;

    /*
    remap_no_libc must work in an environment where the GOT is unavailable,
    which means that we cannot use any shared libraries whatsoever.
    This unfortunately includes libc, so we have to inline absolutely
    everything, including syscalls and memcpy. Also, we cannot use compiler
    optimizations for this code, as the compiler may attempt to insert calls
    to libc for better performance.
    */

    // Munmap old .text section
    asm volatile("syscall" : "=a"(status) : "a"(SYS_munmap),
    "D"(space->text_base), "S"(space->text_end - space->text_base));

    // If there is an error, we can do nothing but quit
    if (status < 0)
        asm volatile("syscall"::"a"(SYS_exit), "D"(1));  // exit(1)

    // Mmap new .text section
    while (size_left > 0) {
        asm volatile(
                "mov %%ecx, %%ecx\n"
                "mov %%rcx, %%r10\n"
                "mov %%ebx, %%ebx\n"
                "mov %%rbx, %%r8\n"
                "mov $0, %%r9\n"
                "syscall\n"
                "mov %%rax, %0"
                : "=r" (rptr)
                : "a"(SYS_mmap), "D"(remapping), "S"(min(size_left, ALLOC_CHUNK_SIZE)),
        "d"(PROT_NONE), "c"(MAP_PRIVATE), "b"(fd)
                : "r8", "r9", "r10"
                );

        if (rptr != space->text_base + c * ALLOC_CHUNK_SIZE)
            asm volatile("syscall"::"a"(SYS_exit), "D"(-(int8_t) (uintptr_t) rptr)); // exit(errno)

        remapping += ALLOC_CHUNK_SIZE;
        size_left -= ALLOC_CHUNK_SIZE;
        c++;
    }

    // Copy from backup into new .txt
    for (i = 0; i < (space->text_end - space->text_base) / sizeof(size_t); i++)
        ((size_t *) space->text_base)[i] = ((size_t *) (dest))[i];

    return 0;
}

/**
 * Migrate the code in space to XOM
 *
 * @param space A text_region describing the code that should be migrated
 * @returns 0 upon success, a negative value otherwise
*/
static int migrate_text_section(text_region *space) {
    int status;
    unsigned int c = 0;
    char *dest;
    size_t num_pages = (space->text_end - space->text_base) >> PAGE_SHIFT;
    ssize_t size_left;
    int (*remap_function)(text_region *, char *, int32_t);
    modxom_cmd cmd;

    // If modxom is unavailable, use PKU
    if (xomfd < 0)
        return mprotect(space->text_base, space->text_end - space->text_base, PROT_EXEC);

    // printf("Remapping %p - %p, type %u - %u\n", space->text_base, space->text_end, space->type, space->jump_into_backup);

    // Mmap code backup
    dest = mmap(NULL, num_pages << PAGE_SHIFT, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (!~(uintptr_t) dest)
        return -1;

    // Copy code
    memcpy(dest, space->text_base, num_pages << PAGE_SHIFT);

    remap_function = remap_no_libc;

    // We cannot unmap the code we are currently executing. If this needs to be done, jump
    // into the backup and do it from there
    if (space->jump_into_backup) {
        mprotect(dest, num_pages << PAGE_SHIFT, PROT_READ | PROT_EXEC);
        remap_function = (int (*)(text_region *, char *, int32_t)) ((size_t) remap_function +
                                                                    (ssize_t) (dest - space->text_base));
    }

    // Remap code into XOM buffer
    status = remap_function(space, dest, xomfd);

    // Lock code
    size_left = (space->text_end - space->text_base);
    while (status >= 0 && size_left > 0) {
        cmd.cmd = MODXOM_CMD_LOCK;
        cmd.num_pages = min(size_left, ALLOC_CHUNK_SIZE) >> PAGE_SHIFT;
        cmd.base_addr = (uintptr_t) space->text_base + c * ALLOC_CHUNK_SIZE;
        status = write(xomfd, &cmd, sizeof(cmd));
        size_left -= ALLOC_CHUNK_SIZE;
        c++;
    }

    // Unmap backup
    munmap(dest, num_pages << PAGE_SHIFT);
    return status;
}

static int migrate_skip_type(unsigned int skip_type) {
    int status = 1;
    unsigned int i = 0;
    text_region *spaces;

    if (!xom_mode) {
        errno = EINVAL;
        return -1;
    }

    spaces = explore_text_regions();
    if (!spaces)
        return -1;

    while (spaces[i].type) {
        if (!(spaces[i].type & skip_type)) {
            status = migrate_text_section(&(spaces[i]));
            if (status < 0)
                break;
        }
        i++;
    }

    free(spaces);
    spaces = NULL;

    return status;
}

static inline int migrate_shared_libraries_internal() {
    return migrate_skip_type(TEXT_TYPE_EXECUTABLE | TEXT_TYPE_VDSO);
}

static inline int migrate_all_code_internal() {
    return migrate_skip_type(TEXT_TYPE_VDSO);
}

#endif

static p_xombuf xomalloc_page_internal(size_t size) {
    void *current_address = xom_base_addr, *last_address = NULL;
    ssize_t size_left = (ssize_t) size;
    p_xombuf ret;

    if (!size || !xom_mode) {
        errno = EINVAL;
        return NULL;
    }

    ret = malloc(sizeof(*ret));

    if (!ret) {
        errno = ENOMEM;
        return NULL;
    }

    ret->address = NULL;
    while (size_left > 0) {
        current_address = mmap(current_address, SIZE_CEIL(min(ALLOC_CHUNK_SIZE, size_left)),
                               PROT_READ | PROT_WRITE, MAP_PRIVATE | (xomfd < 0 ? MAP_ANONYMOUS : 0), xomfd, 0);
        if (!current_address)
            goto fail;
        if (!ret->address)
            ret->address = current_address;
        last_address = current_address;
        current_address += ALLOC_CHUNK_SIZE;
        xom_base_addr = current_address;
        size_left -= ALLOC_CHUNK_SIZE;
    }


    *ret = (_xombuf) {
            .address = ret->address,
            .allocated_size = size,
            .pid = getpid(),
            .locked = 0,
            .marked = 0,
            .xom_mode = (uint8_t) xom_mode
    };

    return ret;

    fail:
    size_left = (ssize_t) size;
    while (ret->address && ret->address <= last_address) {
        munmap(ret->address, SIZE_CEIL(min(ALLOC_CHUNK_SIZE, size_left)));
        ret->address += ALLOC_CHUNK_SIZE;
        size_left -= ALLOC_CHUNK_SIZE;
    }
    free(ret);
    return NULL;
}

static int
xom_write_internal(struct xombuf *dest, const void *const restrict src, const size_t size, const size_t offset) {
    if (!dest || !src || !size) {
        errno = EINVAL;
        return -1;
    }
    if (dest->locked || dest->allocated_size < offset + size) {
        errno = EINVAL;
        return -1;
    }
    memcpy((void *) ((uintptr_t) dest->address + offset), src, size);
    return (int) size;
}

static void *xom_lock_internal(struct xombuf *buf) {
    int status, c = 0;
    modxom_cmd cmd;
    ssize_t size_left;

    if (!buf) {
        errno = EINVAL;
        return NULL;
    }

    if (buf->locked)
        return buf->address;

    if (buf->xom_mode == XOM_MODE_PKU) {
        if (mprotect(buf->address, SIZE_CEIL(buf->allocated_size), PROT_EXEC) < 0)
            return NULL;
        buf->locked = 1;
        return buf->address;
    }

    if (buf->pid != libxom_pid)
        return NULL;

    size_left = (ssize_t) buf->allocated_size;
    while (size_left > 0) {
        cmd = (modxom_cmd) {
                .cmd = MODXOM_CMD_LOCK,
                .num_pages = (uint32_t) SIZE_CEIL(min(size_left, ALLOC_CHUNK_SIZE)) >> PAGE_SHIFT,
                .base_addr = (uint64_t) (uintptr_t) buf->address + c * ALLOC_CHUNK_SIZE
        };
        status = (int) write(xomfd, &cmd, sizeof(cmd));
        if (status < 0)
            return NULL;
        size_left -= ALLOC_CHUNK_SIZE;
        c++;
    }
    buf->locked = 1;
    return buf->address;
}

static void xom_free_internal(struct xombuf *buf) {
    unsigned int c = 0;
    modxom_cmd cmd;
    ssize_t size_left;

    if (!buf)
        return;

    if (buf->xom_mode == XOM_MODE_PKU) {
        munmap(buf->address, SIZE_CEIL(buf->allocated_size));
        free(buf);
        return;
    }

    size_left = buf->allocated_size;
    while (size_left > 0) {
        cmd = (modxom_cmd) {
                .cmd = MODXOM_CMD_FREE,
                .num_pages = SIZE_CEIL(min(size_left, ALLOC_CHUNK_SIZE)) >> PAGE_SHIFT,
                .base_addr = (uint64_t) (uintptr_t) buf->address + c * ALLOC_CHUNK_SIZE
        };
        write(xomfd, &cmd, sizeof(cmd));
        munmap(buf->address, SIZE_CEIL(min(size_left, ALLOC_CHUNK_SIZE)));
        size_left -= ALLOC_CHUNK_SIZE;
        c++;
    }
    free(buf);
}

static struct xom_subpages *xom_alloc_subpages_internal(size_t size) {
    int status;
    modxom_cmd cmd;
    p_xom_subpages ret = NULL;
    p_xombuf xombuf;

    if (size > ALLOC_CHUNK_SIZE)
        return NULL;

    xombuf = xomalloc_page_internal(size);

    if (!xombuf)
        return NULL;

    ret = calloc(1, sizeof(*ret));
    if (!ret) {
        errno = ENOMEM;
        goto exit;
    }

    *ret = (_xom_subpages) {
            .xom_mode = xom_mode,
            .address = xombuf->address,
            .lock_status = calloc((SIZE_CEIL(size) >> PAGE_SHIFT), sizeof(uint32_t)),
            .references = 0,
            .num_subpages = (size / SUBPAGE_SIZE) + (size % SUBPAGE_SIZE ? 1 : 0)
    };

    if (!ret->lock_status) {
        free(ret);
        ret = NULL;
        errno = ENOMEM;
    }

    if (xom_mode == XOM_MODE_SLAT) {
        cmd.cmd = MODXOM_CMD_INIT_SUBPAGES;
        cmd.base_addr = (uint64_t) (uintptr_t) xombuf->address;
        cmd.num_pages = SIZE_CEIL(xombuf->allocated_size) >> PAGE_SHIFT;
        status = (int) write(xomfd, &cmd, sizeof(cmd));
        if (status < 0 && ret) {
            free(ret->lock_status);
            free(ret);
            goto exit;
        }
    } else if (xom_mode == XOM_MODE_PKU) {
        if (subpage_pkey < 0)
            subpage_pkey = pkey_alloc(0, PKEY_DISABLE_ACCESS);
        pkey_mprotect(ret->address, xombuf->allocated_size, PROT_READ | PROT_WRITE | PROT_EXEC, subpage_pkey);
    }

    exit:
    free(xombuf);
    return ret;
}

static void *write_into_subpages(struct xom_subpages *dest, size_t subpages_required, const void *restrict src,
                                 unsigned int base_page, unsigned int base_subpage, uint32_t mask) {
    int status;
    unsigned int i;
    unsigned int pkru;
    xom_subpage_write *write_cmd;

    if (dest->xom_mode == XOM_MODE_SLAT) {
        write_cmd = malloc(sizeof(*write_cmd));

        write_cmd->mxom_cmd = (modxom_cmd) {
                .cmd = MODXOM_CMD_WRITE_SUBPAGES,
                .num_pages = 1,
                .base_addr = (uint64_t) (uintptr_t) (dest->address + base_page * PAGE_SIZE),
        };

        write_cmd->xen_cmd.num_subpages = subpages_required;

        for (i = 0; i < subpages_required; i++) {
            write_cmd->xen_cmd.write_info[i].target_subpage = i + base_subpage;
            memcpy(write_cmd->xen_cmd.write_info[i].data, (char *) src + (i * SUBPAGE_SIZE), SUBPAGE_SIZE);
        }

        status = write(xomfd, write_cmd,
                       sizeof(write_cmd->mxom_cmd) + sizeof(write_cmd->xen_cmd.num_subpages) +
                       subpages_required * sizeof(*write_cmd->xen_cmd.write_info));

        free(write_cmd);

        if (status < 0)
            return NULL;
    } else if (dest->xom_mode == XOM_MODE_PKU) {
        // Transform XOM into WO for filling the subpage, then turn back into XOM
        asm volatile (
                "rdpkru"
                : "=a" (pkru)
                : "c" (0), "d" (0)
                );
        asm volatile(
                "wrpkru"
                ::"a" (pkru & ~(0x3 << (subpage_pkey << 1))), "c" (0), "d"(0)
                );

        memcpy(
                (char *) dest->address + base_page * PAGE_SIZE + base_subpage * SUBPAGE_SIZE,
                src,
                subpages_required * SUBPAGE_SIZE
        );

        asm volatile (
                "wrpkru\n"
                ::"a" (pkru), "c" (0), "d" (0)
                );
    } else
        return NULL;


    dest->lock_status[base_page] |= mask << base_subpage;
    dest->references++;
    return dest->address + base_page * PAGE_SIZE + base_subpage * SUBPAGE_SIZE;
}

static void *xom_fill_and_lock_subpages_internal(struct xom_subpages *dest, size_t size, const void *restrict src) {
    size_t subpages_required = (size / SUBPAGE_SIZE) + (size % SUBPAGE_SIZE ? 1 : 0);
    uint32_t mask;
    unsigned int base_page, base_subpage;

    if (!size || subpages_required > dest->num_subpages || subpages_required > MAX_SUBPAGES_PER_CMD) {
        errno = EINVAL;
        return NULL;
    }

    mask = (uint32_t) ((1 << subpages_required) - 1);

    // Find contigous range of free subpages
    for (base_page = 0; base_page < (dest->num_subpages * SUBPAGE_SIZE) / PAGE_SIZE; base_page++) {
        base_subpage = 0;
        while (base_subpage <= (PAGE_SIZE / SUBPAGE_SIZE) - subpages_required) {
            if (!((mask << base_subpage) & dest->lock_status[base_page]))
                return write_into_subpages(dest, subpages_required, src, base_page, base_subpage, mask);
            base_subpage++;
        }
    }

    // Nothing was found
    errno = -ENOMEM;
    return NULL;
}

static void xom_free_all_subpages_internal(struct xom_subpages *subpages) {
    p_xombuf xbuf = malloc(sizeof(*xbuf));

    if (xbuf) {
        *xbuf = (_xombuf) {
                .address = subpages->address,
                .allocated_size = subpages->num_subpages * SUBPAGE_SIZE,
                .locked = 1,
                .xom_mode = subpages->xom_mode,
        };
        xom_free_internal(xbuf);
    }
    free(subpages->lock_status);
    free(subpages);
}

static int xom_free_subpages_internal(struct xom_subpages *subpages, void *base_address) {
    if (base_address < subpages->address)
        return -1;
    if (base_address >= subpages->address + (subpages->num_subpages * SUBPAGE_SIZE))
        return -1;

    subpages->references--;
    if (subpages->references <= 0) {
        xom_free_all_subpages_internal(subpages);
        return 1;
    }
    return 0;
}

static inline int get_xom_mode_internal() {
    return (int) xom_mode;
}

static int set_xom_mode_internal(const int new_xom_mode) {
    if (new_xom_mode == xom_mode)
        return 0;
    switch (new_xom_mode) {
        case XOM_MODE_SLAT:
            if (xomfd <= 0)
                return -1;
            xom_mode = XOM_MODE_SLAT;
            return 0;
        case XOM_MODE_PKU:
            if (!is_pku_supported())
                return -1;
            xom_mode = XOM_MODE_PKU;
            return 0;
        default:;
    }
    return -1;
}

static int mark_register_clear_internal(struct xombuf *buf, uint8_t full_clear, size_t page_number) {
    modxom_cmd cmd = {
            .cmd = MODXOM_CMD_MARK_REG_CLEAR,
            .base_addr = (uintptr_t) buf->address + (page_number * PAGE_SIZE),
            .num_pages = full_clear ? REG_CLEAR_TYPE_FULL : REG_CLEAR_TYPE_VECTOR
    };

    if (buf->pid != libxom_pid)
        return -EINVAL;

    if (xom_mode != XOM_MODE_SLAT || !buf->locked || buf->marked)
        return -EINVAL;

    if (write(xomfd, &cmd, sizeof(cmd)) < 0)
        return -errno;

    buf->marked = 1;

    return 0;
}


struct xombuf *xom_alloc(size_t size) {
    wrap_call(struct xombuf*, xomalloc_page_internal(size));
}

size_t xom_get_size(const struct xombuf *buf) {
    if (!buf)
        return 0;
    return buf->allocated_size;
}

int xom_write(struct xombuf *dest, const void *const restrict src, const size_t size, const size_t offset) {
    wrap_call(int, xom_write_internal(dest, src, size, offset));
}

void *xom_lock(struct xombuf *buf) {
    wrap_call(void*, xom_lock_internal(buf));
}

void xom_free(struct xombuf *buf) {
    __libxom_prologue();
    xom_free_internal(buf);
    __libxom_epilogue();
}

int xom_mark_register_clear(struct xombuf *buf, uint8_t full_clear, size_t page_number) {
    if (page_number * PAGE_SIZE > buf->allocated_size)
        return -EINVAL;

    wrap_call(int, mark_register_clear_internal(buf, full_clear, page_number));
}

int xom_mark_register_clear_subpage(const struct xom_subpages *subpages, uint8_t full_clear, size_t page_number) {
    struct xombuf buf = {
            .address = subpages->address,
            .allocated_size = (subpages->num_subpages * SUBPAGE_SIZE),
            .locked = ~0
    };
    return xom_mark_register_clear(&buf, full_clear, page_number);
}

#if (defined(__x86_64__) || defined(_M_X64))

int xom_migrate_all_code() {
    wrap_call(int, migrate_all_code_internal());
}

int xom_migrate_shared_libraries() {
    wrap_call(int, migrate_shared_libraries_internal());
}

#else
// Only supported for x64

int xom_migrate_all_code(){
    return -1;
}

int xom_migrate_shared_libraries(){
    return -1;
}
#endif

struct xom_subpages *xom_alloc_subpages(size_t size) {
    wrap_call(p_xom_subpages, xom_alloc_subpages_internal(size))
}

void *xom_fill_and_lock_subpages(struct xom_subpages *dest, size_t size, const void *const src) {
    wrap_call(void*, xom_fill_and_lock_subpages_internal(dest, size, src))
}

int xom_free_subpages(struct xom_subpages *subpages, void *base_address) {
    wrap_call(int, xom_free_subpages_internal(subpages, base_address))
}

void xom_free_all_subpages(struct xom_subpages *subpages) {
    __libxom_prologue();
    xom_free_all_subpages_internal(subpages);
    __libxom_epilogue();
}

int get_xom_mode() {
    wrap_call(int, get_xom_mode_internal());
}

int set_xom_mode(const int new_xom_mode) {
    wrap_call(int, set_xom_mode_internal(new_xom_mode));
}

#if (defined(__x86_64__) || defined(_M_X64))

static inline void install_dlopen_hook(void) {
    dlopen_original = dlsym(RTLD_NEXT, "dlopen");
    if (dlopen_original == dlopen)
        dlopen_original = NULL;
    dlmopen_original = dlsym(RTLD_NEXT, "dlmopen");
    if (dlmopen_original == dlmopen)
        dlmopen_original = NULL;
}

#endif

__attribute__((constructor))
void initialize_libxom(void) {
    char **envp = __environ;
    uintptr_t rval = 0;

    if (initialized)
        return;

    pthread_mutex_init(&lib_lock, NULL);
    initialized = 1;
    pthread_mutex_lock(&lib_lock);

    pthread_mutexattr_init(&full_reg_clear_lock_attr);
    pthread_mutexattr_settype(&full_reg_clear_lock_attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&full_reg_clear_lock, &full_reg_clear_lock_attr);

    xomfd = open(XOM_FILE, O_RDWR);
    if (xomfd >= 0) {
        xom_mode = XOM_MODE_SLAT;
    } else if (is_pku_supported()) {
        xom_mode = XOM_MODE_PKU;
    } else {
        pthread_mutex_unlock(&lib_lock);
        return;
    }

#if (defined(__x86_64__) || defined(_M_X64))
    while (*envp) {
        if (strstr(*envp, LIBXOM_ENVVAR "=" LIBXOM_ENVVAR_LOCK_ALL)) {
            migrate_all_code_internal();
            migrate_dlopen = 1;
            break;
        }
        if (strstr(*envp, LIBXOM_ENVVAR "=" LIBXOM_ENVVAR_LOCK_LIBS)) {
            migrate_shared_libraries_internal();
            migrate_dlopen = 1;
            break;
        }
        envp++;
    }
#endif

    install_dlopen_hook();
    libxom_pid = getpid();

    while (!rval)
        _rdrand32_step((uint32_t *) &rval);

#if (defined(__x86_64__) || defined(_M_X64))
    xom_base_addr = (void *) (XOM_BASE_ADDRESS + ((rval << PAGE_SHIFT) & ~(0xff0000000000)));
#else
    xom_base_addr = (void*) (XOM_BASE_ADDRESS + ((rval << PAGE_SHIFT) & ~(0xff000000ul)));
#endif

    pthread_mutex_unlock(&lib_lock);
}
