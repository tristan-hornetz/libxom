#include <asm/page.h>
#include <asm/io.h>
#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <xen/xen.h>
#include <asm/xen/hypercall.h>
#include <asm/pgtable_types.h>
#include <asm/pgtable_64.h>
#include "modxom.h"

// #define MODXOM_DEBUG 1

#define MMUEXT_MARK_XOM                         21
#define MMUEXT_UNMARK_XOM                       22
#define MMUEXT_CREATE_XOM_SPAGES                23
#define MMUEXT_WRITE_XOM_SPAGES                 24
#define MMUEXT_MARK_REG_CLEAR                   26

#define READ_HEADER_STRING                      "        Address:             Size:\n"
#define MAPPING_LINE_SIZE                       ((2 * (2 * sizeof(size_t) + 2)) + 5)

#define MIN(X, Y)                               ((X) < (Y) ? (X) : (Y))
#define SIZE_CEIL(S)                            ((((S) >> PAGE_SHIFT) + ((S) & (PAGE_SIZE - 1) ? 1 : 0) ) << PAGE_SHIFT)
#define page_l_arr_index(pmapping, index)       ((pmapping)->lock_status[(index) >> 3])
#define is_page_locked(pmapping, index)         ((page_l_arr_index(pmapping, index) & (1 << ((index) & 0x7))) ? 1 : 0)
#define set_lock_status(pmapping, index, val) \
    page_l_arr_index(pmapping, index) = (page_l_arr_index(pmapping, index) & ~(1 << ((index) & 0x7))) | (((val) ? 1 : 0) << ((index) & 0x7))

struct {
    struct list_head lhead;
    unsigned int num_pages;
    unsigned long uaddr;
    unsigned long kaddr;
    pfn_t pfn;
    uint8_t *lock_status;
    bool subpage_level;
} typedef xom_mapping, *pxom_mapping;

struct {
    struct list_head lhead;
    pid_t pid;
    struct list_head mappings;
    struct list_head locked_in_place;
} typedef xom_process_entry, *pxom_process_entry;

LIST_HEAD(xom_entries);
static struct mutex file_lock;
static uint8_t *modxom_src_operand_page;

static bool were_pages_locked(pxom_mapping mapping) {
    unsigned int i;
    uint8_t ret = 0;

    for (i = 0; i < (mapping->num_pages >> 3) + 1; i++)
        ret |= mapping->lock_status[i];

    return ret > 0;
}

// Add or remove hypervisor protection
static int
xom_invoke_xen(pxom_mapping mapping, unsigned int page_index, unsigned int num_pages, unsigned int mmuext_cmd) {
    int status;
    struct mmuext_op op;
    pfn_t *gfns;
    unsigned int page_c, i, pages_locked = 0;
    unsigned long cur_gfn = mapping->pfn.val, base_gfn = cur_gfn, last_gfn;

    if (!num_pages)
        return 0;
    if (page_index + num_pages > mapping->num_pages)
        return -EINVAL;
    memset(&op, 0, sizeof(op));

    gfns = kvmalloc(sizeof(*gfns) * mapping->num_pages, GFP_KERNEL);
    if (!gfns)
        return -ENOMEM;

    while (pages_locked < num_pages) {
        page_c = 0;

        // Group into physically contiguous ranges
        do {
            page_c++;
            if (page_c + pages_locked >= mapping->num_pages)
                break;
            last_gfn = cur_gfn;
            cur_gfn = virt_to_phys((void *) (mapping->kaddr + (pages_locked + page_c) * PAGE_SIZE)) >> PAGE_SHIFT;
        } while (last_gfn == cur_gfn - 1);

        // Perform Hypercall for range
        op.cmd = mmuext_cmd;
        op.arg1.mfn = base_gfn;
        op.arg2.nr_ents = page_c;
#ifdef MODXOM_DEBUG
        printk(KERN_INFO "[MODXOM] Invoking Hypervisor with mfn 0x%lx for %u pages\n", op.arg1.mfn, op.arg2.nr_ents);
#endif
        status = HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF);
        if (status) {
#ifdef MODXOM_DEBUG
            printk(KERN_INFO "[MODXOM] Failed - Status 0x%x\n", status);
#endif
            status = -EINVAL;
            goto exit;
        }

        // Update lock status in mapping struct
        for (i = 0; i < page_c; i++)
            set_lock_status(mapping, page_index + pages_locked + i, 1);

        base_gfn = cur_gfn;
        pages_locked += page_c;
        // Repeat until all physically contiguous ranges are locked
    }

    exit:
    kvfree(gfns);
    return status;
}

static int release_mapping(pxom_mapping mapping) {
    int status = 0;
    unsigned long i;

    if (were_pages_locked(mapping)) {
        status = xom_invoke_xen(mapping, 0, mapping->num_pages, MMUEXT_UNMARK_XOM);
        if (status)
            return status;
    }

    for (i = 0; i < mapping->num_pages * PAGE_SIZE; i += PAGE_SIZE)
        ClearPageReserved(virt_to_page(mapping->kaddr + i));

    // Don't mess with a dying processes address space
    if (!(current->flags & PF_EXITING)) {
        status = vm_munmap(mapping->uaddr, mapping->num_pages * PAGE_SIZE);
    }

    if (status)
        return status;

    if (mapping->kaddr)
        free_pages(mapping->kaddr, get_order(mapping->num_pages * PAGE_SIZE));

    if (mapping->lock_status) {
        kfree(mapping->lock_status);
        mapping->lock_status = NULL;
    }

    return 0;
}

static pxom_process_entry get_process_entry(void) {
    pxom_process_entry curr_entry = (pxom_process_entry) xom_entries.next;

    while ((void *) curr_entry != &xom_entries && curr_entry) {
        if (curr_entry->pid == current->pid)
            return curr_entry;
        curr_entry = (pxom_process_entry) curr_entry->lhead.next;
    }

#ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] Could not get process entry for PID: %d\n", current->pid);
#endif

    return NULL;
}

static int release_process(pxom_process_entry curr_entry) {
    pxom_mapping last_mapping, curr_mapping;

    if (!curr_entry)
        return -EINVAL;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;

    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        release_mapping(curr_mapping);
        last_mapping = curr_mapping;
        curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
        kfree(last_mapping);
    }
    return 0;
}

static int xmem_free(pmodxom_cmd cmd) {
    int status;
    pxom_process_entry curr_entry;
    pxom_mapping curr_mapping;

    curr_entry = get_process_entry();
    if (!curr_entry)
        return -EBADF;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        if (curr_mapping->uaddr != cmd->base_addr) {
            curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
            continue;
        }

        if (curr_mapping->num_pages != cmd->num_pages)
            return -EINVAL;

        status = release_mapping(curr_mapping);

        if (status)
            return status;
        list_del(&(curr_mapping->lhead));
        kfree(curr_mapping);
        return 0;
    }
    return -EINVAL;
}

static int lock_pages(pmodxom_cmd cmd) {
    unsigned page_index;
    pxom_process_entry curr_entry;
    pxom_mapping curr_mapping;

#ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] lock_pages(base_addr: 0x%lx, num_pages: 0x%u), PID: %d\n", 
        cmd->base_addr, cmd->num_pages, current->pid);
#endif

    curr_entry = get_process_entry();
    if (!curr_entry)
        return -EBADF;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        if (cmd->base_addr < curr_mapping->uaddr ||
            cmd->base_addr >= curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE) {
            curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
            continue;
        }

        if (curr_mapping->subpage_level)
            goto fail;

        if (cmd->base_addr + cmd->num_pages * PAGE_SIZE > curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE)
            goto fail;

        page_index = (cmd->base_addr - curr_mapping->uaddr) / PAGE_SIZE;

        return xom_invoke_xen(curr_mapping, page_index, cmd->num_pages, MMUEXT_MARK_XOM);
    }
    fail:
#ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] lock_pages - Failed!, PID: %d\n", current->pid);
#endif
    return -EINVAL;
}

static int xom_init_subpages(pmodxom_cmd cmd) {
    int status;
    pxom_process_entry curr_entry;
    pxom_mapping curr_mapping;

    curr_entry = get_process_entry();
    if (!curr_entry)
        return -EBADF;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        if (cmd->base_addr < curr_mapping->uaddr ||
            cmd->base_addr >= curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE) {
            curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
            continue;
        }

        if (curr_mapping->subpage_level)
            return -EINVAL;

        if (cmd->base_addr != curr_mapping->uaddr)
            return -EINVAL;

        if (cmd->num_pages != curr_mapping->num_pages)
            return -EINVAL;

        status = xom_invoke_xen(curr_mapping, 0, curr_mapping->num_pages, MMUEXT_CREATE_XOM_SPAGES);
        if (status >= 0)
            curr_mapping->subpage_level = true;

        return status;
    }
    return -EINVAL;
}

static pxom_mapping get_new_mapping(struct vm_area_struct *vma, pxom_process_entry curr_entry) {
    unsigned long size = (vma->vm_end - vma->vm_start);
    void *newmem = NULL;
    uint8_t *n_lock_status = NULL;
    unsigned int i;
    int status;
    pfn_t pfn;
    pxom_mapping new_mapping = NULL;

    if (!curr_entry)
        return NULL;

    // Must be page-aligned
    if (size % PAGE_SIZE || vma->vm_start % PAGE_SIZE || !size) {
        return NULL;
    }

    if (size > (1 << (MAX_ORDER - 1)) << PAGE_SHIFT)
        return NULL;

    new_mapping = kmalloc(sizeof(*new_mapping), GFP_KERNEL);
    if (!new_mapping)
        return NULL;

    n_lock_status = kmalloc(((size / PAGE_SIZE) >> 3) + 1, GFP_KERNEL);
    if (!n_lock_status)
        goto fail;

    memset(n_lock_status, 0, ((size / PAGE_SIZE) >> 3) + 1);

    newmem = (void *) __get_free_pages(GFP_KERNEL, get_order(size));
    if (!newmem || (ssize_t) newmem == -1)
        goto fail;

    // Set PG_reserved bit to prevent swapping
    for (i = 0; i < size; i += PAGE_SIZE)
        SetPageReserved(virt_to_page(newmem + i));

    memset(newmem, 0x0, PAGE_SIZE * (1 << get_order(size)));

    pfn = (pfn_t) {virt_to_phys(newmem) >> PAGE_SHIFT};
    status = remap_pfn_range(vma, vma->vm_start, pfn.val, size, PAGE_SHARED_EXEC);

    if (status < 0)
        goto fail;

    *new_mapping = (xom_mapping) {
            .num_pages = size / PAGE_SIZE,
            .uaddr = vma->vm_start,
            .kaddr = (unsigned long) newmem,
            .subpage_level = false,
            .pfn = pfn,
            .lock_status = n_lock_status
    };

    return new_mapping;

    fail:
    if (curr_entry)
        kfree(curr_entry);
    if (n_lock_status)
        kfree(n_lock_status);
    if (newmem)
        __free_pages(virt_to_page(newmem), get_order(size));
    return NULL;
}

static int manage_mapping_intersection(struct vm_area_struct *vma, pxom_process_entry curr_entry) {
    int status;
    pxom_mapping curr_mapping;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        if (vma->vm_end < curr_mapping->uaddr ||
            vma->vm_start >= curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE) {
            curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
            continue;
        }
        // The new VMA must fully contain the old mapping, we cannot proceed otherwise
        if (curr_mapping->uaddr < vma->vm_start ||
            curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE > vma->vm_end)
            return 1;
        status = release_mapping(curr_mapping);
        if (status)
            return status;
        list_del(&(curr_mapping->lhead));
        kfree(curr_mapping);
        break;
    }
    return 0;
}

static int xom_subpage_write_xen(pmodxom_cmd cmd) {
    int status;
    struct mmuext_op op;
    pxom_process_entry curr_entry;
    pxom_mapping curr_mapping;

    curr_entry = get_process_entry();
    if (!curr_entry)
        return -EBADF;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        if (cmd->base_addr < curr_mapping->uaddr ||
            cmd->base_addr >= curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE) {
            curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
            continue;
        }

        if (!curr_mapping->subpage_level)
            return -EINVAL;

        op.cmd = MMUEXT_WRITE_XOM_SPAGES;
        op.arg1.mfn =
                virt_to_phys((void *) (curr_mapping->kaddr + (cmd->base_addr - curr_mapping->uaddr))) >> PAGE_SHIFT;
        op.arg2.src_mfn = virt_to_phys(modxom_src_operand_page) >> PAGE_SHIFT;
#ifdef MODXOM_DEBUG
        printk(KERN_INFO "[MODXOM] Invoking hypervisor with dest_mfn 0x%lx and src_mfn 0x%lx\n", op.arg1.mfn, op.arg2.src_mfn);
#endif
        status = HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF);
        if (status) {
#ifdef MODXOM_DEBUG
            printk(KERN_INFO "[MODXOM] Failed - Status 0x%x\n", status);
#endif
            return -EINVAL;
        }
        return 0;
    }
    return -EINVAL;
}

static ssize_t xom_write_into_subpages(struct file *f, const char __user *user_mem, size_t len, loff_t *offset){
    ssize_t ret = -EINVAL;
    xom_subpage_write *cmd = NULL;

    if ((uintptr_t)modxom_src_operand_page & (PAGE_SIZE - 1))
        return -EFAULT;

    if(len < sizeof(cmd->mxom_cmd) + sizeof(cmd->xen_cmd.num_subpages))
        return -EINVAL;

    cmd = kvmalloc(len, GFP_KERNEL);
    if(!cmd || !~(uintptr_t)cmd)
        return -ENOMEM;

    if (copy_from_user(cmd, user_mem, len)) {
        ret = -EFAULT;
        goto exit;
    }

    if(cmd->mxom_cmd.cmd != MODXOM_CMD_WRITE_SUBPAGES)
    goto exit;

    if(!cmd->xen_cmd.num_subpages)
    goto exit;

    if( cmd->xen_cmd.num_subpages >
        (len - sizeof(cmd->mxom_cmd) - sizeof(cmd->xen_cmd.num_subpages)) / sizeof(*(cmd->xen_cmd.write_info)))
        goto exit;

    mutex_lock(&file_lock);

    memcpy(modxom_src_operand_page, &cmd->xen_cmd, len - sizeof(cmd->mxom_cmd));
    ret = xom_subpage_write_xen(&cmd->mxom_cmd);

    mutex_unlock(&file_lock);
exit:
    if(cmd)
        kvfree(cmd);
    return ret;
}

// Make sure that base_addr is a XOM page, and then forward call to hypervisor
static int xom_forward_to_hypervisor(uint64_t base_addr, unsigned int mmuext_t_cmd, unsigned int mmuext_t_arg2) {
    unsigned page_index;
    int status;
    struct mmuext_op op;
    pxom_process_entry curr_entry;
    pxom_mapping curr_mapping;

    // Must be page-aligned
    if ((uintptr_t) base_addr & ((1 << PAGE_SHIFT) - 1))
        return -EINVAL;
    curr_entry = get_process_entry();
    if (!curr_entry)
        return -EBADF;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *) curr_mapping != &(curr_entry->mappings)) {
        if (base_addr < curr_mapping->uaddr ||
            base_addr >= curr_mapping->uaddr + curr_mapping->num_pages * PAGE_SIZE) {
            curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
            continue;
        }

        page_index = (base_addr - curr_mapping->uaddr) / PAGE_SIZE;

        op.cmd = mmuext_t_cmd;
        op.arg1.mfn =
                virt_to_phys((void *) (curr_mapping->kaddr + (base_addr - curr_mapping->uaddr))) >> PAGE_SHIFT;
        op.arg2.nr_ents = mmuext_t_arg2;
#ifdef MODXOM_DEBUG
        printk(KERN_INFO "[MODXOM] Invoking mmuext_op with dest_mfn 0x%lx\n", op.arg1.mfn);
#endif
        status = HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF);
        if (status) {
#ifdef MODXOM_DEBUG
            printk(KERN_INFO "[MODXOM] Failed - Status 0x%x\n", status);
#endif
            return -EINVAL;
        }
        return 0;
    }
    return -EINVAL;
}

static int xom_open(struct inode *__attribute__((unused)) _inode, struct file *__attribute__((unused)) _file) {
    pxom_process_entry new_entry;

    mutex_lock(&file_lock);
    if (get_process_entry()) {
        mutex_unlock(&file_lock);
        return -EEXIST;
    }
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    new_entry->pid = current->pid;
    INIT_LIST_HEAD(&(new_entry->mappings));
    list_add(&(new_entry->lhead), &xom_entries);
    mutex_unlock(&file_lock);
    return 0;
}

static int xom_release(struct inode *, struct file *) {
    int status;
    pxom_process_entry curr_entry;

    mutex_lock(&file_lock);
    curr_entry = get_process_entry();
    if (!curr_entry) {
        mutex_unlock(&file_lock);
        return 0;
    }
    status = release_process(curr_entry);
    list_del(&(curr_entry->lhead));
    kfree(curr_entry);
    mutex_unlock(&file_lock);

    return status;
}

static int xom_mmap(struct file *f, struct vm_area_struct *vma) {
    int status = -EBADF;
    pxom_process_entry curr_entry;
    pxom_mapping new_mapping;

#ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] xom_mmap(0x%lx -> 0x%lx, %lu pages), PID: %d\n", 
        vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / PAGE_SIZE, current->pid);
#endif

    if (!xen_hvm_domain())
        return -ENODEV;

    mutex_lock(&file_lock);

    curr_entry = get_process_entry();

    if (!curr_entry)
        goto exit;

    status = manage_mapping_intersection(vma, curr_entry);
    if (status < 0)
        goto exit;

    new_mapping = get_new_mapping(vma, curr_entry);

    if (!new_mapping)
        status = -EINVAL;
    else
        list_add(&(new_mapping->lhead), &(curr_entry->mappings));

exit:
    mutex_unlock(&file_lock);

#ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] xom_mmap returns %d\n", status);
#endif

    return status;
}

static ssize_t xom_read(struct file *f, char __user *user_mem, size_t len, loff_t *offset) {
    ssize_t status = -EBADF;
    size_t len_reqired = sizeof(READ_HEADER_STRING), index, clen;
    char *dstring;
    pxom_process_entry curr_entry;
    pxom_mapping curr_mapping;
    struct vm_area_struct *vma;

    mutex_lock(&file_lock);

    curr_entry = get_process_entry();
    if(!curr_entry)
        goto exit;

    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    while ((void *)curr_mapping != &(curr_entry->mappings)) {
        len_reqired += MAPPING_LINE_SIZE;
        curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
    }

    if (*offset >= len_reqired){
        status = 0;
        goto exit;
    }

    dstring = kvmalloc(len_reqired, GFP_KERNEL);
    if (!dstring){
        status = -ENOMEM;
        goto exit;
    }

    memcpy(dstring, READ_HEADER_STRING, sizeof(READ_HEADER_STRING));
    curr_mapping = (pxom_mapping) curr_entry->mappings.next;
    index = sizeof(READ_HEADER_STRING) - 1;
    while ((void *)curr_mapping != &(curr_entry->mappings) && index < len_reqired) {
        vma = find_vma(current->mm, curr_mapping->uaddr);
        if (!vma) {
            curr_mapping = (pxom_mapping)
            curr_mapping->lhead.next;
            continue;
        }
        index += snprintf(dstring + index, len_reqired - index, "%16lx, %16lx\n",
        vma->vm_start, vma->vm_end - vma->vm_start);
        curr_mapping = (pxom_mapping) curr_mapping->lhead.next;
    }

    clen = MIN(len_reqired - (unsigned long) *offset, len);
    if ( copy_to_user(user_mem, dstring + *offset, clen))
        clen = 0;
    *offset += clen;
    kvfree(dstring);

    status = (ssize_t) clen;
exit:
    mutex_unlock(&file_lock);
    return status;
}

static ssize_t xom_write(struct file *f, const char __user *user_mem, size_t len, loff_t *offset) {
    ssize_t ret = -EINVAL;
    modxom_cmd cmd;

    #ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] xom_write(user_mem: 0x%lx, len: 0x%lx, offset: %llx), PID: %d\n",
        (unsigned long) user_mem, len, *offset, current->pid);
    #endif

    if(len < sizeof(modxom_cmd))
        return -EINVAL;
    if(len > sizeof(modxom_cmd))
        return xom_write_into_subpages(f, user_mem, len, offset);
    if(copy_from_user(&cmd, user_mem, sizeof(cmd)))
        return -EFAULT;

    #ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] CMD: cmd: %s, base_addr: 0x%lx, num_pages: %u\n",
        cmd.cmd == MODXOM_CMD_FREE ? "MODXOM_CMD_FREE" :
        cmd.cmd == MODXOM_CMD_LOCK ? "MODXOM_CMD_LOCK" :
        cmd.cmd == MODXOM_CMD_INIT_SUBPAGES ? "MODXOM_CMD_INIT_SUBPAGES" : "<unknown>",
        cmd.base_addr, cmd.num_pages);
    #endif

    mutex_lock(&file_lock);
    switch(cmd.cmd){
        case MODXOM_CMD_NOP:
            ret = sizeof(cmd);
            break;
        case MODXOM_CMD_FREE:
            ret = xmem_free(&cmd);
            break;
        case MODXOM_CMD_LOCK:
            ret = lock_pages(&cmd);
            break;
        case MODXOM_CMD_INIT_SUBPAGES:
            ret = xom_init_subpages(&cmd);
            break;
        case MODXOM_CMD_MARK_REG_CLEAR:
            ret = xom_forward_to_hypervisor(cmd.base_addr, MMUEXT_MARK_REG_CLEAR, cmd.num_pages);
            break;
        default:;
    }

    mutex_unlock(&file_lock);
    #ifdef MODXOM_DEBUG
    printk(KERN_INFO "[MODXOM] xom_write returns %li\n", ret);
    #endif
    return ret;
}

const static struct proc_ops file_ops = {
        .proc_open = xom_open,
        .proc_release = xom_release,
        .proc_read = xom_read,
        .proc_write = xom_write,
        .proc_mmap = xom_mmap
};

static int __init

modxom_init(void) {
    struct proc_dir_entry *entry;
    mutex_init(&file_lock);
    modxom_src_operand_page = (uint8_t *) __get_free_pages(GFP_KERNEL, get_order(PAGE_SIZE));
    entry = proc_create(MODXOM_PROC_FILE_NAME, 0666, NULL, &file_ops);
    if (xen_hvm_domain())
        printk(KERN_INFO
    "[MODXOM] Initialized\n");
    else
    printk(KERN_INFO
    "[MODXOM] Error: This machine is not a Xen HVM domain, so modxom cannot be used!\n");
    return 0;
}

static void __exit

modxom_exit(void) {
    pxom_process_entry curr_entry = (pxom_process_entry) xom_entries.next, last_entry;
    while ((void *) curr_entry != &xom_entries) {
        release_process(curr_entry);
        last_entry = curr_entry;
        curr_entry = (pxom_process_entry) curr_entry->lhead.next;
        kfree(last_entry);
    }

    remove_proc_entry(MODXOM_PROC_FILE_NAME, NULL);
    free_pages((unsigned long) modxom_src_operand_page, get_order(PAGE_SIZE));
    mutex_destroy(&file_lock);
    printk(KERN_INFO
    "[MODXOM] MODXOM Kernel Module unloaded\n");
}

module_init(modxom_init);
module_exit(modxom_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Tristan Hornetz");