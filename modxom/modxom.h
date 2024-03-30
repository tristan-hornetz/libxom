#ifndef _MODXOM_H_
#define _MODXOM_H_

#ifndef __KERNEL__
#include <stdint.h>
#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12
#endif

#define MODXOM_CMD_NOP              0
#define MODXOM_CMD_FREE             1
#define MODXOM_CMD_LOCK             2
#define MODXOM_CMD_INIT_SUBPAGES    3
#define MODXOM_CMD_WRITE_SUBPAGES   4
#define MODXOM_CMD_GET_SECRET_PAGE  5
#define MODXOM_CMD_MARK_REG_CLEAR   6

#define REG_CLEAR_TYPE_NONE     0
#define REG_CLEAR_TYPE_VECTOR   1
#define REG_CLEAR_TYPE_FULL     2

#ifndef SUBPAGE_SIZE
#define SUBPAGE_SIZE (PAGE_SIZE / (sizeof(uint32_t) << 3))
#endif

#define MAX_SUBPAGES_PER_CMD ((PAGE_SIZE - sizeof(uint8_t)) / (sizeof(xom_subpage_write_info)))

#ifdef __cplusplus
extern "C" {
#endif

struct {
    uint32_t cmd;
    uint32_t num_pages;
    uint64_t base_addr;
} typedef modxom_cmd, *pmodxom_cmd;

struct {
    uint8_t target_subpage;
    uint8_t data[SUBPAGE_SIZE];
} typedef xom_subpage_write_info;

struct {
    uint8_t num_subpages;
    xom_subpage_write_info write_info [MAX_SUBPAGES_PER_CMD];
} typedef xom_subpage_write_command;

struct {
    modxom_cmd mxom_cmd;
    xom_subpage_write_command xen_cmd;
} typedef xom_subpage_write;


#ifdef __cplusplus
}
#endif

#endif