#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <sys/mman.h>
#import <fcntl.h>
#include "fishhook.h"

static uint64_t game_base_addr = 0;
static uint64_t game_text_size = 0;
static void* clean_text_backup = NULL;

// 挂钩：mach_vm_read
static kern_return_t (*orig_mach_vm_read)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t my_mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) {
    如果 (clean_text_backup != 空 && 地址 >= 游戏基址 && (地址 + 大小) <= (游戏基址 + 游戏文本大小)) {
        uint64_t offset = address - game_base_addr;
        *data = (vm_offset_t)((uint8_t*)clean_text_backup + offset);
        *dataCnt = size;
        返回 KERN_SUCCESS; 
    }
    返回 orig_mach_vm_read(target_task, address, size, data, dataCnt);
}

// 挂钩：mach_vm_read_overwrite
static kern_return_t (*orig_mach_vm_read_overwrite)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t my_mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize) {
    if (clean_text_backup != NULL && address >= game_base_addr && (address + size) <= (game_base_addr + game_text_size)) {
        uint64_t offset = address - game_base_addr;
        memcpy((void*)data, (uint8_t*)clean_text_backup + offset, size);
        *outsize = size;
        return KERN_SUCCESS;
    }
    return orig_mach_vm_read_overwrite(target_task, address, size, data, outsize);
}

// [核心升级] 0内存占用、瞬间加载的内存欺骗！
void BackupCleanTextSegment() {
    game_base_addr = _dyld_get_image_vmaddr_slide(0) + 0x100000000;
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    
    无符号长整型 text_size = 0;
    uint8_t *text_ptr = getsectiondata(header, "__TEXT", "__text", &text_size);
    
    如果 (text_ptr && text_size > 0) {
        游戏文本大小 = 文本大小;
        const char *image_path = _dyld_get_image_name(0);
        int fd = open(image_path, O_RDONLY);
        if (fd >= 0) {
            struct stat st;
            fstat(fd, &st);
            // 这里是灵魂！将巨大的 __text 段直接映射到虚拟内存（借用硬盘），不吃一丁点真实运行内存(RAM)
            void *file_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (file_map != MAP_FAILED) {
                const struct load_command *cmd = (const struct load_command *)((uint8_t *)header + sizeof(struct mach_header_64));
                对于 (uint32_t i = 0; i < header->ncmds; i++) {
                    如果 (cmd->cmd == LC_SEGMENT_64) {
                        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
                        if (strcmp(seg->segname, "__TEXT") == 0) {
                            结构体 section_64 *sec = (结构体 section_64 *)((uint8_t *)seg + sizeof(结构体 segment_command_64));
                            对于 (uint32_t j = 0; j < seg->nsects; j++) {
                                if (strcmp(sec[j].sectname, "__text") == 0) {
                                    clean_text_backup = (uint8_t *)file_map + sec[j].offset;
                                    break;
                                }
                            }
                        }
                    }
                    cmd = (const struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
                }
            }
        }
    }
}

static const char* (*orig_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* real_name = orig_dyld_get_image_name(image_index);
    if (!real_name) return real_name;
    NSString *nameStr = [NSString stringWithUTF8String:real_name];
]“作弊”] 或 [nameStr 包含字符串：@
        return "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    }
    return real_name;
}

 int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
0NULL && 名称长度 >= 3 && 名称[0] == CTL_KERN && 名称[1] == KERN_PROC && 名称[2] == KERN_PROC_PID) {
        如果 (oldp != NULL) {
            结构体 kinfo_proc *info = (结构体 kinfo_proc *)oldp;
            如果 (info->kp_proc.p_flag & P_TRACED) info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    返回 ret;
}

静态 int (*orig_stat)(const char *path, void *buf);
整型 my_stat(常量 字符指针 *path,  void *buf) {
    if (!path) return orig_stat(path, buf);
    NSString *pathStr = [NSString stringWithUTF8String:path];
"/Applications/Cydia.app""/Library/MobileSubstrate"]) 返回 -
    return orig_stat(path, buf);
}

// 拦截直接强杀指令，防止 Tersafe 引发闪退
static void (*orig_abort)(void);
void my_abort() {
    // 死循环卡住当前危险线程，绝对不让游戏闪退退出
    while(1) { sleep(100); }
}

static void (*orig_exit)(int);
void my_exit(int status) {
    while(1) { sleep(100); }
}


__attribute__((constructor))
static void bypass_init() {
    备份清理文本段();
    struct rebinding rebindings[] = {
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"stat", (void *)my_stat, (void **)&orig_stat},
        {"mach_vm_read", (void *)my_mach_vm_read, (void **)&orig_mach_vm_read},
        {"mach_vm_read_overwrite", (void *)my_mach_vm_read_overwrite, (void **)&orig_mach_vm_read_overwrite},
        {"abort", (void *)my_abort, (void **)&orig_abort},
        {"exit", (void *)my_exit, (void **)&orig_exit}
    };
    rebind_symbols(rebindings, 7);
}
