#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#include <string.h>
#include <errno.h>
#include "fishhook.h"

// ==========================================
// 内存读取防护：定点致盲 (放弃全量备份)
// ==========================================
static uint64_t g_bypass_base = 0;
static uint64_t g_bypass_size = 0;

// 获取我们自己外挂模块的地址范围
static void InitBypassRange() {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "FullBypass") || strstr(name, "Substrate") || strstr(name, "frida"))) {
            const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            if (header) {
                unsigned long text_size = 0;
                uint8_t *text_ptr = getsectiondata(header, "__TEXT", "__text", &text_size);
                if (text_ptr && text_size > 0) {
                    g_bypass_base = (uint64_t)text_ptr + slide;
                    g_bypass_size = text_size;
                    NSLog(@"[AAC] Found bypass module: 0x%llx, Size: %llu", g_bypass_base, g_bypass_size);
                }
            }
            break;
        }
    }
}

// Hook: mach_vm_read
static kern_return_t (*orig_mach_vm_read)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t my_mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) {
    if (data == NULL || dataCnt == NULL) {
        return orig_mach_vm_read(target_task, address, size, data, dataCnt);
    }
    
    // 如果反作弊试图读取我们外挂所在的内存区域，直接返回一堆 0 (致盲)
    if (g_bypass_base != 0 && address >= g_bypass_base && address < (g_bypass_base + g_bypass_size)) {
        vm_offset_t new_mem;
        kern_return_t kr = vm_allocate(mach_task_self(), &new_mem, size, VM_FLAGS_ANYWHERE);
        if (kr == KERN_SUCCESS) {
            memset((void*)new_mem, 0, size); // 填 0 致盲
            *data = new_mem;
            *dataCnt = size;
            return KERN_SUCCESS;
        }
    }
    
    // 否则，正常放行。不再去干扰系统内核读取那 227MB 的游戏代码
    return orig_mach_vm_read(target_task, address, size, data, dataCnt);
}

// Hook: mach_vm_read_overwrite
static kern_return_t (*orig_mach_vm_read_overwrite)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t my_mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize) {
    if (data == 0 || outsize == NULL) {
        return orig_mach_vm_read_overwrite(target_task, address, size, data, outsize);
    }
    
    // 如果读取的是我们的外挂区域，填 0 致盲
    if (g_bypass_base != 0 && address >= g_bypass_base && address < (g_bypass_base + g_bypass_size)) {
        memset((void*)data, 0, size);
        *outsize = size;
        return KERN_SUCCESS;
    }
    
    return orig_mach_vm_read_overwrite(target_task, address, size, data, outsize);
}

// ==========================================
// 常规防护：拦截文件与模块扫描 (防封核心)
// ==========================================

// Hook: _dyld_get_image_name
static const char* (*orig_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* real_name = orig_dyld_get_image_name(image_index);
    if (!real_name) return real_name;
    
    if (strstr(real_name, "Substrate") || 
        strstr(real_name, "frida") || 
        strstr(real_name, "Cheat") || 
        strstr(real_name, "FullBypass.dylib")) {
        return "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    }
    return real_name;
}

// Hook: sysctl
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && name != NULL && namelen >= 3 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        if (oldp != NULL && oldlenp != NULL && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            if (info->kp_proc.p_flag & P_TRACED) {
                info->kp_proc.p_flag &= ~P_TRACED;
            }
        }
    }
    return ret;
}

// Hook: stat
static int (*orig_stat)(const char *path, void *buf);
int my_stat(const char *path, void *buf) {
    int ret = orig_stat(path, buf);
    if (ret == -1 && errno == EFAULT) return ret;
    
    if (path != NULL) {
        if (strstr(path, "/Applications/Cydia.app") || 
            strstr(path, "/Library/MobileSubstrate") ||
            strstr(path, "FullBypass.dylib")) {
            errno = ENOENT; 
            return -1; 
        }
    }
    return ret;
}

// ==========================================
// 初始化
// ==========================================
__attribute__((constructor))
static void bypass_init() {
    // 初始化时仅获取我们外挂自身的地址，只有几十 KB，瞬间完成，极其安全
    InitBypassRange();
    
    struct rebinding rebindings[] = {
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"stat", (void *)my_stat, (void **)&orig_stat},
        {"mach_vm_read", (void *)my_mach_vm_read, (void **)&orig_mach_vm_read},
        {"mach_vm_read_overwrite", (void *)my_mach_vm_read_overwrite, (void **)&orig_mach_vm_read_overwrite}
    };
    
    rebind_symbols(rebindings, 5);
    NSLog(@"[AAC] Advanced Hooks applied successfully. ACE should be blind now.");
}
