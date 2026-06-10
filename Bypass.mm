#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include "fishhook.h"

// ==========================================
// 核心：内存完整性欺骗 (Memory Spoofing) - 延迟初始化终极版
// ==========================================
static uint64_t g_real_text_addr = 0; 
static uint64_t g_text_size = 0;
static void* g_clean_text_backup = NULL;

static _Atomic bool g_backup_ready = false; 

// 延迟初始化函数，确保只执行一次
static void EnsureBackupInitialized() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        intptr_t slide = _dyld_get_image_vmaddr_slide(0);
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
        if (!header) return;
        
        unsigned long text_size = 0;
        uint8_t *text_ptr_unslid = getsectiondata(header, "__TEXT", "__text", &text_size);
        
        if (text_ptr_unslid && text_size > 0) {
            g_real_text_addr = (uint64_t)text_ptr_unslid + slide;
            g_text_size = text_size;
            
            void* temp_backup = malloc(text_size);
            if (temp_backup) {
                memcpy(temp_backup, (void*)g_real_text_addr, text_size);
                g_clean_text_backup = temp_backup;
                atomic_store(&g_backup_ready, true);
                NSLog(@"[AAC] Clean .text backed up (Lazy)! Real Addr: 0x%llx", g_real_text_addr);
            }
        }
    });
}

// Hook: mach_vm_read
static kern_return_t (*orig_mach_vm_read)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t my_mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) {
    if (data == NULL || dataCnt == NULL) {
        return orig_mach_vm_read(target_task, address, size, data, dataCnt);
    }
    
    // 首次触发扫描时，才去进行代码段备份
    EnsureBackupInitialized();
    
    kern_return_t kr = orig_mach_vm_read(target_task, address, size, data, dataCnt);
    if (kr != KERN_SUCCESS) return kr;
    
    if (atomic_load(&g_backup_ready) && size > 0 && address <= ULLONG_MAX - size &&
        address + size > g_real_text_addr && 
        address < g_real_text_addr + g_text_size) {
        
        uint64_t overlap_start = (address > g_real_text_addr) ? address : g_real_text_addr;
        uint64_t overlap_end = ((address + size) < (g_real_text_addr + g_text_size)) ? (address + size) : (g_real_text_addr + g_text_size);
        uint64_t overlap_size = overlap_end - overlap_start;
        
        uint64_t backup_offset = overlap_start - g_real_text_addr;
        uint64_t buffer_offset = overlap_start - address;
        
        memcpy((void*)(*data + buffer_offset), (uint8_t*)g_clean_text_backup + backup_offset, overlap_size);
    }
    return KERN_SUCCESS;
}

// Hook: mach_vm_read_overwrite
static kern_return_t (*orig_mach_vm_read_overwrite)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t my_mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize) {
    if (data == 0 || outsize == NULL) {
        return orig_mach_vm_read_overwrite(target_task, address, size, data, outsize);
    }
    
    EnsureBackupInitialized();
    
    kern_return_t kr = orig_mach_vm_read_overwrite(target_task, address, size, data, outsize);
    if (kr != KERN_SUCCESS) return kr;
    
    if (atomic_load(&g_backup_ready) && size > 0 && address <= ULLONG_MAX - size &&
        address + size > g_real_text_addr && 
        address < g_real_text_addr + g_text_size) {
        
        uint64_t overlap_start = (address > g_real_text_addr) ? address : g_real_text_addr;
        uint64_t overlap_end = ((address + size) < (g_real_text_addr + g_text_size)) ? (address + size) : (g_real_text_addr + g_text_size);
        uint64_t overlap_size = overlap_end - overlap_start;
        
        uint64_t backup_offset = overlap_start - g_real_text_addr;
        uint64_t buffer_offset = overlap_start - address;
        
        memcpy((void*)(data + buffer_offset), (uint8_t*)g_clean_text_backup + backup_offset, overlap_size);
    }
    return KERN_SUCCESS;
}

// ==========================================
// 之前的常规防护
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
    
    if (ret == -1 && errno == EFAULT) {
        return ret;
    }
    
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
    // 延迟初始化：将极其耗时的备份逻辑从高危的 constructor 中移除
    // 改为在第一次需要伪装内存时自动按需加载 (EnsureBackupInitialized)
    
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
