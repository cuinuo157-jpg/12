#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#include "fishhook.h"

// ==========================================
// 核心：内存完整性欺骗 (Memory Spoofing)
// ==========================================
static uint64_t game_base_addr = 0;
static uint64_t game_text_size = 0;
static void* clean_text_backup = NULL;

// Hook: mach_vm_read
static kern_return_t (*orig_mach_vm_read)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t my_mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) {
    if (clean_text_backup != NULL && address >= game_base_addr && (address + size) <= (game_base_addr + game_text_size)) {
        uint64_t offset = address - game_base_addr;
        *data = (vm_offset_t)((uint8_t*)clean_text_backup + offset);
        *dataCnt = size;
        return KERN_SUCCESS; // 给腾讯返回那份干净的备份内存！
    }
    return orig_mach_vm_read(target_task, address, size, data, dataCnt);
}

// Hook: mach_vm_read_overwrite
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

// 在游戏刚启动时，把纯净代码段藏起来
void BackupCleanTextSegment() {
    game_base_addr = _dyld_get_image_vmaddr_slide(0) + 0x100000000;
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    unsigned long text_size = 0;
    uint8_t *text_ptr = getsectiondata(header, "__TEXT", "__text", &text_size);
    
    if (text_ptr && text_size > 0) {
        game_text_size = text_size;
        clean_text_backup = malloc(text_size);
        memcpy(clean_text_backup, text_ptr, text_size);
        NSLog(@"[AAC] Clean .text segment backed up! (Size: %lu)", text_size);
    }
}

// ==========================================
// 之前的常规防护
// ==========================================

// Hook: _dyld_get_image_name
static const char* (*orig_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* real_name = orig_dyld_get_image_name(image_index);
    if (!real_name) return real_name;
    
    NSString *nameStr = [NSString stringWithUTF8String:real_name];
    if ([nameStr containsString:@"Substrate"] || [nameStr containsString:@"frida"] || [nameStr containsString:@"Cheat"] || [nameStr containsString:@"FullBypass.dylib"]) {
        return "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    }
    return real_name;
}

// 挂钩：sysctl
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
NULL && 名称长度 >= 3 && 名称[0] == CTL_KERN && 名称[1] == KERN_PROC && 名称[
        如果 (oldp != NULL) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            如果 (info->kp_proc.p_flag & P_TRACED) {
                info->kp_proc.p_flag &= ~P_TRACED;
            }
        }
    }
    返回 ret;
}

// 钩子：stat
静态 int (*orig_stat)(const char *path, void *buf);
整型 my_stat(常量 字符指针 *path,  void *buf) {
    if (!path) return orig_stat(path, buf);
    NSString *pathStr = [NSString stringWithUTF8String:path];
    如果 ([pathStr 包含字符串:@"/Applications/Cydia.app"] || [pathStr 包含字符串:@"/Library/MobileSubstrate"]) {
        返回 -1; 
    }
    return orig_stat(path, buf);
}

// ==========================================
// 初始化
// ==========================================
__attribute__((constructor))
static void bypass_init() {
    // 1. 备份纯净代码
    备份清理文本段();
    
    // 2. 挂载所有拦截网
    struct rebinding rebindings[] = {
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"stat", (void *)my_stat, (void **)&orig_stat},
        {"mach_vm_read", (void *)my_mach_vm_read, (void **)&orig_mach_vm_read},
        {"mach_vm_read_overwrite", (void *)my_mach_vm_read_overwrite, (void **)&orig_mach_vm_read_overwrite}
    };
    
    重新绑定符号（rebindings，5);
    
    NSLog(@"[AAC] 高级钩子已成功应用。ACE 现在应该已经失效了。");
}
