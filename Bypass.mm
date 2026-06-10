#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#include "fishhook.h"

// 1. Hook _dyld_get_image_name
static const char* (*orig_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* real_name = orig_dyld_get_image_name(image_index);
    if (!real_name) return real_name;
    
    NSString *nameStr = [NSString stringWithUTF8String:real_name];
    if ([nameStr containsString:@"Substrate"] || 
        [nameStr containsString:@"frida"] || 
        [nameStr containsString:@"Cheat"] ||
        [nameStr containsString:@".dylib"] ) 
    {
        return "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    }
    return real_name;
}

// 2. Hook sysctl
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    
    // 抹除调试标志位
    if (ret == 0 && name != NULL && namelen >= 3) {
        if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
            if (oldp != NULL) {
                struct kinfo_proc *info = (struct kinfo_proc *)oldp;
                if (info->kp_proc.p_flag & P_TRACED) {
                    info->kp_proc.p_flag &= ~P_TRACED;
                }
            }
        }
    }
    return ret;
}

// 3. Hook stat
static int (*orig_stat)(const char *path, void *buf);
int my_stat(const char *path, void *buf) {
    if (!path) return orig_stat(path, buf);
    
    NSString *pathStr = [NSString stringWithUTF8String:path];
    NSArray *blacklist = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate"
    ];
    
    for (NSString *blacklisted in blacklist) {
        if ([pathStr containsString:blacklisted]) {
            return -1; 
        }
    }
    return orig_stat(path, buf);
}

// 初始化入口
__attribute__((constructor))
static void bypass_init() {
    struct rebinding rebindings[] = {
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"stat", (void *)my_stat, (void **)&orig_stat}
    };
    
    rebind_symbols(rebindings, 3);
}
