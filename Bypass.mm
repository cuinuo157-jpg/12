#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>
#import <sys/stat.h>

#import "fishhook.h" // 假设你使用 fishhook 进行符号替换

// ==========================================
// 1. 绕过 Dylib 遍历检测 (_dyld_get_image_name)
// ACE 会遍历所有模块，寻找可疑的外挂 dylib
// ==========================================

static const char* (*orig_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* real_name = orig_dyld_get_image_name(image_index);
    if (!real_name) return real_name;
    
    NSString *nameStr = [NSString stringWithUTF8String:real_name];
    
    // 如果遍历到外挂相关的 dylib (或者数字命名的比如 1.dylib, 66532.dylib)
    // 直接返回一个合法的系统库名字，欺骗 ACE 扫描
    if ([nameStr containsString:@"Substrate"] || 
        [nameStr containsString:@"frida"] || 
        [nameStr containsString:@"Cheat"] ||
        [nameStr containsString:@".dylib"] ) // 简单粗暴，你包里那么多数字.dylib都会被伪装
    {
        // 遇到可疑文件，伪装成系统核心库 CoreFoundation
        return "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    }
    
    return real_name;
}

// ==========================================
// 2. 绕过环境检测 (sysctl 防调试和越狱检测)
// ACE 使用 sysctl 检查进程是否被 P_TRACED
// ==========================================

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    
    if (ret == 0 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        // 擦除被调试标志位 (P_TRACED)
        if (info && (info->kp_proc.p_flag & P_TRACED)) {
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

// ==========================================
// 3. 绕过文件越狱/外挂扫描 (stat, access)
// ==========================================

static int (*orig_stat)(const char *restrict path, struct stat *restrict buf);
int my_stat(const char *restrict path, struct stat *restrict buf) {
    NSString *pathStr = [NSString stringWithUTF8String:path];
    NSArray *blacklist = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt"
    ];
    
    for (NSString *blacklisted in blacklist) {
        if ([pathStr containsString:blacklisted]) {
            // 如果 ACE 试图访问越狱文件，假装文件不存在
            return -1; 
        }
    }
    return orig_stat(path, buf);
}

// ==========================================
// 4. 绕过 ACE 的主动汇报 (如果深入分析，可以直接拦截其上报接口)
// 这是一个伪代码示例，假设拦截 NSURLSession 发送请求
// ==========================================
// 这里通常需要对网络层发出的数据包做过滤，特别是目标是腾讯域名的请求

__attribute__((constructor))
static void bypass_init() {
    NSLog(@"[AAC] Anti-AntiCheat Bypass Loaded.");
    
    // 使用 fishhook (或者 Cydia Substrate) 进行 C函数 Hook
    struct rebinding rebindings[] = {
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"stat", (void *)my_stat, (void **)&orig_stat}
    };
    
    // 执行 Hook 替换
    rebind_symbols(rebindings, 3);
    
    NSLog(@"[AAC] Hooks applied successfully. ACE should be blind now.");
}
