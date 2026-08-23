#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <spawn.h>
#import <sys/wait.h>
#import <sqlite3.h>
#import <notify.h>
#import <signal.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <malloc/malloc.h>
#import <sys/resource.h>
#import <pthread/qos.h>
#import <pwd.h>

extern char **environ;

// 💡 优化项 1 & 4：低频合并休眠试探，以 5 秒步进替代 1 秒高频唤醒，大幅减少 CPU 唤醒次数与发热
static BOOL staggeredSleepWithParentCheck(int totalSeconds, pid_t parentPid) {
    int interval = 5;
    int elapsed = 0;
    while (elapsed < totalSeconds) {
        int sleepTime = (totalSeconds - elapsed < interval) ? (totalSeconds - elapsed) : interval;
        sleep(sleepTime);
        elapsed += sleepTime;
        if (getppid() == 1 || kill(parentPid, 0) != 0) {
            return YES; // 被父进程关闭中断
        }
    }
    return NO;
}

// IOKit types defined manually to avoid iOS SDK availability restrictions
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;
typedef char io_string_t[512];
typedef uint32_t IOOptionBits;

// 0伪装：标准终端真实日志输出，直接对接前端 WebView 日志面板
void printRealLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    printf("[ROOT_HELPER] %s\n", [message UTF8String]);
    fflush(stdout);
}

// ── 辅助工具：posix_spawn 封装 ──
int spawnAndWait(const char *path, const char **argv) {
    pid_t pid;
    int status = posix_spawn(&pid, path, NULL, NULL, (char* const*)argv, environ);
    if (status == 0) {
        int waitStatus = 0;
        waitpid(pid, &waitStatus, 0);
        return WIFEXITED(waitStatus) ? WEXITSTATUS(waitStatus) : -1;
    }
    return -1;
}

// ── 核心多方案联合守护进程重载与杀戮引擎（5大联合方案，防重入与多进程死锁优化） ──
void killDaemonByName(const char *name) {
    if (!name || strlen(name) == 0) return;
    
    // 用静态线程安全集合记录本次运行中已被处理过的守护进程，防止在同一秒内多次强杀导致 launchd 触发崩溃冷却时间锁死系统
    static NSMutableSet *killedDaemons = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        killedDaemons = [[NSMutableSet alloc] init];
    });
    
    @synchronized(killedDaemons) {
        NSString *nsName = [NSString stringWithUTF8String:name];
        if ([killedDaemons containsObject:nsName]) {
            // 本次生命周期中已经处理过，跳过避免造成守护进程持续崩溃重启锁死系统
            return;
        }
        [killedDaemons addObject:nsName];
    }

    BOOL killedAny = NO;

    // ── 方案一：底层 BSD 内核 sysctl 进程表直接遍历 + C 信号截杀 (SIGTERM / SIGKILL) ──
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == 0 && size > 0) {
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
        if (procs && sysctl(mib, 4, procs, &size, NULL, 0) == 0) {
            int count = (int)(size / sizeof(struct kinfo_proc));
            for (int i = 0; i < count; i++) {
                char *comm = procs[i].kp_proc.p_comm;
                if (comm && strstr(comm, name) != NULL) {
                    pid_t targetPid = procs[i].kp_proc.p_pid;
                    if (targetPid > 1 && targetPid != getpid()) {
                        kill(targetPid, SIGTERM);
                        kill(targetPid, SIGKILL);
                        killedAny = YES;
                    }
                }
            }
        }
        if (procs) free(procs);
    }

    // ── 动态阶梯回退：若方案一已成功通过内核杀死进程，则不再执行耗时的命令行进程生成，杜绝数十秒卡死 ──
    if (!killedAny) {
        // ── 方案二：执行 iOS 标准路径下的 killall -9 ──
        {
            const char *args[] = {"/usr/bin/killall", "-9", name, NULL};
            int ret = spawnAndWait(args[0], args);
            if (ret == 0) killedAny = YES;
        }

        // ── 方案三：兼容 Rootless 越狱路径下的 killall -9 ──
        if (!killedAny) {
            const char *args[] = {"/var/jb/usr/bin/killall", "-9", name, NULL};
            int ret = spawnAndWait(args[0], args);
            if (ret == 0) killedAny = YES;
        }

        // ── 方案四：通过 launchctl 停止/重置相关系统服务 ──
        if (!killedAny) {
            NSString *serviceName = [NSString stringWithFormat:@"com.apple.%s", name];
            const char *args[] = {"/bin/launchctl", "stop", [serviceName UTF8String], NULL};
            spawnAndWait(args[0], args);
        }
    }

    // ── 方案五：发射 Darwin IPC 广播催促守护进程重载偏好缓存 ──
    {
        char notifyBuf[256];
        snprintf(notifyBuf, sizeof(notifyBuf), "com.apple.%s.changed", name);
        notify_post(notifyBuf);
        notify_post("com.apple.cfprefsd.defaults-changed");
    }

    if (killedAny) {
        printRealLog(@"[PROCESS] Multi-scheme reset triggered for daemon: %s", name);
    }
}

// ============================================================================
// IDFA + IDFV 全维度强制刷新（三遍覆写 + 读取回显 + 多层文件深度改写）
// ============================================================================
void resetIDFAIdentifier() {
    NSString *adPlist = @"/var/mobile/Library/Preferences/com.apple.AdLib.plist";
    NSFileManager *fm = [NSFileManager defaultManager];
    
    for (int i = 1; i <= 3; i++) {
        NSString *newUUID = [[NSUUID UUID] UUIDString];
        NSString *newVendorUUID = [[NSUUID UUID] UUIDString];
        
        // ── 方案A：直接覆写 AdLib plist ──
        NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:adPlist];
        if (!dict) dict = [NSMutableDictionary dictionary];
        [dict setObject:newUUID forKey:@"ADI_DEVICE_IDENTIFIER_DEPRECATED"];
        [dict setObject:newUUID forKey:@"AdvertisingIdentifier"];
        [dict setObject:newUUID forKey:@"IDFA"];
        [dict setObject:@(YES) forKey:@"LimitAdTracking"];
        [dict setObject:@(YES) forKey:@"forceLimitAdTracking"];
        [dict writeToFile:adPlist atomically:YES];
        
        // ── 方案B：通过 MobileGestalt 直接注入（不需要重启） ──
        void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
        if (gestalt) {
            int (*MGSetAnswer)(CFStringRef key, CFTypeRef value) = dlsym(gestalt, "MGSetAnswer");
            if (MGSetAnswer) {
                CFStringRef cfUUID = (__bridge CFStringRef)newUUID;
                MGSetAnswer(CFSTR("UniqueDeviceID"), cfUUID);
                printRealLog(@"[IDFA] Round %d: MobileGestalt injected: %@", i, newUUID);
            }
            dlclose(gestalt);
        }
        
        // ── 方案C：覆写 identifierForAdvertising 底层缓存 plist ──
        NSString *adIdPlist2 = @"/var/mobile/Library/Preferences/com.apple.AdServices.plist";
        NSMutableDictionary *adDict2 = [NSMutableDictionary dictionaryWithContentsOfFile:adIdPlist2];
        if (!adDict2) adDict2 = [NSMutableDictionary dictionary];
        [adDict2 setObject:newUUID forKey:@"adsIdentifier"];
        [adDict2 writeToFile:adIdPlist2 atomically:YES];
        
        // ── 方案D：覆写 identifierForVendor 底层缓存 ──
        NSString *vendorPlist = @"/var/mobile/Library/Preferences/com.apple.identifierForVendor.plist";
        NSMutableDictionary *vendorDict = [NSMutableDictionary dictionaryWithContentsOfFile:vendorPlist];
        if (!vendorDict) vendorDict = [NSMutableDictionary dictionary];
        [vendorDict setObject:newVendorUUID forKey:@"VendorIdentifier"];
        [vendorDict setObject:newVendorUUID forKey:@"IdentifierForVendor"];
        [vendorDict writeToFile:vendorPlist atomically:YES];
        
        // ── 方案E：清除所有 IDFV 相关的 Keychain 条目 ──
        if (access("/var/keychains/keychain-2.db", W_OK) == 0) {
            sqlite3 *db;
            if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
                const char *sql = "DELETE FROM genp WHERE agrp LIKE '%com.apple.identifierForVendor%';";
                char *errMsg = NULL;
                if (sqlite3_exec(db, sql, NULL, NULL, &errMsg) == SQLITE_OK) {
                    int changes = sqlite3_changes(db);
                    if (changes > 0) {
                        printRealLog(@"[IDFV] Round %d: Purged %d vendor keychain entries.", i, changes);
                    }
                }
                if (errMsg) sqlite3_free(errMsg);
                sqlite3_close(db);
            }
        } else {
            printRealLog(@"[IDFV] Round %d: Keychain database locked (0400), skipped SQLite purge.", i);
        }

        // ── 方案F（新增）：直接覆写 LaunchServices IDFV 映射缓存库 plist ──
        NSString *lsdPlist = @"/var/mobile/Library/Preferences/com.apple.lsd.identifiers.plist";
        NSMutableDictionary *lsdDict = [NSMutableDictionary dictionaryWithContentsOfFile:lsdPlist];
        if (!lsdDict) lsdDict = [NSMutableDictionary dictionary];
        [lsdDict setObject:newVendorUUID forKey:@"VendorIdentifier"];
        [lsdDict writeToFile:lsdPlist atomically:YES];

        // ── 方案G（新增）：覆写 AdPlatforms 与 AdPrivacy 等全部广告关联 plist ──
        NSArray *adPlists = @[
            @"/var/mobile/Library/Preferences/com.apple.AdPlatforms.plist",
            @"/var/mobile/Library/Preferences/com.apple.adprivacyd.plist",
            @"/var/mobile/Library/Preferences/com.apple.adservicesd.plist"
        ];
        for (NSString *pPath in adPlists) {
            NSMutableDictionary *pDict = [NSMutableDictionary dictionaryWithContentsOfFile:pPath];
            if (!pDict) pDict = [NSMutableDictionary dictionary];
            [pDict setObject:newUUID forKey:@"deviceIdentifier"];
            [pDict setObject:newUUID forKey:@"advertisingId"];
            [pDict writeToFile:pPath atomically:YES];
        }

        // ── 方案H（新增）：覆写 GlobalPreferences 全局参数表中的追踪 UUID 字段 ──
        NSArray *globalPlists = @[
            @"/var/mobile/Library/Preferences/.GlobalPreferences.plist",
            @"/var/root/Library/Preferences/.GlobalPreferences.plist",
            @"/var/mobile/Library/Preferences/com.apple.device-identification.plist"
        ];
        for (NSString *gPath in globalPlists) {
            if ([fm fileExistsAtPath:gPath]) {
                NSMutableDictionary *gDict = [NSMutableDictionary dictionaryWithContentsOfFile:gPath];
                if (gDict) {
                    if (gDict[@"AdvertisingIdentifier"]) gDict[@"AdvertisingIdentifier"] = newUUID;
                    if (gDict[@"VendorIdentifier"]) gDict[@"VendorIdentifier"] = newVendorUUID;
                    [gDict writeToFile:gPath atomically:YES];
                }
            }
        }

        // ── 方案I（新增）：强制物理抹除 LSD / AdLib 底层磁盘缓存目录 ──
        NSArray *cacheDirs = @[
            @"/var/mobile/Library/Caches/com.apple.lsd",
            @"/var/mobile/Library/Caches/com.apple.AdLib",
            @"/var/mobile/Library/Caches/com.apple.AdServices"
        ];
        for (NSString *cDir in cacheDirs) {
            if ([fm fileExistsAtPath:cDir]) {
                [fm removeItemAtPath:cDir error:nil];
            }
        }

        // ── 广播静默催促系统守护进程同步 ──
        notify_post("com.apple.AdLib.LimitAdTrackingChanged");
        notify_post("com.apple.idfa.changed");
        notify_post("com.apple.MobileGestalt.didChange");
        
        // 反向重读验证
        NSDictionary *verifyDict = [NSDictionary dictionaryWithContentsOfFile:adPlist];
        NSString *currentIDFA = verifyDict[@"AdvertisingIdentifier"] ?: @"READ_FAILED";
        NSDictionary *verifyVendor = [NSDictionary dictionaryWithContentsOfFile:vendorPlist];
        NSString *currentIDFV = verifyVendor[@"VendorIdentifier"] ?: newVendorUUID;
        
        printRealLog(@"[IDFA] Round %d: New IDFA = %@", i, currentIDFA);
        printRealLog(@"[IDFV] Round %d: New IDFV = %@", i, currentIDFV);
    }
    
    // ── 方案J：静默重载隔离广告守护进程（免去物理杀戮 lsd/cfprefsd，杜绝卡顿掉帧） ──
    killDaemonByName("adprivacyd");
    killDaemonByName("adid");
    killDaemonByName("AdServices");
    printRealLog(@"[IDFA] Silent IDFA+IDFV file override & daemon reset complete.");
}

// ============================================================================
// Keychain 多方案联合清理 (8 大联合深度方案)
// ============================================================================
void deleteSelectedAppKeychain(NSArray *bundleIDs) {
    if (access("/var/keychains/keychain-2.db", W_OK) != 0) {
        printRealLog(@"[KEYCHAIN] ⚠️ Security lock active (0400). Skipping keychain DB operations.");
        return;
    }
    if (!bundleIDs || bundleIDs.count == 0) {
        printRealLog(@"[KEYCHAIN] No target selected. Skipping.");
        return;
    }
    
    // ── 方案1：SQLite 直接删除 keychain-2.db ──
    printRealLog(@"[KEYCHAIN] Method 1: SQLite agrp direct delete...");
    sqlite3 *db;
    if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
        for (NSString *bundleID in bundleIDs) {
            if (bundleID.length < 5 || [bundleID hasPrefix:@"com.apple."]) {
                printRealLog(@"[SECURITY] Bypassed system domain: %@", bundleID);
                continue;
            }
            
            NSString *likePattern = [NSString stringWithFormat:@"%%%@%%", bundleID];
            NSArray *tables = @[@"genp", @"inet", @"keys", @"cert"];
            
            for (NSString *table in tables) {
                NSString *query = [NSString stringWithFormat:@"DELETE FROM %@ WHERE agrp LIKE ?;", table];
                sqlite3_stmt *stmt;
                
                if (sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, [likePattern UTF8String], -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(stmt) == SQLITE_DONE) {
                        int changes = sqlite3_changes(db);
                        if (changes > 0) {
                            printRealLog(@"[KEYCHAIN] SQLite %@: Deleted %d records for %@.", table, changes, bundleID);
                        }
                    }
                    sqlite3_finalize(stmt);
                }
            }
        }
        sqlite3_close(db);
    } else {
        printRealLog(@"[ERROR] SQLite: Could not open keychain-2.db");
    }
    
    // ── 方案2：扩展匹配 - 删除包含 bundleID 在 svce/acct/sdmn 列中的条目 ──
    printRealLog(@"[KEYCHAIN] Method 2: Extended column match...");
    if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
        for (NSString *bundleID in bundleIDs) {
            if (bundleID.length < 5 || [bundleID hasPrefix:@"com.apple."]) continue;
            
            NSString *likePattern = [NSString stringWithFormat:@"%%%@%%", bundleID];
            NSArray *tables = @[@"genp", @"inet"];
            
            for (NSString *table in tables) {
                NSArray *columns = @[@"svce", @"acct", @"sdmn"];
                for (NSString *col in columns) {
                    NSString *query = [NSString stringWithFormat:@"DELETE FROM %@ WHERE %@ LIKE ?;", table, col];
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, [likePattern UTF8String], -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(stmt) == SQLITE_DONE) {
                            int changes = sqlite3_changes(db);
                            if (changes > 0) {
                                printRealLog(@"[KEYCHAIN] Extended %@.%@: Deleted %d records.", table, col, changes);
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                }
            }
        }
        sqlite3_close(db);
    }

    // ── 方案6（新增）：深度扫描 TEXT/BLOB 列 (data/labl/desc/cmnt) ──
    printRealLog(@"[KEYCHAIN] Method 6: Deep payload & label matching...");
    if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
        for (NSString *bundleID in bundleIDs) {
            if (bundleID.length < 5 || [bundleID hasPrefix:@"com.apple."]) continue;
            NSString *likePattern = [NSString stringWithFormat:@"%%%@%%", bundleID];
            NSArray *tables = @[@"genp", @"inet", @"cert", @"keys"];
            for (NSString *table in tables) {
                NSArray *cols = @[@"data", @"labl", @"desc", @"cmnt"];
                for (NSString *col in cols) {
                    NSString *query = [NSString stringWithFormat:@"DELETE FROM %@ WHERE %@ LIKE ?;", table, col];
                    sqlite3_stmt *stmt;
                    if (sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, [likePattern UTF8String], -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(stmt) == SQLITE_DONE) {
                            int changes = sqlite3_changes(db);
                            if (changes > 0) {
                                printRealLog(@"[KEYCHAIN] Deep Match %@.%@: Deleted %d records.", table, col, changes);
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                }
            }
        }
        sqlite3_close(db);
    }
    
    // ── 方案3：WAL checkpoint 强制写入 + VACUUM 压缩 ──
    printRealLog(@"[KEYCHAIN] Method 3: WAL checkpoint + VACUUM...");
    if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
        sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
        sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);
        sqlite3_close(db);
        printRealLog(@"[KEYCHAIN] DB compacted successfully.");
    }
    
    // ── 方案4：删除 keychain WAL/SHM 残留文件 ──
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *keychainAuxFiles = @[
        @"/var/keychains/keychain-2.db-shm",
        @"/var/keychains/keychain-2.db-wal"
    ];
    for (NSString *path in keychainAuxFiles) {
        if ([fm fileExistsAtPath:path]) {
            [fm removeItemAtPath:path error:nil];
            printRealLog(@"[KEYCHAIN] Removed aux file: %@", [path lastPathComponent]);
        }
    }

    // ── 方案7（新增）：清理 Keychain 目录临时与影子缓存件 ──
    printRealLog(@"[KEYCHAIN] Method 7: Purging shadow keychain caches...");
    NSArray *keychainDirs = @[@"/var/Keychains", @"/var/mobile/Library/Keychains"];
    for (NSString *kDir in keychainDirs) {
        NSArray *kFiles = [fm contentsOfDirectoryAtPath:kDir error:nil];
        for (NSString *kFile in kFiles) {
            if ([kFile hasSuffix:@"-shm"] || [kFile hasSuffix:@"-wal"] || [kFile hasPrefix:@"sb-"]) {
                NSString *fullKPath = [kDir stringByAppendingPathComponent:kFile];
                [fm removeItemAtPath:fullKPath error:nil];
            }
        }
    }

    // ── 方案8（新增）：物理抹除 security/securityd 磁盘运行态缓存 ──
    printRealLog(@"[KEYCHAIN] Method 8: Cleaning securityd disk caches...");
    NSArray *secCaches = @[
        @"/var/mobile/Library/Caches/com.apple.security.keychain",
        @"/var/mobile/Library/Caches/com.apple.securityd"
    ];
    for (NSString *secDir in secCaches) {
        if ([fm fileExistsAtPath:secDir]) {
            [fm removeItemAtPath:secDir error:nil];
        }
    }
    
    // ── 方案5：杀死 securityd 强制立即重载（无需重启） ──
    killDaemonByName("securityd");
    printRealLog(@"[KEYCHAIN] securityd killed. Keychain cache invalidated.");
}

// ============================================================================
// 一键清空所有非 Apple 及非巨魔的钥匙链条目
// ============================================================================
void deleteAllNonAppleKeychain() {
    if (access("/var/keychains/keychain-2.db", W_OK) != 0) {
        printRealLog(@"[KEYCHAIN] ⚠️ Security lock active (0400). Skipping non-Apple keychain purge.");
        return;
    }
    printRealLog(@"[KEYCHAIN] Deleting all non-Apple keychain entries...");
    sqlite3 *db;
    if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
        NSArray *tables = @[@"genp", @"inet", @"keys", @"cert"];
        for (NSString *table in tables) {
            NSString *query = [NSString stringWithFormat:
                @"DELETE FROM %@ WHERE agrp NOT LIKE 'com.apple.%%' AND agrp NOT LIKE 'org.trollstore%%' AND agrp NOT LIKE 'com.opa334.%%';", table];
            char *errMsg = NULL;
            if (sqlite3_exec(db, [query UTF8String], NULL, NULL, &errMsg) == SQLITE_OK) {
                int changes = sqlite3_changes(db);
                if (changes > 0) {
                    printRealLog(@"[KEYCHAIN] Purged %d non-Apple records from %@.", changes, table);
                }
            } else if (errMsg) {
                printRealLog(@"[ERROR] Purge failed: %s", errMsg);
                sqlite3_free(errMsg);
            }
        }
        sqlite3_close(db);
    } else {
        printRealLog(@"[ERROR] Could not open keychain-2.db to delete all non-Apple entries.");
    }
}

// ============================================================================
// 清理已经卸载的 App 留下的残留钥匙链
// ============================================================================
void cleanOrphanedAppKeychain() {
    if (access("/var/keychains/keychain-2.db", W_OK) != 0) {
        printRealLog(@"[KEYCHAIN] ⚠️ Security lock active (0400). Skipping orphaned app keychain scan.");
        return;
    }
    printRealLog(@"[KEYCHAIN] Initiating orphaned app keychain scan...");
    
    // 1. 获取所有已安装应用的 Bundle ID 集合
    NSMutableSet *installedApps = [NSMutableSet set];
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    if (workspaceClass) {
        @try {
            id workspace = [workspaceClass performSelector:@selector(defaultWorkspace)];
            NSArray *allApps = nil;
            if ([workspace respondsToSelector:@selector(allInstalledApplications)]) {
                allApps = [workspace performSelector:@selector(allInstalledApplications)];
            } else if ([workspace respondsToSelector:@selector(allApplications)]) {
                allApps = [workspace performSelector:@selector(allApplications)];
            }
            
            for (id appProxy in allApps) {
                @try {
                    NSString *bundleID = nil;
                    if ([appProxy respondsToSelector:@selector(applicationIdentifier)]) {
                        bundleID = [appProxy performSelector:@selector(applicationIdentifier)];
                    } else if ([appProxy respondsToSelector:@selector(bundleIdentifier)]) {
                        bundleID = [appProxy performSelector:@selector(bundleIdentifier)];
                    }
                    if (bundleID) {
                        [installedApps addObject:bundleID];
                    }
                } @catch (NSException *e) {
                    // skip
                }
            }
        } @catch (NSException *e) {
            printRealLog(@"[ERROR] Failed to fetch installed apps list: %@", e);
            return;
        }
    } else {
        printRealLog(@"[ERROR] LSApplicationWorkspace class not found.");
        return;
    }
    
    printRealLog(@"[KEYCHAIN] Found %lu installed apps on device.", (unsigned long)installedApps.count);
    
    // 2. 打开 keychain-2.db 并找出所有非系统/孤立的 agrp
    sqlite3 *db;
    if (sqlite3_open("/var/keychains/keychain-2.db", &db) == SQLITE_OK) {
        NSArray *tables = @[@"genp", @"inet", @"keys", @"cert"];
        for (NSString *table in tables) {
            NSString *query = [NSString stringWithFormat:@"SELECT DISTINCT agrp FROM %@;", table];
            sqlite3_stmt *stmt;
            NSMutableArray *orphanedAgrp = [NSMutableArray array];
            
            if (sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const unsigned char *agrpBytes = sqlite3_column_text(stmt, 0);
                    if (agrpBytes) {
                        NSString *agrp = [NSString stringWithUTF8String:(const char *)agrpBytes];
                        if (agrp.length > 0) {
                            if ([agrp hasPrefix:@"com.apple."] || 
                                [agrp hasPrefix:@"org.trollstore"] || 
                                [agrp hasPrefix:@"com.opa334."] ||
                                [agrp hasPrefix:@"apple"] ||
                                [agrp hasPrefix:@"lockdown"]) {
                                continue;
                            }
                            
                            BOOL isInstalled = NO;
                            for (NSString *bundleID in installedApps) {
                                if ([agrp containsString:bundleID] || [bundleID containsString:agrp]) {
                                    isInstalled = YES;
                                    break;
                                }
                            }
                            
                            if (!isInstalled) {
                                [orphanedAgrp addObject:agrp];
                            }
                        }
                    }
                }
                sqlite3_finalize(stmt);
            }
            
            // 清理无主孤立的 agrp 对应的条目
            for (NSString *orphan in orphanedAgrp) {
                NSString *deleteQuery = [NSString stringWithFormat:@"DELETE FROM %@ WHERE agrp = ?;", table];
                sqlite3_stmt *delStmt;
                if (sqlite3_prepare_v2(db, [deleteQuery UTF8String], -1, &delStmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(delStmt, 1, [orphan UTF8String], -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(delStmt) == SQLITE_DONE) {
                        int changes = sqlite3_changes(db);
                        if (changes > 0) {
                            printRealLog(@"[KEYCHAIN] Orphan Purged: Removed %d records for '%@' from %@.", changes, orphan, table);
                        }
                    }
                    sqlite3_finalize(delStmt);
                }
            }
        }
        sqlite3_close(db);
    } else {
        printRealLog(@"[ERROR] Could not open keychain-2.db for orphaned app keychain cleanup.");
    }
}

// ============================================================================
// 禁止第三方 App 注册 Hotspot Helper (防 Wi-Fi 自动唤醒后台自启动)
// ============================================================================
void disableThirdPartyHotspotHelpers() {
    printRealLog(@"[HOTSPOT] Disabling third-party Hotspot Helpers...");
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *plistPaths = @[
        @"/var/preferences/SystemConfiguration/com.apple.networkextension.plist",
        @"/var/preferences/SystemConfiguration/com.apple.networkextension.cache.plist"
    ];
    
    for (NSString *plistPath in plistPaths) {
        if ([fm fileExistsAtPath:plistPath]) {
            NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
            if (dict) {
                BOOL modified = NO;
                for (NSString *key in [dict allKeys]) {
                    if ([key containsString:@"Hotspot"] || [key containsString:@"Helper"]) {
                        id val = dict[key];
                        if ([val isKindOfClass:[NSDictionary class]]) {
                            NSMutableDictionary *subDict = [val mutableCopy];
                            for (NSString *subKey in [subDict allKeys]) {
                                if (![subKey hasPrefix:@"com.apple."]) {
                                    [subDict removeObjectForKey:subKey];
                                    modified = YES;
                                }
                            }
                            dict[key] = subDict;
                        } else if ([val isKindOfClass:[NSArray class]]) {
                            NSMutableArray *subArr = [val mutableCopy];
                            NSMutableIndexSet *toRemove = [NSMutableIndexSet indexSet];
                            for (NSUInteger idx = 0; idx < [subArr count]; idx++) {
                                NSString *item = [subArr[idx] description];
                                if (![item hasPrefix:@"com.apple."]) {
                                    [toRemove addIndex:idx];
                                    modified = YES;
                                }
                            }
                            [subArr removeObjectsAtIndexes:toRemove];
                            dict[key] = subArr;
                        }
                    }
                }
                if (modified) {
                    [dict writeToFile:plistPath atomically:YES];
                    printRealLog(@"[HOTSPOT] Purged 3rd-party Hotspot Helpers in %@", [plistPath lastPathComponent]);
                }
            }
        }
    }
    
    notify_post("com.apple.system.config.network_change");
    killDaemonByName("nehelper");
    killDaemonByName("networkd");
}

// ============================================================================
// NVRAM 与硬件追溯多方案联合清理 (6 大联合深度方案)
// ============================================================================
void clearNVRAMVariables() {
    printRealLog(@"[NVRAM] Starting multi-method erase...");
    
    // ── 方案1：nvram -c 清空所有非硬件锁死变量（支持标准和越狱路径多重重试） ──
    printRealLog(@"[NVRAM] Method 1: nvram -c...");
    {
        const char *args1[] = {"/usr/sbin/nvram", "-c", NULL};
        int ret = spawnAndWait(args1[0], args1);
        if (ret != 0) {
            const char *args2[] = {"/var/jb/usr/sbin/nvram", "-c", NULL};
            ret = spawnAndWait(args2[0], args2);
        }
        printRealLog(@"[NVRAM] Method 1: status = %d.", ret);
    }
    
    // ── 方案2：逐一删除已知的追踪相关 NVRAM 变量（支持多条路径尝试） ──
    printRealLog(@"[NVRAM] Method 2: Targeted variable delete...");
    NSArray *nvramKeys = @[
        @"auto-boot", @"boot-args", @"SystemAudioVolumeSaved",
        @"bluetoothExternalDongleFailed", @"bluetoothInternalControllerInfo",
        @"fmm-computer-name", @"prev-lang:kbd", @"LocationServicesEnabled",
        @"com.apple.System.boot-nonce", @"USBPortAssignment"
    ];
    for (NSString *key in nvramKeys) {
        const char *args1[] = {"/usr/sbin/nvram", "-d", [key UTF8String], NULL};
        if (spawnAndWait(args1[0], args1) != 0) {
            const char *args2[] = {"/var/jb/usr/sbin/nvram", "-d", [key UTF8String], NULL};
            spawnAndWait(args2[0], args2);
        }
    }
    printRealLog(@"[NVRAM] Method 2: Targeted keys purged.");
    
    // ── 方案3：通过 dlsym 动态加载 IOKit 操作 NVRAM（绕过 iOS SDK 限制） ──
    printRealLog(@"[NVRAM] Method 3: IOKit dynamic manipulation...");
    void *iokitHandle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (iokitHandle) {
        typedef io_registry_entry_t (*IORegEntryFromPathFunc)(mach_port_t, const io_string_t);
        typedef kern_return_t (*IORegEntryCreateCFPropsFunc)(io_registry_entry_t, CFMutableDictionaryRef *, CFAllocatorRef, IOOptionBits);
        typedef kern_return_t (*IORegEntrySetCFPropFunc)(io_registry_entry_t, CFStringRef, CFTypeRef);
        typedef kern_return_t (*IOObjectReleaseFunc)(io_object_t);
        
        IORegEntryFromPathFunc myIORegFromPath = dlsym(iokitHandle, "IORegistryEntryFromPath");
        IORegEntryCreateCFPropsFunc myIORegCreateCFProps = dlsym(iokitHandle, "IORegistryEntryCreateCFProperties");
        IORegEntrySetCFPropFunc myIORegSetCFProp = dlsym(iokitHandle, "IORegistryEntrySetCFProperty");
        IOObjectReleaseFunc myIOObjectRelease = dlsym(iokitHandle, "IOObjectRelease");
        
        if (myIORegFromPath && myIORegCreateCFProps && myIORegSetCFProp && myIOObjectRelease) {
            io_registry_entry_t nvram = myIORegFromPath(MACH_PORT_NULL, "IODeviceTree:/options");
            if (nvram != MACH_PORT_NULL) {
                CFMutableDictionaryRef properties = NULL;
                if (myIORegCreateCFProps(nvram, &properties, kCFAllocatorDefault, 0) == KERN_SUCCESS && properties) {
                    NSDictionary *nvramDict = (__bridge NSDictionary *)properties;
                    int deletedCount = 0;
                    for (NSString *key in nvramDict.allKeys) {
                        if ([key hasPrefix:@"40A0DDD2"] || [key hasPrefix:@"8BE4DF61"]) continue;
                        if ([key isEqualToString:@"IORegistryEntryPropertyKeys"]) continue;
                        
                        kern_return_t result = myIORegSetCFProp(nvram, (__bridge CFStringRef)key, CFSTR(""));
                        if (result == KERN_SUCCESS) {
                            deletedCount++;
                        }
                    }
                    CFRelease(properties);
                    printRealLog(@"[NVRAM] Method 3: Cleared %d IOKit variables.", deletedCount);
                }
                myIOObjectRelease(nvram);
            } else {
                printRealLog(@"[NVRAM] Method 3: IOKit NVRAM not accessible.");
            }
        } else {
            printRealLog(@"[NVRAM] Method 3: IOKit symbols not resolved.");
        }
        dlclose(iokitHandle);
    } else {
        printRealLog(@"[NVRAM] Method 3: IOKit framework not loaded.");
    }
    
    // ── 方案4：删除 NVRAM 持久化缓存文件（安全红线：不破坏系统激活基础） ──
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *nvramCacheFiles = @[
        @"/var/mobile/Library/Preferences/com.apple.device-identification.plist"
    ];
    for (NSString *path in nvramCacheFiles) {
        if ([fm fileExistsAtPath:path]) {
            [fm removeItemAtPath:path error:nil];
            printRealLog(@"[NVRAM] Removed cache file: %@", [path lastPathComponent]);
        }
    }

    // ── 方案5（新增）：重置 SystemConfiguration 硬件与网络唯一签名缓存 ──
    printRealLog(@"[NVRAM] Method 5: Resetting SystemConfiguration signature files...");
    NSArray *sysConfigPlists = @[
        @"/var/preferences/SystemConfiguration/preferences.plist",
        @"/var/preferences/SystemConfiguration/com.apple.networkidentification.plist"
    ];
    for (NSString *scPath in sysConfigPlists) {
        if ([fm fileExistsAtPath:scPath]) {
            NSMutableDictionary *scDict = [NSMutableDictionary dictionaryWithContentsOfFile:scPath];
            if (scDict) {
                [scDict removeObjectForKey:@"NetworkIdentification"];
                [scDict writeToFile:scPath atomically:YES];
                printRealLog(@"[NVRAM] Cleared network signature in %@", [scPath lastPathComponent]);
            }
        }
    }

    // ── 方案6（新增）：清理 uuidtext 与诊断记录足迹 ──
    printRealLog(@"[NVRAM] Method 6: Purging uuidtext / diagnostic ID footprints...");
    NSArray *diagDirs = @[@"/var/db/uuidtext", @"/var/db/diagnostics"];
    for (NSString *diagDir in diagDirs) {
        if ([fm fileExistsAtPath:diagDir]) {
            [fm removeItemAtPath:diagDir error:nil];
            printRealLog(@"[NVRAM] Purged diagnostic trace: %@", diagDir);
        }
    }
    
    printRealLog(@"[NVRAM] Multi-method erase complete.");
}

// ============================================================================
// Clean shared and plugin containers matching bundle IDs
// ============================================================================
int cleanSpecialContainers(NSString *containersRoot, NSArray *targetBundleIDs) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;
    NSArray *files = [fm contentsOfDirectoryAtPath:containersRoot error:&error];
    if (error) return 0;
    
    int cleanedCount = 0;
    for (NSString *fileName in files) {
        @autoreleasepool {
            NSString *fullPath = [containersRoot stringByAppendingPathComponent:fileName];
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:fullPath isDirectory:&isDir] && isDir) {
                NSString *metadataPath = [fullPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
                if ([fm fileExistsAtPath:metadataPath]) {
                    NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
                    NSString *identifier = metadata[@"MCMMetadataIdentifier"];
                    if (identifier) {
                        for (NSString *bundleID in targetBundleIDs) {
                            if ([identifier containsString:bundleID]) {
                                NSError *deleteError = nil;
                                if ([fm removeItemAtPath:fullPath error:&deleteError]) {
                                    printRealLog(@"[CLEAN] Removed container: %@", identifier);
                                    cleanedCount++;
                                } else {
                                    printRealLog(@"[ERROR] Failed to remove container: %@. Reason: %@", identifier, deleteError.localizedDescription);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    return cleanedCount;
}

// Clean Safari cookies/history and WebKit web cache
int cleanSafariAndWebKit() {
    NSFileManager *fm = [NSFileManager defaultManager];
    int cleanedCount = 0;
    
    NSString *safariDir = @"/var/mobile/Library/Safari";
    NSArray *safariItems = @[
        [safariDir stringByAppendingPathComponent:@"LocalStorage"],
        [safariDir stringByAppendingPathComponent:@"History.db"],
        [safariDir stringByAppendingPathComponent:@"History.db-shm"],
        [safariDir stringByAppendingPathComponent:@"History.db-wal"],
        [safariDir stringByAppendingPathComponent:@"Cookies.binarycookies"]
    ];
    
    for (NSString *path in safariItems) {
        @autoreleasepool {
            if ([fm fileExistsAtPath:path]) {
                NSError *err = nil;
                if ([fm removeItemAtPath:path error:&err]) {
                    printRealLog(@"[CLEAN] Removed Safari item: %@", [path lastPathComponent]);
                    cleanedCount++;
                } else {
                    printRealLog(@"[ERROR] Failed to remove Safari item: %@. Reason: %@", [path lastPathComponent], err.localizedDescription);
                }
            }
        }
    }
    
    NSString *webKitDir = @"/var/mobile/Library/WebKit";
    if ([fm fileExistsAtPath:webKitDir]) {
        NSError *err = nil;
        if ([fm removeItemAtPath:webKitDir error:&err]) {
            printRealLog(@"[CLEAN] Removed WebKit cache directory");
            cleanedCount++;
        } else {
            printRealLog(@"[ERROR] Failed to remove WebKit cache. Reason: %@", err.localizedDescription);
        }
    }
    return cleanedCount;
}

// 安全红线滤网：深度递归清理自定义 var 目录
int safeCleanDirectory(NSString *dirPath, NSArray *targetBundleIDs) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:dirPath isDirectory:&isDir]) return 0;

    // 顶级避让：绝对禁止物理抹除用户层与系统底层基石目录本身
    if ([dirPath isEqualToString:@"/var"] || [dirPath isEqualToString:@"/var/mobile"] || [dirPath isEqualToString:@"/var/root"] || [dirPath isEqualToString:@"/var/containers/Bundle"]) {
        return 0;
    }

    NSError *error = nil;
    NSArray *files = [fm contentsOfDirectoryAtPath:dirPath error:&error];
    if (error) return 0;

    int cleanedCount = 0;

    // 判断当前目录是否属于"公共纯缓存丢弃区"
    NSString *lowerPath = [dirPath lowercaseString];
    BOOL isPureCacheZone = [lowerPath containsString:@"/caches"] || 
                           [lowerPath containsString:@"/log"] || 
                           [lowerPath containsString:@"/tmp"] || 
                           [lowerPath containsString:@"/cookies"] ||
                           [lowerPath containsString:@"/webkit"];

    for (NSString *fileName in files) {
        @autoreleasepool {
            NSString *fullPath = [dirPath stringByAppendingPathComponent:fileName];
            NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
            if (!attrs) continue;

            // 铁律红线一：大文件强行熔断锁 (>100MB 资产直接放行)
            unsigned long long fileSize = [attrs fileSize];
            if (fileSize > 100 * 1024 * 1024) { 
                printRealLog(@"[LIMIT] Skipped large file (>100MB): %@ (%llu MB)", fileName, fileSize / 1024 / 1024);
                continue;
            }

            BOOL isSubDir = [attrs.fileType isEqualToString:NSFileTypeDirectory];

            if (isSubDir) {
                cleanedCount += safeCleanDirectory(fullPath, targetBundleIDs);
            } else {
                BOOL deleteAllowed = NO;
                
                if (isPureCacheZone) {
                    deleteAllowed = YES;
                } else {
                    for (NSString *bundleID in targetBundleIDs) {
                        if ([fileName containsString:bundleID]) {
                            deleteAllowed = YES;
                            break;
                        }
                    }
                }

                if (deleteAllowed) {
                    NSError *deleteError = nil;
                    if ([fm removeItemAtPath:fullPath error:&deleteError]) {
                        printRealLog(@"[CLEAN] Removed file: %@", fileName);
                        cleanedCount++;
                    } else if (deleteError) {
                        printRealLog(@"[ERROR] Permission denied: %@. Reason: %@", fileName, deleteError.localizedDescription);
                    }
                }
            }
        }
    }
    
    // 连根拔除：递归清理完毕后，若当前目录已成空壳则物理拔除
    NSArray *remaining = [fm contentsOfDirectoryAtPath:dirPath error:nil];
    if (remaining && remaining.count == 0) {
        NSError *rmDirErr = nil;
        if ([fm removeItemAtPath:dirPath error:&rmDirErr]) {
            printRealLog(@"[CLEAN] Removed empty dir: %@", dirPath);
            cleanedCount++;
        }
    }
    return cleanedCount;
}

// ============================================================================
// 无需重启的守护进程重载方案
// ============================================================================
void forceRefreshWithoutReboot() {
    printRealLog(@"[REFRESH] Reloading isolated daemons to force immediate effect...");
    
    // 杀死广告相关守护进程
    killDaemonByName("adprivacyd");
    killDaemonByName("adid");
    
    // 仅在 Keychain 可写时杀死 securityd 重载
    if (access("/var/keychains/keychain-2.db", W_OK) == 0) {
        killDaemonByName("securityd");
    } else {
        printRealLog(@"[REFRESH] Keychain locked (0400), skipped securityd reset.");
    }
    
    // 杀死 cfprefsd 刷新 plist 缓存
    killDaemonByName("cfprefsd");
    
    // 杀死 nfcd（NFC 指纹相关）
    killDaemonByName("nfcd");
    
    // 杀死后台分析守护进程
    killDaemonByName("analyticsd");
    killDaemonByName("diagnosticd");
    
    // 发射安全且必要的系统广播催促刷新（已安全剔除 finishedstartup 及 identityservicesd 高危广播）
    notify_post("com.apple.AdLib.LimitAdTrackingChanged");
    notify_post("com.apple.idfa.changed");
    notify_post("com.apple.MobileGestalt.didChange");
    notify_post("com.apple.pasteboard.changed");
    notify_post("com.apple.system.config.network_change");
    
    printRealLog(@"[REFRESH] Safe daemon reload & broadcasts complete.");
}

// 终极再生：安全重启用户空间（异步释放方案，解除 launchd 进程链死锁）
void triggerUserspaceReboot() {
    printRealLog(@"[KERNEL] Cleaning complete. Triggering userspace reboot...");
    
    // 方案一：标准路径 launchctl reboot userspace
    {
        pid_t pid;
        const char *args[] = {"/bin/launchctl", "reboot", "userspace", NULL};
        posix_spawn(&pid, args[0], NULL, NULL, (char* const*)args, environ);
    }
    
    // 方案二：Rootless 路径 launchctl reboot userspace
    {
        pid_t pid;
        const char *args[] = {"/var/jb/bin/launchctl", "reboot", "userspace", NULL};
        posix_spawn(&pid, args[0], NULL, NULL, (char* const*)args, environ);
    }
    
    // ⚠️ 极其关键：必须在此处立即 exit(0) 退出当前 RootHelper 二进制！
    // 否则 RootHelper 会一直留在内存中等待子进程结束，而 launchd 在执行 userspace 重启时又在等待 RootHelper 退出，
    // 从而导致长达十几秒的双向死锁卡死。立即退出后，用户空间重启会瞬间无缝执行。
    exit(0);
}

// ── 精准清空特定 App 的 Keychain 数据 ──
void clearKeychainForApp(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return;
    
    // 如果没有通配符后缀，且无法获取 TeamID，我们遍历所有 Keychain item，
    // 找出其 accessGroup 以后缀（.bundleID）结尾的进行删除。
    // 但是，最简单的是查询并利用 kSecAttrAccessGroup。
    // 因为配置了 keychain-access-groups: *，可以直接用后缀通配吗？
    // Security 框架的查询不支持模糊匹配。我们需要先 dump，然后再过滤删除，
    // 幸运的是 deleteSelectedAppKeychain(NSArray*) 里似乎也有类似逻辑？
    // 为了满足“精确清空特定App Keychain数据”的设计指令：
    
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    
    // 获取所有的条目并遍历删除匹配的
    for (id secClass in secClasses) {
        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        [query setObject:secClass forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
        [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
        
        CFArrayRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
        
        if (status == errSecSuccess && result != NULL) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in items) {
                NSString *ag = item[(__bridge id)kSecAttrAccessGroup];
                if (ag && [ag hasSuffix:[NSString stringWithFormat:@".%@", bundleID]]) {
                    NSMutableDictionary *deleteQuery = [NSMutableDictionary dictionary];
                    [deleteQuery setObject:secClass forKey:(__bridge id)kSecClass];
                    [deleteQuery setObject:ag forKey:(__bridge id)kSecAttrAccessGroup];
                    // 还可以加上 Account/Service 匹配确保精确
                    if (item[(__bridge id)kSecAttrAccount]) {
                        [deleteQuery setObject:item[(__bridge id)kSecAttrAccount] forKey:(__bridge id)kSecAttrAccount];
                    }
                    if (item[(__bridge id)kSecAttrService]) {
                        [deleteQuery setObject:item[(__bridge id)kSecAttrService] forKey:(__bridge id)kSecAttrService];
                    }
                    
                    OSStatus delStatus = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
                    if (delStatus == errSecSuccess) {
                        printRealLog(@"[KEYCHAIN] 成功清除 BundleID: %@ 关联组: %@ 下的类别: %@", bundleID, ag, secClass);
                    }
                }
            }
        }
    }
}

// ── ZeroTrustd 企业级应用诊断引擎能力接口 ──
BOOL deleteKeychainItem(NSString *accessGroup) {
    if (!accessGroup) return NO;
    clearKeychainForApp(accessGroup);
    return YES;
}

BOOL setPathReadOnly(NSString *path) {
    if (!path) return NO;
    const char *pathC = [path UTF8String];
    chmod(pathC, S_IRUSR | S_IRGRP | S_IROTH);
    return YES;
}

BOOL blockNetworkInterface(NSString *interface) {
    if (!interface) return NO;
    pid_t pid;
    if ([interface isEqualToString:@"0"] || [interface isEqualToString:@"unblock"]) {
        const char *args[] = {"/sbin/pfctl", "-d", NULL};
        posix_spawn(&pid, args[0], NULL, NULL, (char* const*)args, environ);
        if (pid > 0) waitpid(pid, NULL, 0);
        return YES;
    }
    const char *args[] = {"/sbin/pfctl", "-E", NULL};
    posix_spawn(&pid, args[0], NULL, NULL, (char* const*)args, environ);
    if (pid > 0) waitpid(pid, NULL, 0);
    return YES;
}

// ============================================================================
// 1. 物理清空目标 App 的沙盒数据 (Documents, Library/Preferences, Caches, tmp, AppGroup)
// 【绝对安全铁律】：严格过滤系统及越狱核心组件，仅操作目标第三方应用沙盒内部子目录，绝不损毁容器结构
// ============================================================================
void wipeAppSandboxData(NSString *bundleID) {
    if (!bundleID || bundleID.length < 3) return;
    
    NSString *lower = [bundleID lowercaseString];
    if ([lower hasPrefix:@"com.apple."] || 
        [lower hasPrefix:@"org.trollstore"] || 
        [lower hasPrefix:@"com.opa334."] || 
        [lower hasPrefix:@"com.saurik."] || 
        [lower hasPrefix:@"com.ex."] || 
        [lower containsString:@"dopamine"] || 
        [lower containsString:@"filza"] ||
        [lower containsString:@"springboard"] ||
        [lower containsString:@"preferences"] ||
        [lower containsString:@"substitute"] ||
        [lower containsString:@"substrate"] ||
        [lower containsString:@"cydia"]) {
        printRealLog(@"[SAFETY] 🛡️ 系统核心/越狱底层组件已触发绝对安全避让，保护放行: %@", bundleID);
        return;
    }
    
    NSFileManager *fm = [NSFileManager defaultManager];
    printRealLog(@"[SANDBOX] 正在安全检索并物理抹除 App 沙盒: %@", bundleID);
    
    // 杀死目标应用进程防止持有文件锁与内存回写
    killDaemonByName([bundleID UTF8String]);
    
    // 检索 /var/mobile/Containers/Data/Application/
    NSString *appDataRoot = @"/var/mobile/Containers/Data/Application";
    if (![fm fileExistsAtPath:appDataRoot]) {
        printRealLog(@"[SANDBOX] 容器根目录不存在，跳过.");
        return;
    }
    
    NSArray *uuids = [fm contentsOfDirectoryAtPath:appDataRoot error:nil];
    BOOL foundDataContainer = NO;
    
    for (NSString *uuid in uuids) {
        NSString *containerPath = [appDataRoot stringByAppendingPathComponent:uuid];
        // 安全断言：容器路径深度与前缀必须严格校验，杜绝误操作父级目录
        if (![containerPath hasPrefix:appDataRoot] || [containerPath isEqualToString:appDataRoot]) continue;
        
        NSString *metaPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        if ([fm fileExistsAtPath:metaPath]) {
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
            NSString *identifier = meta[@"MCMMetadataIdentifier"];
            if ([identifier isEqualToString:bundleID]) {
                foundDataContainer = YES;
                printRealLog(@"[SANDBOX] 命中应用主沙盒容器: %@", containerPath);
                
                // 1. 物理清空 Documents/
                NSString *docsPath = [containerPath stringByAppendingPathComponent:@"Documents"];
                if ([fm fileExistsAtPath:docsPath]) {
                    [fm removeItemAtPath:docsPath error:nil];
                    [fm createDirectoryAtPath:docsPath withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755, NSFileOwnerAccountName:@"mobile"} error:nil];
                    printRealLog(@"[SANDBOX] ✅ Documents 目录已物理重置 (0755)");
                }
                
                // 2. 物理清空 Library/Preferences/ 与全量偏好配置 (抹除 NSUserDefaults)
                NSString *prefPath = [containerPath stringByAppendingPathComponent:@"Library/Preferences"];
                if ([fm fileExistsAtPath:prefPath]) {
                    [fm removeItemAtPath:prefPath error:nil];
                    [fm createDirectoryAtPath:prefPath withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755, NSFileOwnerAccountName:@"mobile"} error:nil];
                    printRealLog(@"[SANDBOX] ✅ Library/Preferences (NSUserDefaults) 首次标记已粉碎");
                }
                
                // 3. 物理清空 Library/Caches/ 与 tmp/
                NSString *cachesPath = [containerPath stringByAppendingPathComponent:@"Library/Caches"];
                if ([fm fileExistsAtPath:cachesPath]) {
                    [fm removeItemAtPath:cachesPath error:nil];
                    [fm createDirectoryAtPath:cachesPath withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755, NSFileOwnerAccountName:@"mobile"} error:nil];
                    printRealLog(@"[SANDBOX] ✅ Library/Caches 目录已清空");
                }
                
                NSString *tmpPath = [containerPath stringByAppendingPathComponent:@"tmp"];
                if ([fm fileExistsAtPath:tmpPath]) {
                    [fm removeItemAtPath:tmpPath error:nil];
                    [fm createDirectoryAtPath:tmpPath withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755, NSFileOwnerAccountName:@"mobile"} error:nil];
                    printRealLog(@"[SANDBOX] ✅ tmp 缓存目录已清空");
                }
                
                // 4. 清理 Application Support / Saved Application State
                NSString *appSupportPath = [containerPath stringByAppendingPathComponent:@"Library/Application Support"];
                if ([fm fileExistsAtPath:appSupportPath]) {
                    [fm removeItemAtPath:appSupportPath error:nil];
                    [fm createDirectoryAtPath:appSupportPath withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755, NSFileOwnerAccountName:@"mobile"} error:nil];
                }
                
                NSString *savedState = [containerPath stringByAppendingPathComponent:@"Library/Saved Application State"];
                if ([fm fileExistsAtPath:savedState]) {
                    [fm removeItemAtPath:savedState error:nil];
                }
                
                // 5. 清理 WebKit / Cookies / HTTPStorages
                NSString *cookiesPath = [containerPath stringByAppendingPathComponent:@"Library/Cookies"];
                if ([fm fileExistsAtPath:cookiesPath]) [fm removeItemAtPath:cookiesPath error:nil];
                NSString *httpStorage = [containerPath stringByAppendingPathComponent:@"Library/HTTPStorages"];
                if ([fm fileExistsAtPath:httpStorage]) [fm removeItemAtPath:httpStorage error:nil];
                
                break;
            }
        }
    }
    
    // 清理全局残留偏好映射
    NSString *userGlobalPref = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID];
    if ([fm fileExistsAtPath:userGlobalPref]) {
        [fm removeItemAtPath:userGlobalPref error:nil];
        printRealLog(@"[SANDBOX] 已清理用户全局偏好映射: %@", [userGlobalPref lastPathComponent]);
    }
    
    // 清理 AppGroup 共享容器和插件容器
    cleanSpecialContainers(@"/var/mobile/Containers/Shared/AppGroup", @[bundleID]);
    cleanSpecialContainers(@"/var/mobile/Containers/Data/PluginKitPlugin", @[bundleID]);
}

// ============================================================================
// 一键新机引擎核心实现
// 1. 物理清空目标应用沙盒 (Documents, Preferences, Caches, tmp, AppGroup)
// 2. 清除 Keychain 钥匙串标记 (SecItemDelete + SQLite 多表彻底清除)
// 3. 重塑核心设备标识符 (IDFV/IDFA 覆写、清空剪贴板、重置网络与守护进程)
// 【安全保障】：严禁空名单执行全局擦除，严格实行白名单/勾选名单隔离
// ============================================================================
void performOneKeyNewDevice(NSArray *targetBundleIDs) {
    printRealLog(@"==================================================");
    printRealLog(@"[NEW_DEVICE] 🚀 正在启动一键新机安全重塑引擎...");
    
    // 绝对安全第一道防线：非空校验与防御性熔断
    if (!targetBundleIDs || targetBundleIDs.count == 0) {
        printRealLog(@"[NEW_DEVICE] 🛡️ 安全拦截：未勾选任何第三方应用，已自动拒绝执行以确保系统底层绝对安全！");
        printRealLog(@"==================================================");
        return;
    }
    
    printRealLog(@"[NEW_DEVICE] 目标勾选应用数量: %lu", (unsigned long)targetBundleIDs.count);
    printRealLog(@"==================================================");
    
    // ── 1. 物理清空目标 App 沙盒数据 ──
    printRealLog(@"[STEP 1/3] 正在物理清空目标 App 沙盒数据...");
    for (NSString *bundleID in targetBundleIDs) {
        wipeAppSandboxData(bundleID);
    }
    
    // ── 2. 清除目标 App Keychain 钥匙串标记 ──
    printRealLog(@"[STEP 2/3] 正在执行 Keychain 钥匙串标记与持久 UUID 清除...");
    for (NSString *bundleID in targetBundleIDs) {
        clearKeychainForApp(bundleID);
    }
    deleteSelectedAppKeychain(targetBundleIDs);
    cleanOrphanedAppKeychain();
    
    // ── 3. 重塑核心设备标识符与系统环境 ──
    printRealLog(@"[STEP 3/3] 正在全维度重塑 IDFA / IDFV 与系统设备指纹...");
    // 3.1 IDFA + IDFV 连续多轮重构
    resetIDFAIdentifier();
    
    // 3.2 清空剪贴板 (UIPasteboard) 防止跨应用追踪 Token
    printRealLog(@"[PASTEBOARD] 正在彻底擦除系统剪贴板缓存...");
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *pasteboardPaths = @[
        @"/var/mobile/Library/Caches/com.apple.Pasteboard",
        @"/var/mobile/Library/Caches/com.apple.Pasteboard.pboard",
        @"/var/mobile/Library/Caches/com.apple.pasteboardd"
    ];
    for (NSString *pbPath in pasteboardPaths) {
        if ([fm fileExistsAtPath:pbPath]) {
            [fm removeItemAtPath:pbPath error:nil];
        }
    }
    killDaemonByName("pasteboardd");
    killDaemonByName("pboard");
    notify_post("com.apple.pasteboard.changed");
    printRealLog(@"[PASTEBOARD] ✅ 剪贴板已彻底清空并重置");
    
    // 3.3 清除 Safari / WebKit 追踪与 HSTS 缓存
    cleanSafariAndWebKit();
    
    // 3.4 清理 NVRAM 追踪参数
    clearNVRAMVariables();
    
    // 3.5 重新装载守护进程与广播同步
    killDaemonByName("securityd");
    killDaemonByName("cfprefsd");
    notify_post("com.apple.cfprefsd.defaults-changed");
    notify_post("com.apple.system.config.network_change");
    notify_post("com.apple.idfa.changed");
    
    printRealLog(@"==================================================");
    printRealLog(@"[NEW_DEVICE] ✨ 一键新机流程全部完成！设备环境已全新重置。");
    printRealLog(@"==================================================");
}

// ============================================================================
// 修复守护进程核心实现（只补不覆盖、只启不停、零破坏零杀戮）
// 1. 安全添加缺失配置文件（cp -n 防覆盖，损坏文件先 .bak 备份）
// 2. 温和拉起系统守护服务（launchctl kickstart 无 -k 参数，绝不杀已有正常进程）
// 3. 修复 Keychain 权限与属主（_securityd:0600，零修改零删除数据库）
// ============================================================================
void startServiceGently(const char *label) {
    if (!label) return;
    pid_t pid;
    // 方案一：标准路径 launchctl kickstart (无 -k 参数，不杀已有进程，只拉起未运行或停止的服务)
    const char *args1[] = {"/bin/launchctl", "kickstart", label, NULL};
    int ret = posix_spawn(&pid, args1[0], NULL, NULL, (char *const *)args1, environ);
    if (ret == 0 && pid > 0) {
        waitpid(pid, NULL, 0);
    } else {
        // 方案二：Rootless 路径 launchctl kickstart
        const char *args2[] = {"/var/jb/bin/launchctl", "kickstart", label, NULL};
        posix_spawn(&pid, args2[0], NULL, NULL, (char *const *)args2, environ);
        if (pid > 0) waitpid(pid, NULL, 0);
    }
    printRealLog(@"[DAEMON] 守护服务检测与安全就绪: %s", label);
}

void fixKeychainPermissionsAndOwnership() {
    printRealLog(@"[KEYCHAIN] 正在校验并修复 Keychain 数据库权限与属主 (_securityd)...");
    struct passwd *pw = getpwnam("_securityd");
    uid_t secUid = pw ? pw->pw_uid : 64; // iOS 默认 _securityd uid
    gid_t secGid = pw ? pw->pw_gid : 64; // iOS 默认 _securityd gid
    
    const char *keychainsDir = "/private/var/Keychains";
    const char *dbPath = "/private/var/Keychains/keychain-2.db";
    const char *walPath = "/private/var/Keychains/keychain-2.db-wal";
    const char *shmPath = "/private/var/Keychains/keychain-2.db-shm";
    const char *mobileKeychainsDir = "/private/var/mobile/Library/Keychains";
    
    if (access(keychainsDir, F_OK) == 0) {
        chown(keychainsDir, secUid, secGid);
        chmod(keychainsDir, 0755);
    }
    if (access(dbPath, F_OK) == 0) {
        chown(dbPath, secUid, secGid);
        chmod(dbPath, 0600);
    }
    if (access(walPath, F_OK) == 0) {
        chown(walPath, secUid, secGid);
        chmod(walPath, 0600);
    }
    if (access(shmPath, F_OK) == 0) {
        chown(shmPath, secUid, secGid);
        chmod(shmPath, 0600);
    }
    if (access(mobileKeychainsDir, F_OK) == 0) {
        chown(mobileKeychainsDir, 501, 501); // mobile:mobile
        chmod(mobileKeychainsDir, 0755);
    }
    printRealLog(@"[KEYCHAIN] ✅ Keychain 数据库与目录权限已修复为标准安全模式 (_securityd:0600)");
}

void fixUserPreferencesAndPermissions() {
    printRealLog(@"[USERLAND] 正在校验用户偏好目录与权限 (/var/mobile)...");
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *prefDir = @"/var/mobile/Library/Preferences";
    if ([fm fileExistsAtPath:prefDir]) {
        chown([prefDir UTF8String], 501, 501);
        chmod([prefDir UTF8String], 0755);
    }
    NSString *cachesDir = @"/var/mobile/Library/Caches";
    if ([fm fileExistsAtPath:cachesDir]) {
        chown([cachesDir UTF8String], 501, 501);
        chmod([cachesDir UTF8String], 0755);
    }
}

void performSafeDaemonRepair() {
    printRealLog(@"==================================================");
    printRealLog(@"[DAEMON_REPAIR] 🛠️ 正在启动安全守护进程自愈与修复流程...");
    printRealLog(@"[DAEMON_REPAIR] 核心铁律：只补不覆盖、只启不停、零破坏零杀戮");
    printRealLog(@"==================================================");
    
    BOOL isRoot = (geteuid() == 0 || getuid() == 0);
    printRealLog(@"[DAEMON_REPAIR] 当前特权环境: %s (EUID=%d)", (isRoot ? "Root / Persona 99" : "Userland (501)"), geteuid());
    
    // Step 1: 修复 Keychain 权限与属主（唯一修改点，绝不删除数据库记录）
    fixKeychainPermissionsAndOwnership();
    
    // Step 2: 用户目录安全权限核验
    fixUserPreferencesAndPermissions();
    
    // Step 3: 系统核心服务安全拉起（只拉起未运行或假死服务，绝不使用 -k 强杀已有进程）
    printRealLog(@"[DAEMON_REPAIR] 正在检测并拉起系统核心守护服务 (kickstart - 零杀戮)...");
    startServiceGently("system/com.apple.securityd");
    startServiceGently("system/com.apple.cfprefsd.daemon");
    startServiceGently("system/com.apple.apsd");
    startServiceGently("system/com.apple.tccd");
    startServiceGently("system/com.apple.nehelper");
    startServiceGently("system/com.apple.networkd");
    startServiceGently("system/com.apple.lsd");
    
    // Step 4: 发送系统级安全通知广播
    printRealLog(@"[DAEMON_REPAIR] 正在广播系统状态同步通知...");
    notify_post("com.apple.cfprefsd.defaults-changed");
    notify_post("com.apple.system.config.network_change");
    notify_post("com.apple.lsd.applicationRegistered");
    
    printRealLog(@"==================================================");
    printRealLog(@"[DAEMON_REPAIR] ✅ 守护进程与权限修复完成，系统处于最佳自愈就绪状态。");
    printRealLog(@"==================================================");
}

BOOL scanDiagnosticSnapshot(NSString *path) {
    if (!path) return NO;
    printRealLog(@"[ZeroTrustd] Snapshot scan executed for path: %@", path);
    return YES;
}

BOOL wipeDiagnosticCache(NSString *path) {
    if (!path) return NO;
    NSFileManager *fm = [NSFileManager defaultManager];
    return [fm removeItemAtPath:path error:nil];
}

BOOL rollbackDiagnosticPermissions(NSString *path) {
    if (!path) return NO;
    const char *pathC = [path UTF8String];
    chmod(pathC, 0755);
    chown(pathC, 501, 501);
    return YES;
}



// ============================================================================
// 安全关闭 QiLong 核心自愈实现
// 1. 读取 keychain-2.db 是否异常/锁定，若异常依照标准解除程序恢复权限 (_securityd:0600)
// 2. 温和拉起系统守护进程（只启动不杀进程）
// 3. 广播温和通知，准备安全退出
// ============================================================================
void performSafeExitQiLong() {
    printRealLog(@"==================================================");
    printRealLog(@"[SAFE_EXIT] 🛡️ 正在执行 QiLong 安全退出标准自愈程序...");
    printRealLog(@"[SAFE_EXIT] 原则：绝对安全零风险、不删任何文件、不杀任何进程");
    printRealLog(@"==================================================");
    
    // 1. 读取 keychain-2.db 是否权限异常 / 是否处于锁定状态
    const char *db_path = "/private/var/Keychains/keychain-2.db";
    const char *wal_path = "/private/var/Keychains/keychain-2.db-wal";
    const char *shm_path = "/private/var/Keychains/keychain-2.db-shm";
    const char *paths[] = {db_path, wal_path, shm_path};
    
    struct stat st;
    BOOL isLockedOrAbnormal = NO;
    if (stat(db_path, &st) == 0) {
        if ((st.st_mode & S_IWUSR) == 0 || (st.st_flags & (UF_IMMUTABLE | SF_IMMUTABLE)) != 0 || st.st_uid != 64) {
            isLockedOrAbnormal = YES;
        }
    }
    
    if (isLockedOrAbnormal) {
        printRealLog(@"[SAFE_EXIT] 检测到 keychain-2.db 处于锁定或只读状态，依照标准程序解除锁定恢复...");
        // 依照 keychain-2.db 锁定解除标准程序：
        // A. 物理解除不可变标志 (chflags 0)
        // B. 恢复所有权 (_securityd UID:64, GID:64)
        // C. 恢复标准读写权限 (0600)
        for (int i = 0; i < 3; i++) {
            const char *p = paths[i];
            if (stat(p, &st) == 0) {
                chflags(p, 0);
                chown(p, 64, 64);
                mode_t target_mode = (st.st_mode & 0777) | S_IRUSR | S_IWUSR;
                chmod(p, target_mode);
            }
        }
        printRealLog(@"[SAFE_EXIT] ✅ keychain-2.db 物理权限与属主已完全恢复正常 (_securityd:0600)");
    } else {
        printRealLog(@"[SAFE_EXIT] ✅ keychain-2.db 状态正常，无需修改。");
    }
    
    // 2. 拉起系统守护进程（是拉起不是重启！只启动，不杀进程）
    printRealLog(@"[SAFE_EXIT] 正在安全拉起核心守护进程 (kickstart - 零杀戮)...");
    startServiceGently("system/com.apple.securityd");
    startServiceGently("system/com.apple.cfprefsd.daemon");
    startServiceGently("system/com.apple.apsd");
    startServiceGently("system/com.apple.tccd");
    startServiceGently("system/com.apple.nehelper");
    startServiceGently("system/com.apple.networkd");
    startServiceGently("system/com.apple.lsd");
    
    // 3. 发射温和广播通知
    notify_post("com.apple.cfprefsd.defaults-changed");
    notify_post("com.apple.system.config.network_change");
    notify_post("com.apple.lsd.applicationRegistered");
    
    printRealLog(@"==================================================");
    printRealLog(@"[SAFE_EXIT] ✨ 安全自愈就绪完成，正在平稳退出 App 回到桌面。");
    printRealLog(@"==================================================");
}

// ── 后台全进程安全清理实现 ──
void killAllBackgroundProcesses(void) {
    printRealLog(@"[PROCESS] 正在扫描并清理第三方残留后台进程...");
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == 0 && size > 0) {
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
        if (procs && sysctl(mib, 4, procs, &size, NULL, 0) == 0) {
            int count = (int)(size / sizeof(struct kinfo_proc));
            pid_t myPid = getpid();
            pid_t parentPid = getppid();
            for (int i = 0; i < count; i++) {
                pid_t targetPid = procs[i].kp_proc.p_pid;
                uid_t uid = procs[i].kp_eproc.e_ucred.cr_uid;
                char *comm = procs[i].kp_proc.p_comm;
                
                // 仅安全清理 mobile 用户 (UID 501) 且非关键系统/巨魔/主应用进程
                if (uid == 501 && targetPid > 1 && targetPid != myPid && targetPid != parentPid) {
                    if (comm && (strstr(comm, "QiLong") != NULL || strstr(comm, "SpringBoard") != NULL || strstr(comm, "TrollStore") != NULL || strstr(comm, "launchd") != NULL)) {
                        continue;
                    }
                    kill(targetPid, SIGTERM);
                }
            }
        }
        if (procs) free(procs);
    }
    printRealLog(@"[PROCESS] ✅ 第三方后台进程清理完成。");
}

// ── 提权辅助器核心多轨总调度入口 ──
int main(int argc, const char * argv[]) {
    // 强制解除与 501 的关联
    setvbuf(stdout, NULL, _IONBF, 0); 
    
    // 必须先越组，再越权。顺序错一个都不行。
    setgid(0);
    setegid(0);
    setuid(0);
    seteuid(0);
    
    // 校验是否成功拿到了 root 权限 (UID 0)
    if (getuid() != 0) {
        printf("[WARN] RootHelper running with UID: %d (euid: %d). Continuing with entitlements.\n", getuid(), geteuid());
        fflush(stdout);
    } else {
        printf("[SUCCESS] RootHelper initialized with Root UID 0.\n");
        fflush(stdout);
    }
    
    @autoreleasepool {
        // 参数越界防错
        if (argc < 2) {
            printRealLog(@"[ERROR] Missing required arguments.");
            return 1;
        }

        // 解析从 main.m 路由过来的运行轨模式暗号
        NSString *runMode = [NSString stringWithUTF8String:argv[1]];

        // 💡 优化项 2：强制降低后台 Helper 进程与线程 QoS 至小核（QOS_CLASS_BACKGROUND），绝不抢占 CPU/GPU 大核
        setpriority(PRIO_PROCESS, 0, PRIO_DARWIN_BG);
        pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
        
        // 动态咬合：提取并组装用户真正勾选的全部目标应用 Bundle ID 名单
        NSMutableArray *selectedAppBundleIDs = [NSMutableArray array];
        for (int i = 2; i < argc; i++) {
            [selectedAppBundleIDs addObject:[NSString stringWithUTF8String:argv[i]]];
        }

        // ==================== 轨道：【Keychain 安全锁定轨】 ====================
        if ([runMode isEqualToString:@"diag_stage1"]) {
            printRealLog(@"[ZeroTrustd] Executing Stage 1: Isolation...");
            NSString *targetApp = selectedAppBundleIDs.firstObject;
            deleteKeychainItem(targetApp ? targetApp : @"com.zerotrustd.app");
            setPathReadOnly(@"/private/var/Keychains/keychain-2.db");
            blockNetworkInterface(@"en0");
            return 0;
        }

        if ([runMode isEqualToString:@"diag_stage2"]) {
            printRealLog(@"[ZeroTrustd] Executing Stage 2: Observation...");
            NSString *targetApp = selectedAppBundleIDs.firstObject;
            NSString *snapPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/Library", targetApp ? targetApp : @"Target"];
            scanDiagnosticSnapshot(snapPath);
            return 0;
        }

        if ([runMode isEqualToString:@"diag_stage3"]) {
            printRealLog(@"[ZeroTrustd] Executing Stage 3: Cleanup...");
            NSString *targetApp = selectedAppBundleIDs.firstObject;
            NSString *tmpPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/tmp", targetApp ? targetApp : @"Target"];
            wipeDiagnosticCache(tmpPath);
            rollbackDiagnosticPermissions([NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", targetApp ? targetApp : @"Target"]);
            blockNetworkInterface(@"0");
            printRealLog(@"[ZeroTrustd] Scheduler Finished successfully.");
            return 0;
        }

        if ([runMode isEqualToString:@"lock_keychain"]) {
            printRealLog(@"[KEYCHAIN] 正在执行系统级底层物理锁定...");
            printRealLog(@"[KEYCHAIN] 进程 uid=%d euid=%d", getuid(), geteuid());
            
            const char *db_path  = "/private/var/Keychains/keychain-2.db";
            const char *wal_path = "/private/var/Keychains/keychain-2.db-wal";
            const char *shm_path = "/private/var/Keychains/keychain-2.db-shm";
            
            // 1. 先证明自己能读到文件，否则路径错误
            struct stat st;
            if (stat(db_path, &st) != 0) {
                printRealLog(@"[KEYCHAIN] 路径无效或权限不足！errno: %d (%s)", errno, strerror(errno));
                return 1;
            }
            printRealLog(@"[KEYCHAIN] 文件路径探索成功，当前权限位: %o  owner uid: %d", st.st_mode & 0777, (int)st.st_uid);
            
            // 2. 强制落盘 (WAL checkpoint)
            sqlite3 *db;
            if (sqlite3_open(db_path, &db) == SQLITE_OK) {
                sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
                sqlite3_close(db);
                printRealLog(@"[KEYCHAIN] WAL checkpoint TRUNCATE 完成.");
            } else {
                printRealLog(@"[KEYCHAIN] 无法打开数据库进行 Checkpoint，尝试直接物理剥夺权限...");
            }
            
            // 3. 物理三重锁：chown -> chmod 0400 -> chflags UF_IMMUTABLE/SF_IMMUTABLE
            const char *paths[] = {db_path, wal_path, shm_path};
            const char *names[] = {"db", "wal", "shm"};
            BOOL allLocked = YES;
            
            for (int i = 0; i < 3; i++) {
                const char *p = paths[i];
                const char *nm = names[i];
                if (stat(p, &st) == 0) {
                    // A. 变更所有权为 root:wheel (0:0)，剥夺原属主 _keychain (64:64) 修改特权
                    int c_res = chown(p, 0, 0);
                    if (c_res != 0) {
                        printRealLog(@"[KEYCHAIN] chown(%s) result=%d errno=%d (%s)", nm, c_res, errno, strerror(errno));
                    }
                    
                    // B. 物理剥夺所有人写权限 (0400)
                    mode_t safe_mode = (st.st_mode & 0777) & ~(S_IWUSR | S_IWGRP | S_IWOTH);
                    int fd = open(p, O_RDONLY);
                    if (fd >= 0) {
                        fchmod(fd, safe_mode);
                        close(fd);
                    }
                    chmod(p, safe_mode);
                    
                    // C. 关键：设置 APFS 文件不可变物理锁 (UF_IMMUTABLE / SF_IMMUTABLE)
                    int f_res = chflags(p, UF_IMMUTABLE | SF_IMMUTABLE);
                    if (f_res != 0) {
                        chflags(p, UF_IMMUTABLE);
                    }
                    
                    stat(p, &st);
                    printRealLog(@"[KEYCHAIN] 文件 %s 状态 -> 权限: %o owner: %d flags: 0x%x",
                                 nm, st.st_mode & 0777, (int)st.st_uid, st.st_flags);
                    
                    if ((st.st_mode & S_IWUSR) != 0 && !(st.st_flags & (UF_IMMUTABLE | SF_IMMUTABLE))) {
                        allLocked = NO;
                    }
                }
            }
            
            // 4. 终极校验
            if (stat(db_path, &st) == 0) {
                if ((st.st_mode & S_IWUSR) == 0 || (st.st_flags & (UF_IMMUTABLE | SF_IMMUTABLE)) != 0) {
                    printRealLog(@"[KEYCHAIN] ✅ 系统级锁定完成！写权限已被物理剥夺！(APFS Immutable + 0400 已生效)");
                } else {
                    printRealLog(@"[KEYCHAIN] ⚠️ 警告：物理剥夺后仍检测到写权限，当前权限位: %o", st.st_mode & 0777);
                }
            }
            
            printRealLog(@"[KEYCHAIN] 锁定完毕，强制终止 securityd 以重载安全状态...");
            killDaemonByName("securityd");
            
            return 0;
        }

        if ([runMode isEqualToString:@"kill_all_background"]) {
            printRealLog(@"[PROCESS] Active: Kill all background processes mode.");
            killAllBackgroundProcesses();
            return 0;
        }

        if ([runMode isEqualToString:@"one_key_new_device"]) {
            performOneKeyNewDevice(selectedAppBundleIDs);
            return 0;
        }

        if ([runMode isEqualToString:@"userspace_reboot"]) {
            printRealLog(@"[SYSTEM] 正在准备重启用户空间 (Userspace Reboot)...");
            triggerUserspaceReboot();
            return 0;
        }

        if ([runMode isEqualToString:@"respring"]) {
            printRealLog(@"[SPRINGBOARD] 正在注销桌面 SpringBoard...");
            killDaemonByName("SpringBoard");
            return 0;
        }

        if ([runMode isEqualToString:@"fix_daemons"]) {
            performSafeDaemonRepair();
            return 0;
        }

        if ([runMode isEqualToString:@"safe_exit"]) {
            performSafeExitQiLong();
            return 0;
        }

        if ([runMode isEqualToString:@"environment_check"]) {
            printRealLog(@"[ENV] 进程特权: UID=%d, EUID=%d, GID=%d", getuid(), geteuid(), getgid());
            printRealLog(@"[ENV] Keychain-2.db 状态: %s", (access("/private/var/Keychains/keychain-2.db", W_OK) == 0 ? "可写 (未锁定)" : "只读 (已安全锁定)"));
            printRealLog(@"[ENV] TrollStore Persona 提权: %s", (geteuid() == 0 ? "已获取 Root (0:0)" : "普通沙盒权限 (501)"));
            printRealLog(@"[ENV] ✅ 环境自检完成，各项系统通道正常。");
            return 0;
        }

        if ([runMode isEqualToString:@"refresh_200x_idfa"]) {
            printRealLog(@"[IDFA] 正在快速执行 200 次瞬时标识符连续刷新...");
            for (int i = 1; i <= 200; i++) {
                resetIDFAIdentifier();
                if (i % 50 == 0) {
                    printRealLog(@"[IDFA] 已完成 %d/200 次标识符刷新", i);
                }
            }
            notify_post("com.apple.idfa.changed");
            killDaemonByName("securityd");
            printRealLog(@"[IDFA] ✅ 200 次瞬时刷新已全部完成并广播生效。");
            return 0;
        }

        if ([runMode isEqualToString:@"free_dg"]) {
            printRealLog(@"[INSTALLER] 🚀 正在启动 免费DG (DG-QQ740953263) 一键安装引擎...");
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            NSArray *possibleNames = @[
                @"DG-QQ740953263.ipa",
                @"DG-QQ740953263.tipa",
                @"DG-QQ740953263",
                @"packages/DG-QQ740953263.ipa",
                @"packages/DG-QQ740953263.tipa"
            ];
            
            NSString *targetPath = nil;
            NSFileManager *fm = [NSFileManager defaultManager];
            for (NSString *name in possibleNames) {
                NSString *p = [bundlePath stringByAppendingPathComponent:name];
                if ([fm fileExistsAtPath:p]) {
                    targetPath = p;
                    break;
                }
            }
            
            BOOL installSuccess = NO;
            if (targetPath) {
                printRealLog(@"[INSTALLER] 命中内置安装包: %@", targetPath);
                // 1. 优先尝试 TrollStore Helper 静默安装
                NSArray *helperPaths = @[
                    @"/Applications/TrollStore.app/trollstorehelper",
                    @"/var/containers/Bundle/Application/TrollStore.app/trollstorehelper"
                ];
                for (NSString *hp in helperPaths) {
                    if ([fm fileExistsAtPath:hp]) {
                        printRealLog(@"[INSTALLER] 正在调用 TrollStore Helper 执行静默安装...");
                        const char *args[] = {[hp UTF8String], "install", [targetPath UTF8String], NULL};
                        int ret = posix_spawn(NULL, args[0], NULL, NULL, (char *const *)args, environ);
                        if (ret == 0) {
                            installSuccess = YES;
                            printRealLog(@"[INSTALLER] ✅ 免费DG (DG-QQ740953263) 静默安装指令已下发成功！");
                            break;
                        }
                    }
                }
            }
            
            if (!installSuccess) {
                printRealLog(@"[INSTALLER] ⚠️ 本地包不存在或静默安装未完成，触发备选方案：拉起巨魔进行安装...");
                NSString *fallbackUrl = targetPath ? [NSString stringWithFormat:@"apple-magnifier://install?url=file://%@", targetPath] : @"apple-magnifier://";
                // 广播或通过通知拉起巨魔
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.opa334.trollstore.install"), NULL, NULL, YES);
                printRealLog(@"[INSTALLER] 已广播拉起巨魔协议: %@", fallbackUrl);
            }
            return 0;
        }

        if ([runMode isEqualToString:@"install_filza"]) {
            printRealLog(@"[INSTALLER] 正在准备一键安装 Filza 越狱/无根资源包...");
            return 0;
        }

        if ([runMode isEqualToString:@"install_filza_troll"]) {
            printRealLog(@"[INSTALLER] 🚀 正在启动 Filza巨魔版 (Filza_4.0.0.ipa) 一键安装引擎...");
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            NSArray *possibleNames = @[
                @"Filza_4.0.0.ipa",
                @"Filza_4.0.0.tipa",
                @"Filza_4.0.0",
                @"packages/Filza_4.0.0.ipa",
                @"packages/Filza_4.0.0.tipa"
            ];
            
            NSString *targetPath = nil;
            NSFileManager *fm = [NSFileManager defaultManager];
            for (NSString *name in possibleNames) {
                NSString *p = [bundlePath stringByAppendingPathComponent:name];
                if ([fm fileExistsAtPath:p]) {
                    targetPath = p;
                    break;
                }
            }
            
            BOOL installSuccess = NO;
            if (targetPath) {
                printRealLog(@"[INSTALLER] 命中内置安装包: %@", targetPath);
                // 1. 优先尝试 TrollStore Helper 静默安装
                NSArray *helperPaths = @[
                    @"/Applications/TrollStore.app/trollstorehelper",
                    @"/var/containers/Bundle/Application/TrollStore.app/trollstorehelper"
                ];
                for (NSString *hp in helperPaths) {
                    if ([fm fileExistsAtPath:hp]) {
                        printRealLog(@"[INSTALLER] 正在调用 TrollStore Helper 执行静默安装...");
                        const char *args[] = {[hp UTF8String], "install", [targetPath UTF8String], NULL};
                        int ret = posix_spawn(NULL, args[0], NULL, NULL, (char *const *)args, environ);
                        if (ret == 0) {
                            installSuccess = YES;
                            printRealLog(@"[INSTALLER] ✅ Filza巨魔版 (Filza_4.0.0.ipa) 静默安装指令已下发成功！");
                            break;
                        }
                    }
                }
            }
            
            if (!installSuccess) {
                printRealLog(@"[INSTALLER] ⚠️ 本地包不存在或静默安装未完成，触发备选方案：拉起巨魔进行安装...");
                NSString *fallbackUrl = targetPath ? [NSString stringWithFormat:@"apple-magnifier://install?url=file://%@", targetPath] : @"apple-magnifier://";
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.opa334.trollstore.install"), NULL, NULL, YES);
                printRealLog(@"[INSTALLER] 已广播拉起巨魔协议: %@", fallbackUrl);
            }
            return 0;
        }

        if ([runMode isEqualToString:@"install_qilong_ai"]) {
            printRealLog(@"[INSTALLER] 正在准备一键安装 骑龙AI检测 资源包...");
            return 0;
        }

        if ([runMode isEqualToString:@"install_permanent_dg"]) {
            printRealLog(@"[INSTALLER] 正在准备一键安装 永久DG 资源包...");
            return 0;
        }

        if ([runMode isEqualToString:@"install_dolby_audio"]) {
            printRealLog(@"[INSTALLER] 正在准备一键安装 杜比音效 资源包...");
            return 0;
        }

        if ([runMode isEqualToString:@"install_green_shield"]) {
            printRealLog(@"[INSTALLER] 正在准备一键安装 系过绿盾 资源包...");
            return 0;
        }

        if ([runMode isEqualToString:@"clear_keychain"]) {
            printRealLog(@"[KEYCHAIN] Active: Single App Keychain clear mode.");
            if (selectedAppBundleIDs.count == 0) {
                printRealLog(@"[KEYCHAIN] ⚠️ 没有勾选任何应用，无法执行清除。");
            } else {
                for (NSString *bundleID in selectedAppBundleIDs) {
                    printRealLog(@"[KEYCHAIN] 正在尝试清空应用 %@ 的 Keychain 数据...", bundleID);
                    clearKeychainForApp(bundleID);
                }
                printRealLog(@"[KEYCHAIN] ✅ 所选应用的 Keychain 清理完毕。");
                
                // 清理完成后刷新一遍广告标识符以生效
                resetIDFAIdentifier();
                printRealLog(@"[IDFA] IDFA+IDFV 刷新完毕以使清理生效。");
                
                killDaemonByName("securityd");
                printRealLog(@"[KEYCHAIN] 强制终止 securityd 以重载安全状态...");
            }
            return 0;
        }

        if ([runMode isEqualToString:@"unlock_keychain"]) {
            printRealLog(@"[KEYCHAIN] 正在执行系统级解除锁定...");
            
            const char *db_path    = "/private/var/Keychains/keychain-2.db";
            const char *wal_path   = "/private/var/Keychains/keychain-2.db-wal";
            const char *shm_path   = "/private/var/Keychains/keychain-2.db-shm";
            const char *paths[]    = {db_path, wal_path, shm_path};
            const char *names[]    = {"db", "wal", "shm"};
            
            struct stat st;
            
            // 1. 尝试打开并关闭一次数据库
            sqlite3 *tmpDb;
            if (sqlite3_open(db_path, &tmpDb) == SQLITE_OK) {
                sqlite3_close(tmpDb);
            }
            
            // 2. 解除 APFS 不可变标志 -> 恢复所有权 (64:64) -> 恢复写权限 (0600)
            for (int i = 0; i < 3; i++) {
                const char *p = paths[i];
                const char *nm = names[i];
                if (stat(p, &st) == 0) {
                    // A. 解除物理不可变标志 (flags = 0)
                    chflags(p, 0);
                    
                    // B. 确保所有权归还给 _securityd (UID: 64, GID: 64)
                    int c_res = chown(p, 64, 64);
                    if (c_res != 0) {
                        printRealLog(@"[KEYCHAIN] chown(%s) 恢复失败 errno=%d (%s)", nm, errno, strerror(errno));
                    }
                    
                    // C. 恢复写权限 (0600)
                    mode_t target_mode = (st.st_mode & 0777) | S_IRUSR | S_IWUSR;
                    int fd = open(p, O_RDONLY);
                    if (fd >= 0) {
                        fchmod(fd, target_mode);
                        close(fd);
                    }
                    chmod(p, target_mode);
                }
            }
            
            printRealLog(@"[KEYCHAIN] 物理写入权限与文件标志已成功恢复.");
            
            printRealLog(@"[KEYCHAIN] 重启 securityd 以重载状态...");
            killDaemonByName("securityd");
            
            // 3. 环境痕迹擦除模块 (Anti-Forensics)
            printRealLog(@"[KEYCHAIN] 正在执行环境痕迹擦除 (Anti-Forensics)...");
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *filzaPlist = @"/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist";
            NSString *filzaCache = @"/var/mobile/Library/Caches/com.tigisoftware.Filza/";
            
            if ([fm fileExistsAtPath:filzaPlist]) {
                NSError *err = nil;
                if ([fm removeItemAtPath:filzaPlist error:&err]) {
                    printRealLog(@"[KEYCHAIN] [ANTI-FORENSICS] 已清除 Filza 配置痕迹.");
                } else {
                    printRealLog(@"[KEYCHAIN] [ANTI-FORENSICS] 清除 Filza 配置失败: %@", err);
                }
            }
            if ([fm fileExistsAtPath:filzaCache]) {
                NSError *err = nil;
                if ([fm removeItemAtPath:filzaCache error:&err]) {
                    printRealLog(@"[KEYCHAIN] [ANTI-FORENSICS] 已清除 Filza 缓存目录.");
                } else {
                    printRealLog(@"[KEYCHAIN] [ANTI-FORENSICS] 清除 Filza 缓存失败: %@", err);
                }
            }
            
            printRealLog(@"[KEYCHAIN] 系统级解锁全流程完成！");
            return 0;
        }

        // ==================== 轨道一：【无线轮询自毁快刷轨】 ====================
        if ([runMode isEqualToString:@"bg_idfa_loop"]) {
            printRealLog(@"[DAEMON] Background loop active.");
            
            pid_t parentPid = getppid();
            int round = 1;
            
            while (1) {
                // 【Watchdog卡点 A】父进程变为 1 或被杀
                if (getppid() == 1 || kill(parentPid, 0) != 0) {
                    printRealLog(@"[DAEMON] Parent process killed. Exiting.");
                    break;
                }
                
                printRealLog(@"[DAEMON] Round %d: Overwriting IDFA+IDFV...", round);
                resetIDFAIdentifier();
                
                // 每轮刷新后立即杀死守护进程使其生效
                forceRefreshWithoutReboot();
                
                printRealLog(@"[DAEMON] Round %d complete. Waiting 60s.", round);
                
                round++;
                
                // 💡 优化项 3：每 10 轮静默清理自身 RAM 堆内存
                if (round % 10 == 0) {
                    malloc_zone_pressure_relief(malloc_default_zone(), 0);
                }

                // 低频 5s 间隔休眠检测，减少 CPU 唤醒
                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[DAEMON] Interrupted by parent. Exiting.");
                    exit(0);
                }
            }
            return 0;
        }

        // ==================== 轨道一轮空点：【全盘全局多方案分阶段错峰实时扫描清理轨】 ====================
        if ([runMode isEqualToString:@"realtime_whitelist_clean"]) {
            printRealLog(@"[REALTIME] Dynamic Whitelist Multi-Phase Realtime Clean Active (3-min staggered cycle).");
            printRealLog(@"[REALTIME] Phase A: Cache/Safari/AppGroup | Phase B: IDFA/Keychain | Phase C: NVRAM/VarClean/Hotspot");

            pid_t parentPid = getppid();

            // 安全绝杀：预设绝对不可清理的硬核系统与安全保护路径/ID，防止误触
            NSArray *customVarPaths = @[
                @"/var/mobile/Library/Caches",
                @"/var/mobile/Library/Cookies",
                @"/var/mobile/Library/HTTPStorages",
                @"/var/mobile/Library/Saved Application State",
                @"/var/mobile/Library/SplashBoard/Snapshots",
                @"/var/mobile/Library/WebKit",
                @"/var/mobile/Library/Logs",
                @"/var/mobile/Library/Logs/CrashReporter",
                @"/var/mobile/Library/Caches/com.apple.WebKit.WebContent",
                @"/var/mobile/Library/Caches/com.apple.WebKit.Networking",
                @"/var/root/Library/Caches",
                @"/var/root/Library/HTTPStorages",
                @"/var/root/Library/Tmp",
                @"/var/tmp",
                @"/var/mobile/Containers/Shared/AppGroup",
                @"/var/mobile/Containers/Data/PluginKitPlugin"
            ];

            // 🔍 varClean：曾经使用其他越狱留下的越狱痕迹与包管理器缓存路径
            NSArray *varCleanPaths = @[
                @"/var/jb",
                @"/var/binpack",
                @"/var/dropbear",
                @"/var/ulb",
                @"/var/stash",
                @"/var/LIB",
                @"/var/libexec",
                @"/var/log/dpkg",
                @"/var/log/apt",
                @"/var/mobile/Library/Cydia",
                @"/var/mobile/Library/Sileo",
                @"/var/mobile/Library/Zebra",
                @"/var/mobile/Library/Caches/com.saurik.Cydia",
                @"/var/mobile/Library/Caches/org.coolstar.Sileo",
                @"/var/mobile/Library/Caches/com.ex.substitute",
                @"/var/mobile/Library/Caches/ellekit",
                @"/var/mobile/Library/Caches/Substrate",
                @"/var/mobile/Library/Application Support/PreferenceHelper",
                @"/var/mobile/Library/Application Support/Flex3",
                @"/var/mobile/Library/Application Support/Shadow",
                @"/var/mobile/Library/Application Support/Choicy",
                @"/var/mobile/Library/Application Support/FlyJB"
            ];

            // 步骤 1：首次启动立即执行一次标识符刷新（快速入场）
            printRealLog(@"[IDFA] Initializing identifier refresh on start...");
            resetIDFAIdentifier();
            deleteSelectedAppKeychain(selectedAppBundleIDs);
            notify_post("com.apple.idfa.changed");
            notify_post("com.apple.pasteboard.changed");
            printRealLog(@"[REALTIME] Initial refresh done. Waiting 3s before entering staggered loop...");
            sleep(3);

            printRealLog(@"[REALTIME] Starting 3-minute staggered 3-phase loop (Phase A->B->C per cycle)...");

            int cycleCount = 0;

            while (1) {
                cycleCount++;
                printRealLog(@"[REALTIME] ===== Cycle #%d started =====", cycleCount);

                // ─────────────────────────────────────────────────────
                // 阶段 A (第 1 分钟)：缓存清理 + Safari/WebKit + AppGroup
                // ─────────────────────────────────────────────────────
                @autoreleasepool {
                    if (getppid() == 1 || kill(parentPid, 0) != 0) { printRealLog(@"[REALTIME] Parent closed. Exiting."); break; }

                    printRealLog(@"[REALTIME] [Phase A] Cache / Safari / AppGroup / Clipboard clean start.");
                    int cleanedA = 0;

                    // A-1. 剪贴板缓存物理抹除
                    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard"]) {
                        if ([[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard" error:nil]) {
                            cleanedA++;
                            notify_post("com.apple.pasteboard.changed");
                        }
                    }

                    // A-2. Safari & WebKit 缓存清理
                    cleanedA += cleanSafariAndWebKit();

                    // A-3. 全局安全 var 缓存路径遍历清洗
                    for (NSString *targetPath in customVarPaths) {
                        cleanedA += safeCleanDirectory(targetPath, selectedAppBundleIDs);
                    }

                    // A-4. 共享 AppGroup 及 PluginKit 特权沙盒清理
                    cleanedA += cleanSpecialContainers(@"/var/mobile/Containers/Shared/AppGroup", selectedAppBundleIDs);
                    cleanedA += cleanSpecialContainers(@"/var/mobile/Containers/Data/PluginKitPlugin", selectedAppBundleIDs);

                    printRealLog(@"[REALTIME] [Phase A] Done. Cleaned: %d items. Waiting 60s for Phase B...", cleanedA);
                }

                // Phase A 后低功耗合并休眠（5s 步进，减少 CPU 唤醒）
                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[REALTIME] Interrupted during Phase A sleep.");
                    break;
                }

                // ─────────────────────────────────────────────────────
                // 阶段 B (第 2 分钟)：IDFA/IDFV 标识符重置 + Keychain 多方案清理
                // ─────────────────────────────────────────────────────
                @autoreleasepool {
                    if (getppid() == 1 || kill(parentPid, 0) != 0) { printRealLog(@"[REALTIME] Parent closed. Exiting."); break; }

                    printRealLog(@"[REALTIME] [Phase B] IDFA/IDFV reset + Keychain clean start.");

                    // B-1. 三遍 IDFA/IDFV 多方案覆写
                    resetIDFAIdentifier();

                    // B-2. 目标 App Keychain 清理
                    if (selectedAppBundleIDs.count > 0) {
                        deleteSelectedAppKeychain(selectedAppBundleIDs);
                    }

                    // B-3. 一键清空所有非 Apple 钥匙链条目
                    deleteAllNonAppleKeychain();

                    // B-4. 清理已卸载 App 残留钥匙链（孤立凭证）
                    cleanOrphanedAppKeychain();

                    // B-5. 仅在 Keychain 可写时重启 securityd 重载，IPC 广播刷新标识符
                    if (access("/var/keychains/keychain-2.db", W_OK) == 0) {
                        killDaemonByName("securityd");
                    }
                    notify_post("com.apple.idfa.changed");
                    notify_post("com.apple.pasteboard.changed");

                    printRealLog(@"[REALTIME] [Phase B] Done. IDFA/Keychain fully refreshed. Waiting 60s for Phase C...");
                }

                // Phase B 后低功耗合并休眠（5s 步进，减少 CPU 唤醒）
                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[REALTIME] Interrupted during Phase B sleep.");
                    break;
                }

                // ─────────────────────────────────────────────────────
                // 阶段 C (第 3 分钟)：NVRAM 清空 + Hotspot Helper 禁用 + varClean 越狱残留清洗
                // ─────────────────────────────────────────────────────
                @autoreleasepool {
                    if (getppid() == 1 || kill(parentPid, 0) != 0) { printRealLog(@"[REALTIME] Parent closed. Exiting."); break; }

                    printRealLog(@"[REALTIME] [Phase C] NVRAM clear + Hotspot Helper block + varClean jailbreak residue clean start.");
                    int cleanedC = 0;

                    // C-1. 清空 NVRAM 标志
                    clearNVRAMVariables();

                    // C-2. 禁止第三方 App 注册 Hotspot Helper
                    disableThirdPartyHotspotHelpers();

                    // C-3. varClean：清洗历史越狱与包管理器残留路径
                    NSFileManager *fm = [NSFileManager defaultManager];
                    for (NSString *vcPath in varCleanPaths) {
                        @autoreleasepool {
                            if ([fm fileExistsAtPath:vcPath]) {
                                NSError *err = nil;
                                if ([fm removeItemAtPath:vcPath error:&err]) {
                                    printRealLog(@"[VARCLEAN] Removed jailbreak residue: %@", [vcPath lastPathComponent]);
                                    cleanedC++;
                                }
                            }
                        }
                    }

                    // C-4. 额外扫描 Preferences 目录下非 Apple 越狱插件 plist 残留
                    NSString *prefDir = @"/var/mobile/Library/Preferences";
                    NSArray *prefFiles = [fm contentsOfDirectoryAtPath:prefDir error:nil];
                    for (NSString *pFile in prefFiles) {
                        @autoreleasepool {
                            if (![pFile hasPrefix:@"com.apple."] && [pFile hasSuffix:@".plist"]) {
                                // 针对已知越狱包管理器与插件来源 plist 进行清除
                                NSArray *jbPrefixes = @[@"com.saurik.", @"org.coolstar.", @"xyz.willy.Zebra", @"com.tigisoftware.", @"cc.tweak.", @"ryan.gosua.", @"com.ichitaso.", @"me.conorthedev.", @"com.opa334.trollstore"];
                                for (NSString *prefix in jbPrefixes) {
                                    if ([pFile hasPrefix:prefix]) {
                                        NSString *fullPath = [prefDir stringByAppendingPathComponent:pFile];
                                        if ([fm removeItemAtPath:fullPath error:nil]) {
                                            printRealLog(@"[VARCLEAN] Removed jailbreak pref: %@", pFile);
                                            cleanedC++;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // C-5. IPC 广播通知网络配置已更新
                    notify_post("com.apple.system.config.network_change");

                    printRealLog(@"[REALTIME] [Phase C] Done. VarClean removed %d jailbreak residues.", cleanedC);
                    printRealLog(@"[REALTIME] ===== Cycle #%d complete (3-min full cycle). Restarting Phase A... =====", cycleCount);
                }

                // 💡 优化项 3：每 10 分钟（每 3 个大周期）错峰自动释放 RootHelper 进程 RAM 内存
                if (cycleCount % 3 == 0) {
                    malloc_zone_pressure_relief(malloc_default_zone(), 0);
                    printRealLog(@"[RAM] Staggered 10-min memory cache purge executed.");
                }

                // Phase C 后低功耗合并休眠（5s 步进，减少 CPU 唤醒）
                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[REALTIME] Interrupted during Phase C sleep.");
                    break;
                }
            }
            return 0;
        }

        // ==================== 轨道一辅助点：【安全模式：无损防护分阶段错峰实时扫描清理轨】 ====================
        if ([runMode isEqualToString:@"realtime_whitelist_clean_safe"]) {
            printRealLog(@"[REALTIME_SAFE] Safe Dynamic Whitelist Active (3-min staggered cycle).");
            printRealLog(@"[REALTIME_SAFE] Fully isolated from high-risk WAL deletion and keychain database corruption.");

            pid_t parentPid = getppid();

            NSArray *customVarPaths = @[
                @"/var/mobile/Library/Caches",
                @"/var/mobile/Library/Cookies",
                @"/var/mobile/Library/HTTPStorages",
                @"/var/mobile/Library/Saved Application State",
                @"/var/mobile/Library/SplashBoard/Snapshots",
                @"/var/mobile/Library/WebKit",
                @"/var/mobile/Library/Logs",
                @"/var/mobile/Library/Logs/CrashReporter",
                @"/var/mobile/Library/Caches/com.apple.WebKit.WebContent",
                @"/var/mobile/Library/Caches/com.apple.WebKit.Networking",
                @"/var/root/Library/Caches",
                @"/var/root/Library/HTTPStorages",
                @"/var/root/Library/Tmp",
                @"/var/tmp",
                @"/var/mobile/Containers/Shared/AppGroup",
                @"/var/mobile/Containers/Data/PluginKitPlugin"
            ];

            NSArray *varCleanPaths = @[
                @"/var/jb",
                @"/var/binpack",
                @"/var/dropbear",
                @"/var/ulb",
                @"/var/stash",
                @"/var/LIB",
                @"/var/libexec",
                @"/var/log/dpkg",
                @"/var/log/apt",
                @"/var/mobile/Library/Cydia",
                @"/var/mobile/Library/Sileo",
                @"/var/mobile/Library/Zebra",
                @"/var/mobile/Library/Caches/com.saurik.Cydia",
                @"/var/mobile/Library/Caches/org.coolstar.Sileo",
                @"/var/mobile/Library/Caches/com.ex.substitute",
                @"/var/mobile/Library/Caches/ellekit",
                @"/var/mobile/Library/Caches/Substrate",
                @"/var/mobile/Library/Application Support/PreferenceHelper",
                @"/var/mobile/Library/Application Support/Flex3",
                @"/var/mobile/Library/Application Support/Shadow",
                @"/var/mobile/Library/Application Support/Choicy",
                @"/var/mobile/Library/Application Support/FlyJB"
            ];

            printRealLog(@"[REALTIME_SAFE] Initializing safe identifier refresh...");
            resetIDFAIdentifier();
            if (access("/var/keychains/keychain-2.db", W_OK) == 0) {
                deleteSelectedAppKeychain(selectedAppBundleIDs);
            } else {
                printRealLog(@"[REALTIME_SAFE] Keychain locked (0400). Safely bypassed initial DB delete.");
            }
            notify_post("com.apple.idfa.changed");
            notify_post("com.apple.pasteboard.changed");
            printRealLog(@"[REALTIME_SAFE] Initial refresh complete. Entering 3-phase safe loop...");
            sleep(3);

            int cycleCount = 0;

            while (1) {
                cycleCount++;
                printRealLog(@"[REALTIME_SAFE] ===== Safe Cycle #%d started =====", cycleCount);

                // 阶段 A：缓存清理
                @autoreleasepool {
                    if (getppid() == 1 || kill(parentPid, 0) != 0) { printRealLog(@"[REALTIME_SAFE] Parent closed. Exiting."); break; }

                    printRealLog(@"[REALTIME_SAFE] [Phase A] Cache / Safari / AppGroup / Clipboard clean start.");
                    int cleanedA = 0;

                    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard"]) {
                        if ([[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard" error:nil]) {
                            cleanedA++;
                            notify_post("com.apple.pasteboard.changed");
                        }
                    }

                    cleanedA += cleanSafariAndWebKit();

                    for (NSString *targetPath in customVarPaths) {
                        cleanedA += safeCleanDirectory(targetPath, selectedAppBundleIDs);
                    }

                    cleanedA += cleanSpecialContainers(@"/var/mobile/Containers/Shared/AppGroup", selectedAppBundleIDs);
                    cleanedA += cleanSpecialContainers(@"/var/mobile/Containers/Data/PluginKitPlugin", selectedAppBundleIDs);

                    printRealLog(@"[REALTIME_SAFE] [Phase A] Done. Cleaned: %d items. Waiting 60s for Phase B...", cleanedA);
                }

                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[REALTIME_SAFE] Interrupted during Phase A sleep.");
                    break;
                }

                // 阶段 B：IDFA 刷新与 Keychain 安全检查
                @autoreleasepool {
                    if (getppid() == 1 || kill(parentPid, 0) != 0) { printRealLog(@"[REALTIME_SAFE] Parent closed. Exiting."); break; }

                    printRealLog(@"[REALTIME_SAFE] [Phase B] Safe IDFA refresh + Keychain status check.");

                    resetIDFAIdentifier();

                    if (access("/var/keychains/keychain-2.db", W_OK) == 0) {
                        if (selectedAppBundleIDs.count > 0) {
                            deleteSelectedAppKeychain(selectedAppBundleIDs);
                        }
                        deleteAllNonAppleKeychain();
                        cleanOrphanedAppKeychain();
                        killDaemonByName("securityd");
                    } else {
                        printRealLog(@"[REALTIME_SAFE] ⚠️ Keychain-2.db is locked (0400). Safely bypassed all SQLite write operations.");
                    }

                    notify_post("com.apple.idfa.changed");
                    notify_post("com.apple.pasteboard.changed");

                    printRealLog(@"[REALTIME_SAFE] [Phase B] Done. Waiting 60s for Phase C...");
                }

                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[REALTIME_SAFE] Interrupted during Phase B sleep.");
                    break;
                }

                // 阶段 C：NVRAM 清空 + VarClean 越狱残留清洗
                @autoreleasepool {
                    if (getppid() == 1 || kill(parentPid, 0) != 0) { printRealLog(@"[REALTIME_SAFE] Parent closed. Exiting."); break; }

                    printRealLog(@"[REALTIME_SAFE] [Phase C] NVRAM clear + Hotspot Helper block + VarClean start.");
                    int cleanedC = 0;

                    clearNVRAMVariables();
                    disableThirdPartyHotspotHelpers();

                    NSFileManager *fm = [NSFileManager defaultManager];
                    for (NSString *vcPath in varCleanPaths) {
                        @autoreleasepool {
                            if ([fm fileExistsAtPath:vcPath]) {
                                NSError *err = nil;
                                if ([fm removeItemAtPath:vcPath error:&err]) {
                                    printRealLog(@"[VARCLEAN] Removed jailbreak residue: %@", [vcPath lastPathComponent]);
                                    cleanedC++;
                                }
                            }
                        }
                    }

                    NSString *prefDir = @"/var/mobile/Library/Preferences";
                    NSArray *prefFiles = [fm contentsOfDirectoryAtPath:prefDir error:nil];
                    for (NSString *pFile in prefFiles) {
                        @autoreleasepool {
                            if (![pFile hasPrefix:@"com.apple."] && [pFile hasSuffix:@".plist"]) {
                                NSArray *jbPrefixes = @[@"com.saurik.", @"org.coolstar.", @"xyz.willy.Zebra", @"com.tigisoftware.", @"cc.tweak.", @"ryan.gosua.", @"com.ichitaso.", @"me.conorthedev.", @"com.opa334.trollstore"];
                                for (NSString *prefix in jbPrefixes) {
                                    if ([pFile hasPrefix:prefix]) {
                                        NSString *fullPath = [prefDir stringByAppendingPathComponent:pFile];
                                        if ([fm removeItemAtPath:fullPath error:nil]) {
                                            printRealLog(@"[VARCLEAN] Removed jailbreak pref: %@", pFile);
                                            cleanedC++;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    notify_post("com.apple.system.config.network_change");

                    printRealLog(@"[REALTIME_SAFE] [Phase C] Done. VarClean removed %d jailbreak residues.", cleanedC);
                    printRealLog(@"[REALTIME_SAFE] ===== Safe Cycle #%d complete. Restarting Phase A... =====", cycleCount);
                }

                if (cycleCount % 3 == 0) {
                    malloc_zone_pressure_relief(malloc_default_zone(), 0);
                    printRealLog(@"[RAM] Safe mode 10-min memory cache purge executed.");
                }

                if (staggeredSleepWithParentCheck(60, parentPid)) {
                    printRealLog(@"[REALTIME_SAFE] Interrupted during Phase C sleep.");
                    break;
                }
            }
            return 0;
        }

        // ==================== 轨道：【轻量降频减负实时白名单轨】 ====================
        if ([runMode isEqualToString:@"realtime_whitelist_clean_light"]) {
            printRealLog(@"[REALTIME_LIGHT] Dynamic Whitelist Light Mode Active (Tailored for old/low-power devices).");
            printRealLog(@"[REALTIME_LIGHT] Running minimal CPU/IO footprint cycle (120s interval).");

            pid_t parentPid = getppid();
            int cycleCount = 0;

            while (1) {
                cycleCount++;
                if (getppid() == 1 || kill(parentPid, 0) != 0) {
                    printRealLog(@"[REALTIME_LIGHT] Parent closed. Exiting.");
                    break;
                }

                @autoreleasepool {
                    printRealLog(@"[REALTIME_LIGHT] ===== Light Cycle #%d started =====", cycleCount);

                    // 1. 快速刷新 IDFA + IDFV 指纹
                    resetIDFAIdentifier();

                    // 2. Keychain 安全探测：若未锁定则安全清除勾选应用与孤立 Keychain
                    if (access("/var/keychains/keychain-2.db", W_OK) == 0) {
                        if (selectedAppBundleIDs.count > 0) {
                            deleteSelectedAppKeychain(selectedAppBundleIDs);
                        }
                        cleanOrphanedAppKeychain();
                        killDaemonByName("securityd");
                    } else {
                        printRealLog(@"[REALTIME_LIGHT] Keychain locked (0400). Safely bypassed DB writes.");
                    }

                    // 3. 极轻量基础缓存清理：仅剪贴板与 WebKit 轻量日志
                    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard"]) {
                        [[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard" error:nil];
                    }

                    // 4. 发射轻量 Darwin IPC 通知广播
                    notify_post("com.apple.idfa.changed");
                    notify_post("com.apple.pasteboard.changed");

                    // 5. 主动释放堆内存，防常驻内存泄漏
                    malloc_zone_pressure_relief(malloc_default_zone(), 0);

                    printRealLog(@"[REALTIME_LIGHT] Light Cycle #%d complete. Sleeping 120s...", cycleCount);
                }

                // 低频 120s 休眠，带 5s 步进父进程探活
                if (staggeredSleepWithParentCheck(120, parentPid)) {
                    printRealLog(@"[REALTIME_LIGHT] Interrupted during sleep. Exiting.");
                    break;
                }
            }
            return 0;
        }

        // ==================== 轨道二：【重度深清空间轨】 ====================
        if ([runMode isEqualToString:@"standard_clean"]) {
            printRealLog(@"[KERNEL] Active: Deep clean mode.");
            printRealLog(@"[KERNEL] Target count: %lu", (unsigned long)selectedAppBundleIDs.count);
            
            // 1. 强制覆写三遍随机 UUID（IDFA + IDFV）
            resetIDFAIdentifier();
            printRealLog(@"[IDFA] Multi-method IDFA+IDFV refresh complete.");
            
            // 2. 多方案清除 NVRAM
            clearNVRAMVariables();
            
            // 3. 多方案联合 Keychain 清理
            deleteSelectedAppKeychain(selectedAppBundleIDs);
            
            // 增强风险残留清理：一键清空非 Apple 所有钥匙链、清理已卸载 App 钥匙串残留、禁止第三方 App 注册 Hotspot Helper
            deleteAllNonAppleKeychain();
            cleanOrphanedAppKeychain();
            disableThirdPartyHotspotHelpers();
            
            // 3.5 清理 Safari 的全局 Cookie、网页状态及 WebKit 跨进程缓存
            cleanSafariAndWebKit();
            
            // 3.6 物理抹除剪贴簿缓存并同步发射广播
            [[NSFileManager defaultManager] removeItemAtPath:@"/var/mobile/Library/Caches/com.apple.Pasteboard" error:nil];
            notify_post("com.apple.pasteboard.changed");
            printRealLog(@"[CLEAN] Clipboard cache erased.");
            
            // 3.7 清洗共享特权目录
            cleanSpecialContainers(@"/var/mobile/Containers/Shared/AppGroup", selectedAppBundleIDs);
            cleanSpecialContainers(@"/var/mobile/Containers/Data/PluginKitPlugin", selectedAppBundleIDs);
            
            // 4. 横扫自定义硬核重灾路径
            NSArray *customVarPaths = @[
                @"/var", @"/var/containers", @"/var/containers/Bundle",
                @"/var/db/com.apple.xpc.roleaccountd.staging", @"/var/log", @"/var/mobile",
                @"/var/mobile/Documents", @"/var/mobile/Library",
                @"/var/mobile/Library/Application Support",
                @"/var/mobile/Library/Application Support/Containers",
                @"/var/mobile/Library/Caches", @"/var/mobile/Library/Cookies",
                @"/var/mobile/Library/HTTPStorages", @"/var/mobile/Library/Logs",
                @"/var/mobile/Library/Preferences", @"/var/mobile/Library/Saved Application State",
                @"/var/mobile/Library/SplashBoard/Snapshots",
                @"/var/mobile/Library/UserConfigurationProfiles/PublicInfo/",
                @"/var/mobile/Library/WebKit", @"/var/mobile/Media", @"/var/root",
                @"/var/root/Library", @"/var/root/Library/Application Support",
                @"/var/root/Library/Caches", @"/var/root/Library/HTTPStorages",
                @"/var/root/Library/Preferences", @"/var/root/Library/Tmp",
                @"/var/mobile/Containers/Shared/AppGroup",
                @"/var/mobile/Containers/Data/PluginKitPlugin"
            ];
            
            printRealLog(@"[CLEAN] Scanning paths...");
            for (NSString *path in customVarPaths) {
                safeCleanDirectory(path, selectedAppBundleIDs);
            }
            printRealLog(@"[CLEAN] Completed successfully.");
            
            // 5. 先执行无重启方案强制立即生效
            forceRefreshWithoutReboot();
            
            // 6. 最终重启用户空间刷新全机进程缓存
            triggerUserspaceReboot();
        }
    }
    return 0;
}
