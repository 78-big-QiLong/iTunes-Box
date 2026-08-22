#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <spawn.h>
#import <sys/wait.h>
#import <signal.h>
#import <unistd.h>
#import <malloc/malloc.h>
#import <CoreLocation/CoreLocation.h>
#import <dlfcn.h>
#import "DeviceInfo.h"

// ── 状态机：持久化记录锁定状态，用于崩溃自愈 ──
static NSString* getLockStatePath() {
    return [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject] stringByAppendingPathComponent:@"lock_state.json"];
}
static void writeLockState(BOOL locked) {
    NSDictionary *dict = @{@"locked": @(locked)};
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    [data writeToFile:getLockStatePath() atomically:YES];
}
static BOOL readLockState() {
    NSData *data = [NSData dataWithContentsOfFile:getLockStatePath()];
    if (data) {
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        return [dict[@"locked"] boolValue];
    }
    return NO;
}

// ── 核心：免声明动态绑定 iOS 底层私有应用管理服务 ──
@interface NSObject (LSApplicationWorkspace_Private)
+ (id)defaultWorkspace;
- (NSArray *)allInstalledApplications;
- (BOOL)openURL:(NSURL *)url;
@end

@interface NSObject (LSApplicationProxy_Private)
- (NSString *)applicationIdentifier;
- (NSString *)localizedName;
- (NSString *)applicationType;
@end

// 【自锁开关闸】锁定后台 IDFA 轮询进程 PID，接通单按钮状态机
static pid_t global_bg_idfa_pid = 0;
static pid_t global_bg_idfa_safe_pid = 0;
static pid_t global_bg_idfa_light_pid = 0;

@interface ViewController : UIViewController <WKScriptMessageHandler, WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
- (pid_t)executeRootHelperWithMode:(NSString *)mode selectedApps:(NSArray *)selectedApps;
@end

// ── ZeroTrustd 企业级应用诊断生命周期调度器 ──
@interface ZeroTrustdScheduler : NSObject
@property (nonatomic, copy) NSString *targetBundleID;
@property (nonatomic, weak) ViewController *viewController;
- (instancetype)initWithBundleID:(NSString *)bundleID viewController:(ViewController *)vc;
- (void)startScheduler;
@end

@implementation ZeroTrustdScheduler

- (instancetype)initWithBundleID:(NSString *)bundleID viewController:(ViewController *)vc {
    self = [super init];
    if (self) {
        _targetBundleID = [bundleID copy];
        _viewController = vc;
    }
    return self;
}

- (void)startScheduler {
    NSLog(@"[ZeroTrustd] Starting scheduler for bundleID: %@", self.targetBundleID);
    [self logToWebView:[NSString stringWithFormat:@"[ZeroTrustd] 启动诊断调度器 (Target: %@)...", self.targetBundleID] level:@"system"];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self stage1_isolation];
    });
}

- (void)stage1_isolation {
    [self logToWebView:@"[ZeroTrustd] Stage 1: 执行底层隔离策略 (Keychain, DB 锁, 网络隔离, App 唤起)..." level:@"warn"];
    
    if (self.viewController) {
        [self.viewController executeRootHelperWithMode:@"diag_stage1" selectedApps:@[self.targetBundleID]];
    }
    
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    if (workspaceClass) {
        @try {
            id workspace = [workspaceClass performSelector:@selector(defaultWorkspace)];
            SEL selector = NSSelectorFromString(@"openApplicationWithBundleID:");
            if ([workspace respondsToSelector:selector]) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                [workspace performSelector:selector withObject:self.targetBundleID];
                #pragma clang diagnostic pop
            }
        } @catch (NSException *e) {
            NSLog(@"[ZeroTrustd] Launch app failed: %@", e);
        }
    }
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self stage2_observation];
    });
}

- (void)stage2_observation {
    [self logToWebView:@"[ZeroTrustd] Stage 2: 正在收集运行期快照与存储观察..." level:@"system"];
    
    if (self.viewController) {
        [self.viewController executeRootHelperWithMode:@"diag_stage2" selectedApps:@[self.targetBundleID]];
    }
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self stage3_cleanup];
    });
}

- (void)stage3_cleanup {
    [self logToWebView:@"[ZeroTrustd] Stage 3: 清洗缓存、恢复网络与权限回滚..." level:@"warn"];
    
    if (self.viewController) {
        [self.viewController executeRootHelperWithMode:@"diag_stage3" selectedApps:@[self.targetBundleID]];
    }
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self logToWebView:@"[ZeroTrustd] ✅ ZeroTrustd 诊断生命周期调度全流程完成。" level:@"success"];
    });
}

- (void)logToWebView:(NSString *)msg level:(NSString *)level {
    if (self.viewController && self.viewController.webView) {
        NSString *js = [NSString stringWithFormat:@"appendLog('%@', '%@');", msg, level];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.viewController.webView evaluateJavaScript:js completionHandler:nil];
        });
    }
}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // 【防御矩阵】：注册四大环境熔断监听
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(checkThermalState:) name:NSProcessInfoThermalStateDidChangeNotification object:nil];
    [[UIDevice currentDevice] setBatteryMonitoringEnabled:YES];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(checkBatteryLevel:) name:UIDeviceBatteryLevelDidChangeNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(checkPowerMode:) name:NSProcessInfoPowerStateDidChangeNotification object:nil];
    
    // 1. 0伪装：开机首要任务，触发底层探针抓取真实的硬件底牌
    DeviceInfo *info = [DeviceInfo sharedInstance];
    NSLog(@"[MAIN] Init complete. iOS: %@, Model: %@", info.systemVersion, info.deviceModel);
    
    // 2. 配置跨界通信管道，注册暗号监听器 "TrollHandler"
    WKUserContentController *userController = [[WKUserContentController alloc] init];
    [userController addScriptMessageHandler:self name:@"TrollHandler"];
    
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    config.userContentController = userController;
    
    // 3. 初始化全屏 WebView 容器
    self.webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:config];
    self.webView.navigationDelegate = self;
    self.webView.backgroundColor = [UIColor colorWithRed:0.04 green:0.04 blue:0.05 alpha:1.0];
    // 禁用原生滚动：HTML内部自己管理滚动容器，禁用后可防止WKWebView的scrollView
    // 拦截系统级手势（如iPad上方三点分屏按钮触发的下滑手势）
    self.webView.scrollView.scrollEnabled = NO;
    self.webView.scrollView.bounces = NO;
    // 设置自动调整mask，配合viewDidLayoutSubviews共同保障横竖屏切换时布局正确
    self.webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:self.webView];
    
    // 4. 从 App Bundle 内部读取并以内存字符串形式直灌 HTML（彻底避免 WebContent 沙盒在 /var/jb 越狱路径下的黑屏拦截）
    NSString *htmlPath = [[NSBundle mainBundle] pathForResource:@"index" ofType:@"html"];
    if (htmlPath) {
        NSData *htmlData = [NSData dataWithContentsOfFile:htmlPath];
        if (htmlData && htmlData.length > 0) {
            // 使用标准的 HTTP localhost 作为 baseURL，既能欺骗 WebKit 沙盒（绕过越狱路径读取限制），
            // 又能赋予完整的源(Origin)权限，防止 about:blank 导致的 inline CSS/JS 被 CSP 拦截（白屏不完整）。
            NSURL *dummyURL = [NSURL URLWithString:@"http://localhost/"];
            [self.webView loadData:htmlData MIMEType:@"text/html" characterEncodingName:@"UTF-8" baseURL:dummyURL];
            NSLog(@"[MAIN] Loaded index.html via raw NSData with localhost dummy baseURL.");
        } else {
            NSLog(@"[MAIN] Error: htmlData is nil or empty.");
        }
    }

    // 📢 启动 App 原生底层 30 秒实时抓取远程公告
    [self fetchRemoteNotice];
    [NSTimer scheduledTimerWithTimeInterval:30.0 target:self selector:@selector(fetchRemoteNotice) userInfo:nil repeats:YES];

    // 💡 性能与功耗优化：使用低功耗 GCD 定时器（带 10s 容差）每 10 分钟静默释放主进程 RAM 缓存
    dispatch_queue_t bgQueue = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0);
    dispatch_source_t ramTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, bgQueue);
    dispatch_source_set_timer(ramTimer, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC), 600 * NSEC_PER_SEC, 10 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(ramTimer, ^{
        @autoreleasepool {
            [[NSURLCache sharedURLCache] removeAllCachedResponses];
            malloc_zone_pressure_relief(malloc_default_zone(), 0);
            NSLog(@"[RAM] Periodic 10-min memory cache purge executed.");
        }
    });
    dispatch_resume(ramTimer);
}

// 📢 App 原生内部网络直接抓取远程公告 (无视浏览器沙盒与CORS限制)
- (void)fetchRemoteNotice {
    NSString *urlString = [NSString stringWithFormat:@"https://gitee.com/qilong-78-big/qilongdynamicwhitelistgun/raw/master/notice.txt?t=%ld", (long)[[NSDate date] timeIntervalSince1970]];
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return;
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData timeoutInterval:10.0];
    [request setValue:@"QiLongNative/1.0" forHTTPHeaderField:@"User-Agent"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (!error && data) {
            NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (content) {
                NSString *trimmed = [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (trimmed.length > 0) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSString *escaped = escapeForJS(trimmed);
                        NSString *js = [NSString stringWithFormat:@"if(window.updateNoticeText){window.updateNoticeText('%@');}", escaped];
                        [self.webView evaluateJavaScript:js completionHandler:nil];
                    });
                }
            }
        }
    }];
    [task resume];
}

// 🛡️ App 启动开屏鉴权校验 (open.txt)
- (void)fetchRemoteOpenAuth {
    NSString *urlString = [NSString stringWithFormat:@"https://gitee.com/qilong-78-big/qilongdynamicwhitelistgun/raw/master/open.txt?t=%ld", (long)[[NSDate date] timeIntervalSince1970]];
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        [self notifyOpenAuthResult:NO content:@""];
        return;
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData timeoutInterval:6.0];
    [request setValue:@"QiLongNative/1.0" forHTTPHeaderField:@"User-Agent"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (!error && data) {
            NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            NSString *trimmed = content ? [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] : @"";
            if ([trimmed isEqualToString:@"1"]) {
                [self notifyOpenAuthResult:YES content:trimmed];
            } else {
                [self notifyOpenAuthResult:NO content:trimmed];
            }
        } else {
            [self notifyOpenAuthResult:NO content:@"network_error"];
        }
    }];
    [task resume];
}

- (void)notifyOpenAuthResult:(BOOL)passed content:(NSString *)content {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *escaped = escapeForJS(content);
        NSString *js = [NSString stringWithFormat:@"if(window.onOpenAuthResult){window.onOpenAuthResult(%@, '%@');}", passed ? @"true" : @"false", escaped];
        [self.webView evaluateJavaScript:js completionHandler:nil];
    });
}

// 🔄 App 原生内部网络抓取最新更新内容 (GenXin.txt)
- (void)fetchRemoteCheckUpdate {
    NSString *urlString = [NSString stringWithFormat:@"https://gitee.com/qilong-78-big/qilongdynamicwhitelistgun/raw/master/GenXin.txt?t=%ld", (long)[[NSDate date] timeIntervalSince1970]];
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) return;
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData timeoutInterval:10.0];
    [request setValue:@"QiLongNative/1.0" forHTTPHeaderField:@"User-Agent"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *resultText = @"暂无更新内容或网络请求失败。";
        if (!error && data) {
            NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (content && content.length > 0) {
                resultText = content;
            }
        } else if (error) {
            resultText = [NSString stringWithFormat:@"获取更新信息失败: %@", error.localizedDescription];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *escaped = escapeForJS(resultText);
            NSString *js = [NSString stringWithFormat:@"if(window.updateCheckUpdateText){window.updateCheckUpdateText('%@');}", escaped];
            [self.webView evaluateJavaScript:js completionHandler:nil];
        });
    }];
    [task resume];
}

// 📄 当网页加载完毕时，精准执行双重反向注入（硬件数据 + 真实App名单）
- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    DeviceInfo *info = [DeviceInfo sharedInstance];
    
    // 注入 A：将硬件底牌送达前端看板
    NSString *v = escapeForJS(info.systemVersion ?: @"iOS 15.0");
    NSString *m = escapeForJS(info.deviceModel ?: @"iPhone");
    NSString *sn = escapeForJS(info.serialNumber ?: @"受沙盒限制");
    NSString *cpu = escapeForJS(info.processor ?: @"Apple Silicon");
    NSString *troll = info.isTrollStore ? @"true" : @"false";
    NSString *jb = info.isJailbroken ? @"true" : @"false";
    
    NSString *jsDevice = [NSString stringWithFormat:@"if(window.updateDevicePayload){window.updateDevicePayload('%@', '%@', '%@', '%@', %@, %@);}",
                        v, m, sn, cpu, troll, jb];
    
    // 注入 B：动态抓取真实 App 列表并转为 JSON 字符串
    NSString *rawList = [self fetchUserAppListJSON];
    NSString *escapedList = escapeForJS(rawList ?: @"[]");
    NSString *jsAppList = [NSString stringWithFormat:@"if(window.updateAppList){window.updateAppList('%@');}", escapedList];
    
    // 延迟 0.3 秒，配合前端开屏执行鉴权与数据注入
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self.webView evaluateJavaScript:jsDevice completionHandler:nil];
        [self.webView evaluateJavaScript:jsAppList completionHandler:nil];
        [self fetchRemoteNotice];
        [self fetchRemoteOpenAuth];
        NSLog(@"[BRIDGE] Data injected & open auth triggered.");
    });
}

// 🔍 利用私有 API 捞取全机所有应用名单（包括系统内置、第三方与隐藏服务，支持iOS全版本兼容）
- (NSString *)fetchUserAppListJSON {
    NSMutableArray *appArray = [NSMutableArray array];
    
    // 动态反射获取系统应用工作空间
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
                    
                    NSString *appName = nil;
                    if ([appProxy respondsToSelector:@selector(localizedName)]) {
                        appName = [appProxy performSelector:@selector(localizedName)];
                    }
                    
                    // 如果无法读取本地化名称，退而求其次使用 bundleID 尾部
                    if (!appName && bundleID) {
                        appName = [bundleID lastPathComponent];
                    }
                    
                    if (bundleID && appName) {
                        // 移除原有的 User/System 过滤，允许全部应用抓取到勾选面板
                        [appArray addObject:@{@"bundleID": bundleID, @"name": appName}];
                    }
                } @catch (NSException *e) {
                    NSLog(@"[ERROR] Skip parsing proxy record: %@", e);
                }
            }
        } @catch (NSException *e) {
            NSLog(@"[ERROR] Failed to fetch application workspace: %@", e);
        }
    }
    
    // 按名称字母表排序，方便用户查找
    [appArray sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        return [obj1[@"name"] localizedCompare:obj2[@"name"]];
    }];
    
    // 序列化为标准不带换行的 JSON 纯文本，供前端 JS 直接解析
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:appArray options:0 error:&error];
    if (!error && jsonData) {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return @"[]";
}

// 🔍 获取仅用户安装应用列表（applicationType == "User"）供诊断 Modal 使用
- (NSString *)fetchUserDiagnosticAppsJSON {
    NSMutableArray *appArray = [NSMutableArray array];
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
                    NSString *appType = nil;
                    if ([appProxy respondsToSelector:NSSelectorFromString(@"applicationType")]) {
                        #pragma clang diagnostic push
                        #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                        appType = [appProxy performSelector:NSSelectorFromString(@"applicationType")];
                        #pragma clang diagnostic pop
                    }

                    if (appType && [appType isEqualToString:@"User"]) {
                        NSString *bundleID = nil;
                        if ([appProxy respondsToSelector:NSSelectorFromString(@"applicationIdentifier")]) {
                            #pragma clang diagnostic push
                            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            bundleID = [appProxy performSelector:NSSelectorFromString(@"applicationIdentifier")];
                            #pragma clang diagnostic pop
                        }

                        NSString *appName = nil;
                        if ([appProxy respondsToSelector:NSSelectorFromString(@"localizedName")]) {
                            #pragma clang diagnostic push
                            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                            appName = [appProxy performSelector:NSSelectorFromString(@"localizedName")];
                            #pragma clang diagnostic pop
                        }

                        if (!appName && bundleID) {
                            appName = [bundleID lastPathComponent];
                        }

                        if (bundleID && appName) {
                            [appArray addObject:@{@"bundleID": bundleID, @"name": appName}];
                        }
                    }
                } @catch (NSException *e) {
                    NSLog(@"[ERROR] Skip parsing proxy record: %@", e);
                }
            }
        } @catch (NSException *e) {
            NSLog(@"[ERROR] Failed to fetch application workspace: %@", e);
        }
    }

    [appArray sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        return [obj1[@"name"] localizedCompare:obj2[@"name"]];
    }];

    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:appArray options:0 error:&error];
    if (!error && jsonData) {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return @"[]";
}

// 🔬 诊断生命周期预留入口（ZeroTrustdScheduler 调用前触发）
static void startDiagnosticLifecycle(NSString *bundleID) {
    NSLog(@"[DIAG] startDiagnosticLifecycle triggered for: %@", bundleID);
    // 预留：可在此处插入 substrate/debugserver 附加逻辑
}

// 📥 核心接收器：解析来自前端的多维度指令（支持字符串与复杂对象格式）
- (void)userContentController:(WKUserContentController *)userContentController 
      didReceiveScriptMessage:(WKScriptMessage *)message {
    
    id body = message.body;
    NSLog(@"[BRIDGE] Payload received: %@", body);
    
    if ([body isKindOfClass:[NSString class]]) {
if ([body isEqualToString:@"start_idfa_loop"]) {
            // 首次点击：派生后台进程并锁定 PID
            pid_t newPid = [self executeRootHelperWithMode:@"bg_idfa_loop" selectedApps:nil];
            if (newPid > 0) {
                global_bg_idfa_pid = newPid;
                [self.webView evaluateJavaScript:@"window.onIdfaStateChanged(true);" completionHandler:nil];
            }
        } else if ([body isEqualToString:@"stop_idfa_loop"]) {
            // 二次点击：下发 SIGKILL 物理截杀后台
            if (global_bg_idfa_pid > 0) {
                kill(global_bg_idfa_pid, SIGKILL);
                NSLog(@"[MAIN] Daemon process terminated (PID: %d)", global_bg_idfa_pid);
                global_bg_idfa_pid = 0;
            }
            [self.webView evaluateJavaScript:@"window.onIdfaStateChanged(false);" completionHandler:nil];
        } else if ([body isEqualToString:@"stop_idfa_safe_loop"]) {
            if (global_bg_idfa_safe_pid > 0) {
                kill(global_bg_idfa_safe_pid, SIGKILL);
                NSLog(@"[MAIN] Safe daemon process terminated (PID: %d)", global_bg_idfa_safe_pid);
                global_bg_idfa_safe_pid = 0;
            }
            [self.webView evaluateJavaScript:@"window.onIdfaSafeStateChanged(false);" completionHandler:nil];
        } else if ([body isEqualToString:@"stop_idfa_light_loop"]) {
            if (global_bg_idfa_light_pid > 0) {
                kill(global_bg_idfa_light_pid, SIGKILL);
                NSLog(@"[MAIN] Light daemon process terminated (PID: %d)", global_bg_idfa_light_pid);
                global_bg_idfa_light_pid = 0;
            }
            [self.webView evaluateJavaScript:@"window.onIdfaLightStateChanged(false);" completionHandler:nil];
        } else if ([body isEqualToString:@"start_clean"]) {
            [self executeRootHelperWithMode:@"standard_clean" selectedApps:nil];
        } else if ([body isEqualToString:@"userspace_reboot"]) {
            [self executeRootHelperWithMode:@"userspace_reboot" selectedApps:nil];
        } else if ([body isEqualToString:@"fix_daemons"]) {
            [self executeRootHelperWithMode:@"fix_daemons" selectedApps:nil];
        } else if ([body isEqualToString:@"safe_exit"]) {
            NSLog(@"[MAIN] Safe exit requested.");
            if (global_bg_idfa_pid > 0) { kill(global_bg_idfa_pid, SIGTERM); global_bg_idfa_pid = 0; }
            if (global_bg_idfa_safe_pid > 0) { kill(global_bg_idfa_safe_pid, SIGTERM); global_bg_idfa_safe_pid = 0; }
            if (global_bg_idfa_light_pid > 0) { kill(global_bg_idfa_light_pid, SIGTERM); global_bg_idfa_light_pid = 0; }
            
            // 执行 RootHelper 安全自愈与守护拉起
            [self executeRootHelperWithMode:@"safe_exit" selectedApps:nil];
            
            // 平稳退出回到桌面
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                if ([[UIApplication sharedApplication] respondsToSelector:NSSelectorFromString(@"suspend")]) {
                    [[UIApplication sharedApplication] performSelector:NSSelectorFromString(@"suspend")];
                }
                #pragma clang diagnostic pop
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    exit(0);
                });
            });
        } else if ([body isEqualToString:@"environment_check"]) {
            [self executeRootHelperWithMode:@"environment_check" selectedApps:nil];
        } else if ([body isEqualToString:@"free_dg"]) {
            [self executeRootHelperWithMode:@"free_dg" selectedApps:nil];
        } else if ([body isEqualToString:@"respring"]) {
            [self executeRootHelperWithMode:@"respring" selectedApps:nil];
        } else if ([body isEqualToString:@"refresh_200x_idfa"]) {
            [self executeRootHelperWithMode:@"refresh_200x_idfa" selectedApps:nil];
        } else if ([body isEqualToString:@"install_filza"]) {
            [self executeRootHelperWithMode:@"install_filza" selectedApps:nil];
        } else if ([body isEqualToString:@"install_filza_troll"]) {
            [self executeRootHelperWithMode:@"install_filza_troll" selectedApps:nil];
        } else if ([body isEqualToString:@"install_qilong_ai"]) {
            [self executeRootHelperWithMode:@"install_qilong_ai" selectedApps:nil];
        } else if ([body isEqualToString:@"install_permanent_dg"]) {
            [self executeRootHelperWithMode:@"install_permanent_dg" selectedApps:nil];
        } else if ([body isEqualToString:@"install_dolby_audio"]) {
            [self executeRootHelperWithMode:@"install_dolby_audio" selectedApps:nil];
        } else if ([body isEqualToString:@"install_green_shield"]) {
            [self executeRootHelperWithMode:@"install_green_shield" selectedApps:nil];
        } else if ([body isEqualToString:@"fetch_notice"]) {
            [self fetchRemoteNotice];
        } else if ([body isEqualToString:@"fetch_check_update"]) {
            [self fetchRemoteCheckUpdate];
        } else if ([body isEqualToString:@"check_open_auth"]) {
            [self fetchRemoteOpenAuth];
        } else if ([body isEqualToString:@"crash_app"]) {
            NSLog(@"[AUTH] App invalid/expired. Triggering isolated self-exit/crash.");
            // 优雅安全退出当前进程，绝不影响系统内核及其他 App
            exit(0);
        }
    } 
    else if ([body isKindOfClass:[NSDictionary class]]) {
        // ✨全新咬合：处理带勾选名单的高阶前端对象 {"action": "xxx", "apps": ["包名1", "包名2"]}
        NSString *action = body[@"action"];
        
        if ([action isEqualToString:@"fetch_user_apps"]) {
            NSString *appListJson = [self fetchUserDiagnosticAppsJSON];
            NSString *jsCall = [NSString stringWithFormat:@"window.updateDiagnosticApps('%@');", escapeForJS(appListJson)];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.webView evaluateJavaScript:jsCall completionHandler:nil];
            });
        } else if ([action isEqualToString:@"execute_diagnostic_launch"]) {
            NSString *bundleID = body[@"bundleID"];
            if (bundleID) {
                // 调用预留的生命周期空函数
                startDiagnosticLifecycle(bundleID);
                
                // 启动 ZeroTrustd 企业级诊断调度器
                ZeroTrustdScheduler *scheduler = [[ZeroTrustdScheduler alloc] initWithBundleID:bundleID viewController:self];
                [scheduler startScheduler];
            }
        }
        
        if ([action isEqualToString:@"start_clean"]) {
            NSArray *apps = body[@"apps"];
            [self executeRootHelperWithMode:@"standard_clean" selectedApps:apps];
        } else if ([action isEqualToString:@"start_realtime_clean"]) {
            NSArray *apps = body[@"apps"];
            pid_t newPid = [self executeRootHelperWithMode:@"realtime_whitelist_clean" selectedApps:apps];
            if (newPid > 0) {
                global_bg_idfa_pid = newPid;
                [self.webView evaluateJavaScript:@"window.onIdfaStateChanged(true);" completionHandler:nil];
            }
        } else if ([action isEqualToString:@"start_realtime_safe_clean"]) {
            NSArray *apps = body[@"apps"];
            pid_t newPid = [self executeRootHelperWithMode:@"realtime_whitelist_clean_safe" selectedApps:apps];
            if (newPid > 0) {
                global_bg_idfa_safe_pid = newPid;
                [self.webView evaluateJavaScript:@"window.onIdfaSafeStateChanged(true);" completionHandler:nil];
            }
        } else if ([action isEqualToString:@"start_realtime_light_clean"]) {
            NSArray *apps = body[@"apps"];
            pid_t newPid = [self executeRootHelperWithMode:@"realtime_whitelist_clean_light" selectedApps:apps];
            if (newPid > 0) {
                global_bg_idfa_light_pid = newPid;
                [self.webView evaluateJavaScript:@"window.onIdfaLightStateChanged(true);" completionHandler:nil];
            }
        } else if ([action isEqualToString:@"one_key_new_device"]) {
            NSArray *apps = body[@"apps"];
            [self executeRootHelperWithMode:@"one_key_new_device" selectedApps:apps];
        } else if ([action isEqualToString:@"lock_filza"]) {
            [self createAndOpenFilzaScript:@"lock"];
        } else if ([action isEqualToString:@"unlock_filza"]) {
            [self createAndOpenFilzaScript:@"unlock"];
        } else if ([action isEqualToString:@"lock_system"]) {
            float level = [[UIDevice currentDevice] batteryLevel];
            if ((level > 0 && level <= 0.15f) || [[NSProcessInfo processInfo] isLowPowerModeEnabled]) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.webView evaluateJavaScript:@"window.showLockResult('unlocked', '[FAILSAVE 拦截] 当前电量极低(<=15%)或已开启省电模式。为防止意外关机导致系统永久死锁，安全矩阵已拒绝本次锁定请求！');" completionHandler:nil];
                });
                return;
            }
            [self executeRootHelperWithMode:@"lock_keychain" selectedApps:nil];
            writeLockState(YES);
        } else if ([action isEqualToString:@"unlock_system"]) {
            [self executeRootHelperWithMode:@"unlock_keychain" selectedApps:nil];
            writeLockState(NO);
        } else if ([action isEqualToString:@"check_lock_status"]) {
            [self checkLockStatusAndNotifyFrontend];
        } else if ([action isEqualToString:@"open_url"]) {
            NSString *urlString = body[@"url"];
            if (urlString) {
                NSString *targetURLString = urlString;
                NSRange sileoRange = [urlString rangeOfString:@"sileo://"];
                if (sileoRange.location != NSNotFound) {
                    NSString *sub = [urlString substringFromIndex:sileoRange.location];
                    NSArray *components = [sub componentsSeparatedByString:@" - from "];
                    targetURLString = [components.firstObject stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                }
                
                NSURL *url = [NSURL URLWithString:targetURLString];
                if (!url) {
                    url = [NSURL URLWithString:[targetURLString stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]]];
                }
                if (!url) {
                    url = [NSURL URLWithString:urlString];
                }
                if (url) {
                    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
                }
            }
        }
    }
}

static NSString* escapeForJS(NSString *input) {
    if (!input) return @"";
    NSMutableString *s = [input mutableCopy];
    [s replaceOccurrencesOfString:@"\\" withString:@"\\\\" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"'" withString:@"\\'" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"\"" withString:@"\\\"" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"\n" withString:@"\\n" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"\r" withString:@"" options:0 range:NSMakeRange(0, s.length)];
    return s;
}

// 🚀 动态派生提权进程（完美传递用户勾选的应用名单参数 + stdout 管道实时回传）
- (pid_t)executeRootHelperWithMode:(NSString *)mode selectedApps:(NSArray *)selectedApps {
    NSString *bundleHelperPath = [[NSBundle mainBundle] pathForResource:@"RootHelper" ofType:nil];
    if (!bundleHelperPath) return 0;
    
    // 【致命雷区 3 修复】脱离 App Bundle 沙盒，将 helper 拷贝到公用目录执行，防止 setuid(0) 被静默降级
    NSString *helperPath = @"/var/mobile/RootHelper";
    NSFileManager *fm = [NSFileManager defaultManager];
    
    [fm removeItemAtPath:helperPath error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:bundleHelperPath toPath:helperPath error:&copyErr]) {
        NSLog(@"[ERROR] Failed to copy RootHelper to /var/mobile/: %@", copyErr);
        // 若拷贝失败则降级使用原路径
        helperPath = bundleHelperPath;
    } else {
        // 赋予执行权限
        chmod([helperPath UTF8String], 0755);
    }
    
    // 构建 C 语言标准的 argv 动态参数列数组
    NSMutableArray *argsArray = [NSMutableArray array];
    [argsArray addObject:helperPath]; // argv[0] 是程序自身路径
    [argsArray addObject:mode];       // argv[1] 是运行模式轨
    
    // 将用户勾选的名单追加到 argv[2], argv[3]... 后面，实现数据物理咬合
    if (selectedApps && selectedApps.count > 0) {
        [argsArray addObjectsFromArray:selectedApps];
    }
    
    // 转为 C 指针分配内存
    int argCount = (int)argsArray.count;
    const char **argv = calloc(argCount + 1, sizeof(char *));
    for (int i = 0; i < argCount; i++) {
        argv[i] = [argsArray[i] UTF8String];
    }
    argv[argCount] = NULL; // 结构体结尾必须置空
    
    // 建立管道，接通 RootHelper 的 stdout 实时日志流
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(argv);
        return 0;
    }
    
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    
    // 【致命雷区 2 修复】使用 posix_spawnattr_t 设置特权标志与身份穿透 (Persona)
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    // 注入 POSIX_SPAWN_START_SUSPENDED
    short flags = POSIX_SPAWN_START_SUSPENDED;
    posix_spawnattr_setflags(&attr, flags);
    
    // 【TrollStore 核心提权骑捷】利用 persona-mgmt entitlement 强制覆盖 UID 0
    #define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
    int (*set_persona_np)(const posix_spawnattr_t* __restrict, uid_t, uint32_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_np");
    int (*set_persona_uid_np)(const posix_spawnattr_t* __restrict, uid_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_uid_np");
    int (*set_persona_gid_np)(const posix_spawnattr_t* __restrict, uid_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_gid_np");
    
    if (set_persona_np != NULL && set_persona_uid_np != NULL && set_persona_gid_np != NULL) {
        set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        set_persona_uid_np(&attr, 0);
        set_persona_gid_np(&attr, 0);
    } else {
        NSLog(@"[Safe] posix_spawnattr persona functions not found, skipping persona setup.");
    }
    pid_t pid;
    int status = posix_spawn(&pid, argv[0], &actions, &attr, (char* const*)argv, NULL);
    
    posix_spawnattr_destroy(&attr);
    
    posix_spawn_file_actions_destroy(&actions);
    free(argv);
    close(pipefd[1]); // 父进程关闭管道写端
    
    if (status == 0) {
        kill(pid, SIGCONT); // 恢复运行 (因为使用了 POSIX_SPAWN_START_SUSPENDED)
        NSLog(@"[SPAWN] RootHelper launched with %d targets (PID: %d)", (argCount - 2), pid);
        
        // 异步读取管道，将 RootHelper 的 stdout 实时转发至前端 WebView 日志面板（低功耗 QOS_CLASS_UTILITY 轨，避开大核）
        int readFd = pipefd[0];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            FILE *stream = fdopen(readFd, "r");
            if (!stream) { close(readFd); return; }
            
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), stream) != NULL) {
                @autoreleasepool {
                    NSString *line = [[NSString alloc] initWithUTF8String:buffer];
                    // 去除行尾换行
                    line = [line stringByTrimmingCharactersInSet:[NSCharacterSet newlineCharacterSet]];
                    if (line.length == 0) continue;
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        // 安全转义字符，防止 JS 注入或解析语法错误引发 WebKit 崩溃
                        NSString *escaped = escapeForJS(line);
                        NSString *js = [NSString stringWithFormat:@"appendLog('%@', 'system');", escaped];
                        [self.webView evaluateJavaScript:js completionHandler:nil];
                    });
                }
            }
            fclose(stream);
        });
        
        return pid;
    } else {
        NSLog(@"[ERROR] sandbox restricted.");
        close(pipefd[0]);
        return 0;
    }
}

- (void)createAndOpenFilzaScript:(NSString *)mode {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *scriptName = [mode isEqualToString:@"lock"] ? @"QiLong_Lock.sh" : @"QiLong_Unlock.sh";
        NSString *scriptPath = [NSString stringWithFormat:@"/var/mobile/Documents/%@", scriptName];
        
        NSMutableString *script = [NSMutableString string];
        [script appendString:@"#!/bin/sh\n"];
        [script appendFormat:@"echo \"=== QiLong Filza Automation: %@ ===\"\n", [mode uppercaseString]];
        
        if ([mode isEqualToString:@"lock"]) {
            [script appendString:@"sqlite3 /private/var/Keychains/keychain-2.db \"PRAGMA wal_checkpoint(TRUNCATE);\"\n"];
            [script appendString:@"chflags nouchg /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chflags noschg /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chown 0:0 /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chmod 0400 /private/var/Keychains/keychain-2.db\n"];
            [script appendString:@"chmod 0400 /private/var/Keychains/keychain-2.db-wal\n"];
            [script appendString:@"chmod 0400 /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chflags uchg /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chflags schg /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"echo \"[LOCK] stat keychain-2.db:\"\n"];
            [script appendString:@"ls -laO /private/var/Keychains/keychain-2.db\n"];
        } else {
            [script appendString:@"chflags nouchg /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chflags noschg /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chown 64:64 /private/var/Keychains/keychain-2.db /private/var/Keychains/keychain-2.db-wal /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"chmod 0600 /private/var/Keychains/keychain-2.db\n"];
            [script appendString:@"chmod 0666 /private/var/Keychains/keychain-2.db-wal\n"];
            [script appendString:@"chmod 0666 /private/var/Keychains/keychain-2.db-shm\n"];
            [script appendString:@"echo \"[UNLOCK] stat keychain-2.db:\"\n"];
            [script appendString:@"ls -laO /private/var/Keychains/keychain-2.db\n"];
        }
        [script appendString:@"killall -9 securityd\n"];
        [script appendString:@"echo \"Operation completed.\"\n"];
        
        NSError *writeError = nil;
        [script writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:&writeError];
        
        if (writeError) {
            NSString *errLog = [NSString stringWithFormat:@"appendLog('[ERROR] 脚本生成失败: %@', 'warn');", escapeForJS(writeError.localizedDescription)];
            [self.webView evaluateJavaScript:errLog completionHandler:nil];
            return;
        }
        
        // 赋予可执行权限
        chmod([scriptPath UTF8String], 0755);
        
        NSString *okLog = [NSString stringWithFormat:@"appendLog('[FILZA] ✅ 自动化脚本已生成: %@ 正在唤起 Filza...', 'success');", scriptPath];
        [self.webView evaluateJavaScript:okLog completionHandler:nil];
        
        // ── Filza URL Scheme 正确格式：filza://view/absolute/path ──
        // filza://view 是官方支持的深链格式，path 必须以 / 开头
        NSString *encodedPath = [scriptPath stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
        
        // 按优先级排列：第一个是官方标准格式
        NSArray<NSString *> *schemesToTry = @[
            [NSString stringWithFormat:@"filza://view%@", encodedPath],
            [NSString stringWithFormat:@"filza://view%@", scriptPath],
            [NSString stringWithFormat:@"filza://%@", scriptPath]
        ];
        
        UIApplication *app = [UIApplication sharedApplication];
        
        // 优先尝试 LSApplicationWorkspace（绕过 canOpenURL 白名单限制）
        Class lsaw = NSClassFromString(@"LSApplicationWorkspace");
        id workspace = lsaw ? [lsaw performSelector:@selector(defaultWorkspace)] : nil;
        
        BOOL opened = NO;
        for (NSString *schemeStr in schemesToTry) {
            NSURL *url = [NSURL URLWithString:schemeStr];
            if (!url) continue;
            
            if (workspace && [workspace respondsToSelector:@selector(openURL:)]) {
                if ([workspace openURL:url]) {
                    opened = YES;
                    NSString *log = @"appendLog('[FILZA] ✅ Filza 已通过 LSApplicationWorkspace 成功唤起', 'success');";
                    [self.webView evaluateJavaScript:log completionHandler:nil];
                    break;
                }
            }
        }
        
        if (!opened) {
            // 不检查 canOpenURL，直接强制 openURL（TrollStore 环境下 canOpenURL 受限）
            NSURL *primaryUrl = [NSURL URLWithString:schemesToTry.firstObject];
            if (primaryUrl) {
                [app openURL:primaryUrl options:@{UIApplicationOpenURLOptionUniversalLinksOnly: @NO} completionHandler:^(BOOL success) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        if (success) {
                            NSString *log = @"appendLog('[FILZA] ✅ Filza 已通过 UIApplication 成功唤起', 'success');";
                            [self.webView evaluateJavaScript:log completionHandler:nil];
                        } else {
                            // 最终兜底：尝试第二个 URL 格式
                            NSURL *fallbackUrl = [NSURL URLWithString:schemesToTry[1]];
                            [app openURL:fallbackUrl options:@{UIApplicationOpenURLOptionUniversalLinksOnly: @NO} completionHandler:^(BOOL s2) {
                                dispatch_async(dispatch_get_main_queue(), ^{
                                    NSString *log = s2
                                        ? @"appendLog('[FILZA] ✅ Filza 兜底格式唤起成功', 'success');"
                                        : @"appendLog('[ERROR] Filza 无法唤起。请确认：1)已安装巨魔版Filza；2)Filza版本支持URL Scheme；3)手动打开Filza导航至 /var/mobile/Documents/ 执行脚本。', 'warn');";
                                    [self.webView evaluateJavaScript:log completionHandler:nil];
                                });
                            }];
                        }
                    });
                }];
            }
        }
    });
}

#include <sys/stat.h>
- (void)checkLockStatusAndNotifyFrontend {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        struct stat st;
        NSString *statusStr = @"unknown";
        NSMutableString *logContent = [NSMutableString string];
        
        if (stat("/private/var/Keychains/keychain-2.db", &st) == 0) {
            int mode = st.st_mode & 0777;
            int uid = (int)st.st_uid;
            uint32_t flags = st.st_flags;
            BOOL writeStripped = (st.st_mode & S_IWUSR) == 0;
            BOOL immutable = (flags & (UF_IMMUTABLE | SF_IMMUTABLE)) != 0;
            
            if (writeStripped || immutable) {
                statusStr = @"locked";
                [logContent appendFormat:@"[KEYCHAIN] ✅ 物理锁定验证通过\n"];
                [logContent appendFormat:@"  权限位: %o (owner write=%@)\n", mode, writeStripped ? @"✅已剥夺" : @"⚠️仍存在"];
                [logContent appendFormat:@"  所有者 uid: %d (期望 0=root)\n", uid];
                [logContent appendFormat:@"  不可变标志 flags: 0x%x (UF_IMMUTABLE=%@, SF_IMMUTABLE=%@)\n",
                    flags,
                    (flags & UF_IMMUTABLE) ? @"✅" : @"❌",
                    (flags & SF_IMMUTABLE) ? @"✅" : @"❌"];
                [logContent appendString:@"\n⚠️ 关于Filza显示「读写」: Filza以root身份运行，root可忽略权限位，这是正常现象。\n"];
                [logContent appendString:@"真正的验证方法：普通App或securityd无法写入此文件，锁定已生效。"];
            } else {
                statusStr = @"unlocked";
                [logContent appendFormat:@"[KEYCHAIN] 🔓 当前状态：未锁定\n"];
                [logContent appendFormat:@"  权限位: %o\n  所有者 uid: %d\n  flags: 0x%x\n", mode, uid, flags];
            }
        } else {
            [logContent appendString:@"[ERROR] 无法读取 keychain-2.db 文件状态（stat 失败）"];
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *escapedLog = escapeForJS(logContent);
            NSString *js = [NSString stringWithFormat:@"window.showLockResult('%@', '%@');", statusStr, escapedLog];
            [self.webView evaluateJavaScript:js completionHandler:nil];
        });
    });
}


// ── 熔断防御矩阵逻辑 ──
- (void)triggerEmergencyUnlock:(NSString *)reason {
    if (readLockState()) {
        NSLog(@"[FAILSAVE] 触发紧急熔断解锁，原因：%@", reason);
        [self executeRootHelperWithMode:@"unlock_keychain" selectedApps:nil];
        writeLockState(NO);
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *logMsg = [NSString stringWithFormat:@"[FAILSAVE] 紧急熔断：为了防止系统死锁，已自动解锁！原因：%@", reason];
            NSString *jsLog = [NSString stringWithFormat:@"appendLog('%@', 'system');", logMsg];
            [self.webView evaluateJavaScript:jsLog completionHandler:nil];
            [self.webView evaluateJavaScript:@"window.showLockResult('unlocked', '由于电量/温度触发安全熔断保护，系统已自动切回未锁定状态。');" completionHandler:nil];
        });
    }
}

- (void)checkThermalState:(NSNotification *)notif {
    NSProcessInfoThermalState state = [[NSProcessInfo processInfo] thermalState];
    if (state == NSProcessInfoThermalStateSerious || state == NSProcessInfoThermalStateCritical) {
        [self triggerEmergencyUnlock:@"设备温度过高(Serious/Critical)"];
    }
}

- (void)checkBatteryLevel:(NSNotification *)notif {
    float level = [[UIDevice currentDevice] batteryLevel];
    if (level > 0 && level <= 0.15f) {
        [self triggerEmergencyUnlock:@"电量极低(<=15%)"];
    }
}

- (void)checkPowerMode:(NSNotification *)notif {
    if ([[NSProcessInfo processInfo] isLowPowerModeEnabled]) {
        [self triggerEmergencyUnlock:@"开启了低电量模式"];
    }
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    // 强制将 WebView 视口界限物理拉伸/重置到当前屏幕物理大小，完美修复旋转时比例没有改变、内容掉到屏幕外的Bug
    self.webView.frame = self.view.bounds;
}

- (BOOL)prefersStatusBarHidden { return YES; }
@end

// ── 标准 AppDelegate 壳子 ──
@interface AppDelegate : UIResponder <UIApplicationDelegate, CLLocationManagerDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) CLLocationManager *locationManager;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    @try {
        // 【崩溃自愈状态机】开机自检：若上次锁定后遭遇崩溃或强杀，立刻自愈解锁！
        if (readLockState()) {
            NSLog(@"[FAILSAVE] 发现上次锁定后遭遇强杀或崩溃，正在执行底层自愈解锁...");
            NSString *bundleHelperPath = [[NSBundle mainBundle] pathForResource:@"RootHelper" ofType:nil];
            if (bundleHelperPath) {
                NSString *helperPath = @"/var/mobile/RootHelper";
                [[NSFileManager defaultManager] removeItemAtPath:helperPath error:nil];
                if ([[NSFileManager defaultManager] copyItemAtPath:bundleHelperPath toPath:helperPath error:nil]) {
                    chmod([helperPath UTF8String], 0755);
                } else {
                    helperPath = bundleHelperPath;
                }
                pid_t pid;
                const char *argv[] = {[helperPath UTF8String], "unlock_keychain", NULL};
                posix_spawnattr_t attr;
                posix_spawnattr_init(&attr);
                posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
                int status = posix_spawn(&pid, argv[0], NULL, &attr, (char* const*)argv, NULL);
                posix_spawnattr_destroy(&attr);
                if (status == 0) kill(pid, SIGCONT);
            }
            writeLockState(NO);
        }
    } @catch (NSException *e) {
        NSLog(@"[APP_INIT] Lock state check exception: %@", e);
    }

    @try {
        // 【后台永生保活】
        self.locationManager = [[CLLocationManager alloc] init];
        self.locationManager.delegate = self;
        self.locationManager.desiredAccuracy = kCLLocationAccuracyKilometer; // 最低精度，极度省电
        if ([self.locationManager respondsToSelector:@selector(setAllowsBackgroundLocationUpdates:)]) {
            [self.locationManager setAllowsBackgroundLocationUpdates:YES];
        }
        self.locationManager.pausesLocationUpdatesAutomatically = NO;
        [self.locationManager requestAlwaysAuthorization];
        [self.locationManager startUpdatingLocation];
    } @catch (NSException *e) {
        NSLog(@"[LOCATION] Background location init error: %@", e);
    }

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    ViewController *mainVC = [[ViewController alloc] init];
    self.window.rootViewController = mainVC;
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    @try {
        // 【退后台熔断】按 PRD 原则：严格执行“退后台即解锁”以防止重启白苹果
        if (readLockState()) {
            NSLog(@"[FAILSAVE] 检测到应用退入后台，执行防死锁紧急解锁 Keychain！");
            NSString *bundleHelperPath = [[NSBundle mainBundle] pathForResource:@"RootHelper" ofType:nil];
            if (bundleHelperPath) {
                NSString *helperPath = @"/var/mobile/RootHelper";
                [[NSFileManager defaultManager] removeItemAtPath:helperPath error:nil];
                if ([[NSFileManager defaultManager] copyItemAtPath:bundleHelperPath toPath:helperPath error:nil]) {
                    chmod([helperPath UTF8String], 0755);
                } else {
                    helperPath = bundleHelperPath;
                }
                pid_t pid;
                const char *argv[] = {[helperPath UTF8String], "unlock_keychain", NULL};
                posix_spawnattr_t attr;
                posix_spawnattr_init(&attr);
                posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
                #define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
                int (*set_persona_np)(const posix_spawnattr_t* __restrict, uid_t, uint32_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_np");
                int (*set_persona_uid_np)(const posix_spawnattr_t* __restrict, uid_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_uid_np");
                int (*set_persona_gid_np)(const posix_spawnattr_t* __restrict, uid_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_gid_np");
                if (set_persona_np != NULL && set_persona_uid_np != NULL && set_persona_gid_np != NULL) {
                    set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
                    set_persona_uid_np(&attr, 0);
                    set_persona_gid_np(&attr, 0);
                } else {
                    NSLog(@"[Safe] posix_spawnattr persona functions not found, skipping persona setup.");
                }
                int status = posix_spawn(&pid, argv[0], NULL, &attr, (char* const*)argv, NULL);
                posix_spawnattr_destroy(&attr);
                if (status == 0) kill(pid, SIGCONT);
            }
            writeLockState(NO);
        }
    } @catch (NSException *e) {
        NSLog(@"[BACKGROUND] Failsafe error: %@", e);
    }
}

- (void)applicationWillTerminate:(UIApplication *)application {
    @try {
        // 【杀后台抢答熔断】：当用户在多任务卡片向上划掉 App 强制杀死时，抢答一波解锁！
        if (readLockState()) {
            NSLog(@"[FAILSAVE] 检测到应用即将被强制关闭，抢答执行紧急解锁 Keychain！");
            NSString *bundleHelperPath = [[NSBundle mainBundle] pathForResource:@"RootHelper" ofType:nil];
            if (bundleHelperPath) {
                NSString *helperPath = @"/var/mobile/RootHelper";
                [[NSFileManager defaultManager] removeItemAtPath:helperPath error:nil];
                if ([[NSFileManager defaultManager] copyItemAtPath:bundleHelperPath toPath:helperPath error:nil]) {
                    chmod([helperPath UTF8String], 0755);
                } else {
                    helperPath = bundleHelperPath;
                }
                pid_t pid;
                const char *argv[] = {[helperPath UTF8String], "unlock_keychain", NULL};
                posix_spawnattr_t attr;
                posix_spawnattr_init(&attr);
                posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
                #define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
                int (*set_persona_np)(const posix_spawnattr_t* __restrict, uid_t, uint32_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_np");
                int (*set_persona_uid_np)(const posix_spawnattr_t* __restrict, uid_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_uid_np");
                int (*set_persona_gid_np)(const posix_spawnattr_t* __restrict, uid_t) = dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_gid_np");
                if (set_persona_np != NULL && set_persona_uid_np != NULL && set_persona_gid_np != NULL) {
                    set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
                    set_persona_uid_np(&attr, 0);
                    set_persona_gid_np(&attr, 0);
                } else {
                    NSLog(@"[Safe] posix_spawnattr persona functions not found, skipping persona setup.");
                }
                int status = posix_spawn(&pid, argv[0], NULL, &attr, (char* const*)argv, NULL);
                posix_spawnattr_destroy(&attr);
                if (status == 0) kill(pid, SIGCONT);
            }
            writeLockState(NO);
        }
    } @catch (NSException *e) {
        NSLog(@"[TERMINATE] Failsafe error: %@", e);
    }
}
@end

int main(int argc, char * argv[]) {
    @autoreleasepool {
        [[@"Main entered at: " stringByAppendingString:[NSDate now].description] 
            writeToFile:@"/tmp/crash_debug.log" 
            atomically:YES 
            encoding:NSUTF8StringEncoding 
            error:nil];

        @try {
            return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
        } @catch (NSException *e) {
            NSLog(@"[FATAL] Uncaught exception: %@\n%@", e.reason, e.callStackSymbols);
            return 0;
        }
    }
}
