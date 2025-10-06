// File: Frida_Script_pretty_logging_v2.js
// Improvements: ANSI colorized logs, safer stack trace helper, fixes & hardening

const ENABLE_RANDOMIZE_BUILD = false;
const ENABLE_COLOR = true; // set false to disable ANSI color sequences
const LITE_ONLY = false;   // if true, script will early-return and only run SSL unpinning

// ---------- ANSI helpers ----------
const ANSI = {
    reset: '\u001b[0m',
    bold: '\u001b[1m',
    red: '\u001b[31m',
    green: '\u001b[32m',
    yellow: '\u001b[33m',
    blue: '\u001b[34m',
    magenta: '\u001b[35m',
    cyan: '\u001b[36m',
    gray: '\u001b[90m'
};

function colorize(s, code) {
    if (!ENABLE_COLOR) return s;
    return code + s + ANSI.reset;
}

function repeat(char, n) { return Array(n+1).join(char); }
function padRight(s, n) { return (s + Array(n+1).join(' ')).slice(0,n); }

function logSection(title) {
    console.log('\n' + colorize(repeat('═', 72), ANSI.cyan));
    console.log(colorize('🧩  ' + title, ANSI.bold + ANSI.blue));
    console.log(colorize(repeat('═', 72), ANSI.cyan));
}
function logSuccess(msg) { console.log(colorize('✅  ' + msg, ANSI.green)); }
function logBypass(msg) { console.log(colorize('🚀  ' + msg, ANSI.magenta)); }
function logInfo(msg) { console.log(colorize('ℹ️  ' + msg, ANSI.cyan)); }
function logWarn(msg) { console.log(colorize('⚠️  ' + msg, ANSI.yellow)); }
function logError(msg) { console.log(colorize('❌  ' + msg, ANSI.red)); }

// small wrapper to safely call a function and log errors
function safe(fn, name) {
    try { fn(); }
    catch (err) { logWarn(name + ' -> ' + (err && err.message ? err.message : err)); }
}

// ---------- common lists ----------
const commonPaths = [
    '/data/local/bin/su', '/data/local/su', '/data/local/xbin/su',
    '/dev/com.koushikdutta.superuser.daemon/', '/sbin/su', '/system/app/Superuser.apk',
    '/system/bin/failsafe/su', '/system/bin/su', '/su/bin/su', '/system/etc/init.d/99SuperSUDaemon',
    '/system/sd/xbin/su', '/system/xbin/busybox', '/system/xbin/daemonsu', '/system/xbin/su',
    '/system/sbin/su', '/vendor/bin/su', '/cache/su', '/data/su', '/dev/su', '/system/bin/.ext/su',
    '/system/usr/we-need-root/su', '/system/app/Kinguser.apk', '/data/adb/magisk', '/sbin/.magisk',
    '/cache/.disable_magisk', '/dev/.magisk.unblock', '/cache/magisk.log', '/data/adb/magisk.img',
    '/data/adb/magisk.db', '/data/adb/magisk_simple', '/init.magisk.rc', '/system/xbin/ku.sud',
    '/data/adb/ksu', '/data/adb/ksud'
];

const MergedRootPackages = [
    'com.noshufou.android.su','com.noshufou.android.su.elite','eu.chainfire.supersu',
    'com.koushikdutta.superuser','com.thirdparty.superuser','com.yellowes.su',
    'com.koushikdutta.rommanager','com.koushikdutta.rommanager.license','com.dimonvideo.luckypatcher',
    'com.chelpus.lackypatch','com.ramdroid.appquarantine','com.ramdroid.appquarantinepro',
    'com.devadvance.rootcloak','com.devadvance.rootcloakplus','de.robv.android.xposed.installer',
    'com.saurik.substrate','com.zachspong.temprootremovejb','com.amphoras.hidemyroot',
    'com.amphoras.hidemyrootadfree','com.formyhm.hiderootPremium','com.formyhm.hideroot',
    'me.phh.superuser','eu.chainfire.supersu.pro','com.kingouser.com','com.topjohnwu.magisk','me.weishu.kernelsu'
];

const RootBinaries = ['su','busybox','supersu','Superuser.apk','KingoUser.apk','SuperSu.apk','magisk'];

const RootProperties = {
    'ro.build.selinux': '1',
    'ro.debuggable': '0',
    'service.adb.root': '0',
    'ro.secure': '1'
};
const RootPropertiesKeys = Object.keys(RootProperties);

// ---------- helpers ----------
function isInArray(arr, val) { return arr.indexOf(val) !== -1; }

function randomBuildProps() {
    const models = [
        {PRODUCT:'gracerltexx', MANUFACTURER:'samsung', BRAND:'samsung', DEVICE:'gracerlte', MODEL:'SM-N935F', HARDWARE:'samsungexynos8890'}
    ];
    return models[Math.floor(Math.random()*models.length)];
}

// Robust stack trace extraction using android.util.Log
function getStackTraceString() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        return Log.getStackTraceString(Exception.$new());
    } catch (e) {
        return 'no stacktrace available: ' + (e && e.message ? e.message : e);
    }
}

// ---------- LITE mode quick exit ----------
if (LITE_ONLY) {
    // run only SSL unpinning block (defined below) and exit early
    Java.perform(function() {
        logSection('LITE MODE: SSL Unpinning only');
        // copy the SSL unpinning block below (or call the function if extracted)
        // For brevity, we'll jump to the SSL block defined later by invoking a named function if present.
    });
    // we intentionally do not return here because SSL block runs in setTimeout later in file
}

// ---------- Java-level: emulator spoof & basic hooks ----------
Java.perform(function() {
    logSection('Java-level: emulator spoof & basic hooks');

    safe(function() {
        try {
            const Build = Java.use('android.os.Build');
            const values = ENABLE_RANDOMIZE_BUILD ? randomBuildProps() : {
                PRODUCT: 'gracerltexx', MANUFACTURER: 'samsung-Pentest1337', BRAND: 'samsung-Pentest1337',
                DEVICE: 'gracerlte', MODEL: 'SM-N935F', HARDWARE: 'samsungexynos8890'
            };
            try { Build.PRODUCT.value = values.PRODUCT; } catch(e){}
            try { Build.MANUFACTURER.value = values.MANUFACTURER; } catch(e){}
            try { Build.BRAND.value = values.BRAND; } catch(e){}
            try { Build.DEVICE.value = values.DEVICE; } catch(e){}
            try { Build.MODEL.value = values.MODEL; } catch(e){}
            try { Build.HARDWARE.value = values.HARDWARE; } catch(e){}
            try { Build.FINGERPRINT.value = 'samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys'; } catch(e){}
            logSuccess('android.os.Build fields spoofed');
        } catch(e) {
            logWarn('Build spoof error: ' + (e && e.message ? e.message : e));
        }
    }, 'Build spoof');

    // Replace java.io.File.exists with combined emulator/root check
    safe(function() {
        try {
            const JFile = Java.use('java.io.File');
            const origExists = JFile.exists;
            JFile.exists.implementation = function() {
                try {
                    var name = this.getName();
                    var abs = this.getAbsolutePath();
                    if (['qemud','qemu_pipe','drivers','cpuinfo'].indexOf(name) > -1) {
                        logBypass('Hooked File.exists (emulator) -> ' + name);
                        return false;
                    }
                    if (isInArray(commonPaths, abs)) {
                        logBypass('Bypassing Root Check for file: ' + abs);
                        return false;
                    }
                } catch (e) {
                    logWarn('File.exists hook error: ' + (e && e.message ? e.message : e));
                }
                return origExists.call(this);
            };
            logSuccess('java.io.File.exists hooked');
        } catch(e) {
            logInfo('java.io.File.exists hook failed: ' + (e && e.message ? e.message : e));
        }
    }, 'File.exists hook');

    // ApplicationPackageManager.getPackageInfo rename tweak
    safe(function() {
        try {
            const APM = Java.use('android.app.ApplicationPackageManager');
            APM.getPackageInfo.overload('java.lang.String','int').implementation = function(name, flag) {
                var catched = ['com.example.android.apis', 'com.android.development'].indexOf(name) > -1;
                if (catched) {
                    logBypass('Renaming package ' + name + ' -> fake.package.name');
                    name = 'fake.package.name';
                }
                return this.getPackageInfo.call(this, name, flag);
            };
            logSuccess('ApplicationPackageManager.getPackageInfo hooked');
        } catch(e) { logInfo('PackageManager hook unavailable: ' + (e && e.message ? e.message : e)); }
    }, 'PackageManager.getPackageInfo');

    // android_getCpuFamily native hook (if available)
    safe(function() {
        try {
            var sym = Module.findExportByName(null, 'android_getCpuFamily');
            if (sym) {
                Interceptor.attach(sym, {
                    onLeave: function(retval) {
                        try {
                            var v = retval.toInt32();
                            if ([2,5].indexOf(v) > -1) retval.replace(4);
                        } catch(e) {}
                    }
                });
                logSuccess('android_getCpuFamily hooked');
            } else {
                logInfo('android_getCpuFamily not found - skipping');
            }
        } catch(e) { logWarn('android_getCpuFamily attach error: ' + (e && e.message ? e.message : e)); }
    }, 'android_getCpuFamily');
});

// ---------- Root bypass & native file function hooks ----------
setTimeout(function() {
    logSection('Root bypass (native + Java)');

    // helper to print stack traces when needed (returns string)
    function stackTraceHere() { return getStackTraceString(); }

    safe(function bypassNativeFileCheck() {
        try {
            var fopen = Module.findExportByName('libc.so', 'fopen');
            if (fopen) {
                Interceptor.attach(fopen, {
                    onEnter: function(args) {
                        try { this.inputPath = args[0].readUtf8String(); } catch(e) { this.inputPath = null; }
                    },
                    onLeave: function(retval) {
                        try {
                            if (this.inputPath && retval.toInt32() != 0 && isInArray(commonPaths, this.inputPath)) {
                                logBypass('Anti Root Detect - fopen : ' + this.inputPath);
                                retval.replace(ptr(0x0));
                            }
                        } catch(e) {}
                    }
                });
                logSuccess('libc fopen hooked');
            } else logInfo('libc fopen not present');
        } catch(e) { logWarn('bypassNativeFileCheck fopen error: ' + (e && e.message ? e.message : e)); }

        try {
            var access = Module.findExportByName('libc.so', 'access');
            if (access) {
                Interceptor.attach(access, {
                    onEnter: function(args) { try { this.inputPath = args[0].readUtf8String(); } catch(e) { this.inputPath = null; } },
                    onLeave: function(retval) {
                        try {
                            if (this.inputPath && retval.toInt32() == 0 && isInArray(commonPaths, this.inputPath)) {
                                logBypass('Anti Root Detect - access : ' + this.inputPath);
                                retval.replace(ptr(-1));
                            }
                        } catch(e) {}
                    }
                });
                logSuccess('libc access hooked');
            } else logInfo('libc access not present');
        } catch(e) { logWarn('bypassNativeFileCheck access error: ' + (e && e.message ? e.message : e)); }
    }, 'bypassNativeFileCheck');

    safe(function bypassJavaFileCheck() {
        try {
            var UnixFileSystem = Java.use('java.io.UnixFileSystem');
            UnixFileSystem.checkAccess.implementation = function(file, access) {
                try {
                    var filename = file.getAbsolutePath();
                    if (filename.indexOf('magisk') >= 0 || isInArray(commonPaths, filename)) {
                        logBypass('Anti Root Detect - check file: ' + filename);
                        return false;
                    }
                } catch(e) { logWarn('UnixFileSystem.checkAccess error: ' + (e && e.message ? e.message : e)); }
                return this.checkAccess.call(this, file, access);
            };
            logSuccess('UnixFileSystem.checkAccess hooked');
        } catch(e) { logInfo('UnixFileSystem.checkAccess not available: ' + (e && e.message ? e.message : e)); }
    }, 'bypassJavaFileCheck');

    safe(function setProp() {
        try {
            var Build = Java.use('android.os.Build');
            try {
                var TAGS = Build.class.getDeclaredField('TAGS'); TAGS.setAccessible(true); TAGS.set(null, 'release-keys');
            } catch(e) {}
            try {
                var FINGERPRINT = Build.class.getDeclaredField('FINGERPRINT'); FINGERPRINT.setAccessible(true);
                FINGERPRINT.set(null, 'google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys');
            } catch(e) {}
        } catch(e) {}

        try {
            var system_property_get = Module.findExportByName('libc.so','__system_property_get');
            if (system_property_get) {
                Interceptor.attach(system_property_get, {
                    onEnter: function(args) { try { this.key = args[0].readCString(); this.ret = args[1]; } catch(e) { this.key = null; this.ret = null; } },
                    onLeave: function(ret) {
                        try {
                            if (this.key == 'ro.build.fingerprint') {
                                var tmp = 'google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys';
                                var p = Memory.allocUtf8String(tmp);
                                Memory.copy(this.ret, p, tmp.length + 1);
                                logBypass('__system_property_get -> ro.build.fingerprint modified');
                            }
                            if (this.key == 'ro.debuggable' || this.key == 'ro.secure') {
                                var tmp = '0'; var p = Memory.allocUtf8String(tmp);
                                Memory.copy(this.ret, p, tmp.length + 1);
                                logBypass('__system_property_get -> ' + this.key + ' modified');
                            }
                        } catch(e) {}
                    }
                });
                logSuccess('__system_property_get hooked');
            } else logInfo('__system_property_get not found');
        } catch(e) { logWarn('setProp system_property_get error: ' + (e && e.message ? e.message : e)); }
    }, 'setProp');

    safe(function bypassRootAppCheck() {
        try {
            var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
            ApplicationPackageManager.getPackageInfo.overload('java.lang.String','int').implementation = function(str, i) {
                if (isInArray(MergedRootPackages, str)) {
                    logBypass('Anti Root Detect - check package : ' + str);
                    str = 'ashen.one.ye.not.found';
                }
                return this.getPackageInfo.call(this, str, i);
            };
            logSuccess('ApplicationPackageManager.getPackageInfo (root apps) hooked');
        } catch(e) { logInfo('bypassRootAppCheck not possible: ' + (e && e.message ? e.message : e)); }
    }, 'bypassRootAppCheck');

    safe(function bypassShellCheck() {
        try {
            var StringClass = Java.use('java.lang.String');
            var ProcessImpl = Java.use('java.lang.ProcessImpl');
            ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
                try {
                    if (cmdarray && cmdarray.length > 0) {
                        var first = cmdarray[0];
                        if (first == 'mount') { logBypass('Anti Root Detect - Shell : ' + cmdarray.toString()); arguments[0] = Java.array('java.lang.String',[StringClass.$new('')]); return ProcessImpl.start.apply(this, arguments); }
                        if (first == 'getprop') { var prop = ['ro.secure','ro.debuggable']; if (prop.indexOf(cmdarray[1]) >= 0) { logBypass('Anti Root Detect - Shell : ' + cmdarray.toString()); arguments[0] = Java.array('java.lang.String',[StringClass.$new('')]); return ProcessImpl.start.apply(this, arguments); } }
                        if (first.indexOf('which') >= 0 && cmdarray[1] && cmdarray[1].indexOf('su') >= 0) { logBypass('Anti Root Detect - Shell : ' + cmdarray.toString()); arguments[0] = Java.array('java.lang.String',[StringClass.$new('')]); return ProcessImpl.start.apply(this, arguments); }
                    }
                } catch(e) { logWarn('ProcessImpl.start wrapper error: ' + (e && e.message ? e.message : e)); }
                return ProcessImpl.start.apply(this, arguments);
            };
            logSuccess('ProcessImpl.start hooked');
        } catch(e) { logInfo('bypassShellCheck not available: ' + (e && e.message ? e.message : e)); }
    }, 'bypassShellCheck');

    // Runtime.exec hooks: safer consolidation
    safe(function runtimeExecHooks() {
        try {
            var Runtime = Java.use('java.lang.Runtime');
            // hook java.lang.String overload if exists
            try {
                var execStr = Runtime.exec.overload('java.lang.String');
                execStr.implementation = function(cmd) {
                    try {
                        if (cmd && (cmd.indexOf('getprop') != -1 || cmd == 'mount' || cmd.indexOf('build.prop') != -1 || cmd == 'id' || cmd == 'sh')) {
                            logBypass('Bypass ' + cmd + ' command');
                            return execStr.call(this, 'grep');
                        }
                        if (cmd == 'su') {
                            logBypass('Bypass ' + cmd + ' command');
                            return execStr.call(this, 'justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled');
                        }
                    } catch(e) {}
                    return execStr.call(this, cmd);
                };
            } catch(e) { logInfo('Runtime.exec(java.lang.String) not hooked: ' + (e && e.message ? e.message : e)); }

            // hook String[] overload if exists
            try {
                var execArr = Runtime.exec.overload('[Ljava.lang.String;');
                execArr.implementation = function(cmd) {
                    try {
                        for (var i=0;i<cmd.length;i++){
                            var tmp = cmd[i];
                            if (tmp && (tmp.indexOf('getprop') != -1 || tmp == 'mount' || tmp.indexOf('build.prop') != -1 || tmp == 'id' || tmp == 'sh')) {
                                logBypass('Bypass ' + cmd + ' command');
                                return execArr.call(this, Java.array('java.lang.String',['grep']));
                            }
                            if (tmp == 'su') {
                                logBypass('Bypass ' + cmd + ' command');
                                return execArr.call(this, Java.array('java.lang.String',['justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled']));
                            }
                        }
                    } catch(e) {}
                    return execArr.call(this, cmd);
                };
            } catch(e) { logInfo('Runtime.exec(String[]) not hooked: ' + (e && e.message ? e.message : e)); }

            logSuccess('Runtime.exec hooks (selected) installed');
        } catch(e) { logWarn('runtimeExecHooks failed: ' + (e && e.message ? e.message : e)); }
    }, 'runtimeExecHooks');

    // String.contains tweak for test-keys
    safe(function() {
        try {
            var StringClass = Java.use('java.lang.String');
            StringClass.contains.implementation = function(name) {
                try {
                    if (name == 'test-keys') { logBypass('Bypass test-keys check'); return false; }
                } catch(e){}
                return this.contains.call(this, name);
            };
            logSuccess('java.lang.String.contains patched (test-keys)');
        } catch(e) { logInfo('String.contains patch failed: ' + (e && e.message ? e.message : e)); }
    }, 'String.contains');

    // SystemProperties.get hook for RootProperties
    safe(function() {
        try {
            var SystemProperties = Java.use('android.os.SystemProperties');
            var get = SystemProperties.get.overload('java.lang.String');
            get.implementation = function(name) {
                if (RootPropertiesKeys.indexOf(name) >= 0) {
                    logBypass('Bypass ' + name + ' -> ' + RootProperties[name]);
                    return RootProperties[name];
                }
                return this.get.call(this, name);
            };
            logSuccess('android.os.SystemProperties.get hooked');
        } catch(e) { logInfo('SystemProperties.get not available: ' + (e && e.message ? e.message : e)); }
    }, 'SystemProperties.get');

    // Intercept libc.system native calls and sanitize commands
    safe(function() {
        try {
            var systemSym = Module.findExportByName('libc.so','system');
            if (systemSym) {
                Interceptor.attach(systemSym, {
                    onEnter: function(args) {
                        try {
                            var cmd = Memory.readCString(args[0]);
                            logInfo('SYSTEM CMD: ' + cmd);
                            if (cmd.indexOf('getprop') != -1 || cmd == 'mount' || cmd.indexOf('build.prop') != -1 || cmd == 'id') {
                                logBypass('Bypass native system: ' + cmd);
                                Memory.writeUtf8String(args[0], 'grep');
                            }
                            if (cmd == 'su') {
                                logBypass('Bypass native system: ' + cmd);
                                Memory.writeUtf8String(args[0], 'justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled');
                            }
                        } catch(e) {}
                    }
                });
                logSuccess('libc.system hooked');
            } else logInfo('libc.system not found');
        } catch(e) { logWarn('libc.system attach error: ' + (e && e.message ? e.message : e)); }
    }, 'libc.system');

    // BufferedReader.readLine override (build.prop read sanitization)
    safe(function() {
        try {
            var BufferedReader = Java.use('java.io.BufferedReader');
            // Try no-arg overload first
            try {
                var readNoArg = BufferedReader.readLine.overload();
                readNoArg.implementation = function() {
                    var text = readNoArg.call(this);
                    try {
                        if (text !== null) {
                            if (text.indexOf('ro.build.tags=test-keys') > -1) {
                                logBypass('Bypass build.prop file read');
                                text = text.replace('ro.build.tags=test-keys','ro.build.tags=release-keys');
                            }
                        }
                    } catch(e){}
                    return text;
                };
                logSuccess('BufferedReader.readLine() hooked');
            } catch(e) { /* no no-arg overload */ }

            // If there's a boolean overload (some runtimes), try it
            try {
                var readBool = BufferedReader.readLine.overload('boolean');
                readBool.implementation = function(b) {
                    var text = readBool.call(this, b);
                    try {
                        if (text !== null) {
                            if (text.indexOf('ro.build.tags=test-keys') > -1) {
                                logBypass('Bypass build.prop file read (boolean overload)');
                                text = text.replace('ro.build.tags=test-keys','ro.build.tags=release-keys');
                            }
                        }
                    } catch(e){}
                    return text;
                };
                logSuccess('BufferedReader.readLine(boolean) hooked');
            } catch(e) {}
        } catch(e) { logInfo('BufferedReader.readLine hooking not available: ' + (e && e.message ? e.message : e)); }
    }, 'BufferedReader.readLine');

    logSuccess('Root bypass module attached');
}, 0);


// ---------- SSL pinning bypass module ----------
setTimeout(function() {
    Java.perform(function() {
        logSection('SSL Pinning Bypass');
        logInfo('Unpinning Android app...');

        // Robust SSLPeerUnverifiedException auto-patcher
        safe(function() {
            try {
                const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
                // Patch constructors that accept String and (String, Throwable)
                try {
                    UnverifiedCertError.$init.overload('java.lang.String').implementation = function(str) {
                        // Print a short stack trace for debugging and attempt auto-patch (best-effort)
                        logWarn('SSLPeerUnverifiedException raised: ' + (str || 'no-message'));
                        var st = getStackTraceString();
                        logInfo('Stacktrace (short):\n' + st.split('\n').slice(0,8).join('\n'));
                        // attempt to discover caller and patch (best-effort)
                        try {
                            var Thread = Java.use('java.lang.Thread');
                            var frames = Thread.currentThread().getStackTrace();
                            if (frames && frames.length > 0) {
                                // find first non-JDK frame - best-effort heuristic
                                var idx = -1;
                                for (var i=0;i<frames.length;i++){
                                    var cname = frames[i].getClassName();
                                    if (cname && cname.indexOf('java.') !== 0 && cname.indexOf('javax.') !== 0 && cname.indexOf('sun.') !== 0 && cname.indexOf('dalvik.') !== 0 && cname.indexOf('android.') !== 0) { idx = i; break; }
                                }
                                if (idx > -1 && frames[idx]) {
                                    var calling = frames[idx];
                                    var className = calling.getClassName();
                                    var methodName = calling.getMethodName();
                                    logInfo('Attempting to auto-patch caller: ' + className + ' -> ' + methodName);
                                    try {
                                        var Calling = Java.use(className);
                                        if (Calling[methodName]) {
                                            // store original implementation if needed
                                            try {
                                                Calling[methodName].implementation = function() {
                                                    logBypass('Auto-patch: bypassing ' + className + '->' + methodName);
                                                    // safest: return default value based on return type if possible, else null/void
                                                    return null;
                                                };
                                                logSuccess('Auto-patched ' + className + '->' + methodName);
                                            } catch(e) { logWarn('Auto-patch failed: ' + (e && e.message ? e.message : e)); }
                                        }
                                    } catch(e) { logWarn('Auto-patch reflection error: ' + (e && e.message ? e.message : e)); }
                                }
                            }
                        } catch(e) {}
                        return this.$init(str);
                    };
                } catch(e) { /* constructor not present or different signature */ }

                // Also try to patch two-arg constructor if present
                try {
                    UnverifiedCertError.$init.overload('java.lang.String','java.lang.Throwable').implementation = function(s,t) {
                        logWarn('SSLPeerUnverifiedException (2-arg) raised: ' + (s || 'no-message'));
                        logInfo(getStackTraceString());
                        return this.$init(s,t);
                    };
                } catch(e) {}

                logSuccess('SSLPeerUnverifiedException auto-patcher installed');
            } catch(e) { logInfo('SSLPeerUnverifiedException class not present: ' + (e && e.message ? e.message : e)); }
        }, 'SSLPeerUnverifiedException auto-patcher');

        // Convenience wrapper for guarded installations
        const installGuarded = function(title, fn) { safe(fn, title); };

        installGuarded('HttpsURLConnection.setDefaultHostnameVerifier', function() {
            try {
                const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) { logBypass('Bypassing HttpsURLConnection (setDefaultHostnameVerifier)'); return; };
                logSuccess('HttpsURLConnection.setDefaultHostnameVerifier patched');
            } catch(e) { logInfo('HttpsURLConnection.setDefaultHostnameVerifier not present'); }
        });

        installGuarded('HttpsURLConnection.setSSLSocketFactory', function() {
            try {
                const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) { logBypass('Bypassing HttpsURLConnection (setSSLSocketFactory)'); return; };
                logSuccess('HttpsURLConnection.setSSLSocketFactory patched');
            } catch(e) { logInfo('HttpsURLConnection.setSSLSocketFactory not present'); }
        });

        installGuarded('HttpsURLConnection.setHostnameVerifier', function() {
            try {
                const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) { logBypass('Bypassing HttpsURLConnection (setHostnameVerifier)'); return; };
                logSuccess('HttpsURLConnection.setHostnameVerifier patched');
            } catch(e) { logInfo('HttpsURLConnection.setHostnameVerifier not present'); }
        });

        // Trust manager & SSLContext generic override
        installGuarded('SSLContext.init override', function() {
            try {
                const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                const SSLContext = Java.use('javax.net.ssl.SSLContext');
                const TrustManager = Java.registerClass({
                    name: 'dev.asd.test.TrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                const TrustManagers = [TrustManager.$new()];
                const SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    logBypass('Bypassing TrustManager (SSLContext.init)');
                    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                };
                logSuccess('SSLContext.init patched');
            } catch(e) { logInfo('SSLContext.init hook failed: ' + (e && e.message ? e.message : e)); }
        });

        installGuarded('TrustManagerImpl (conscrypt) overrides', function() {
            try {
                const array_list = Java.use('java.util.ArrayList');
                const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                try {
                    TrustManagerImpl.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) { logBypass('Bypassing TrustManagerImpl.checkTrustedRecursive'); return array_list.$new(); };
                    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) { logBypass('Bypassing TrustManagerImpl.verifyChain for: ' + host); return untrustedChain; };
                    logSuccess('TrustManagerImpl overrides installed');
                } catch(e) { logInfo('TrustManagerImpl API mismatch or not present'); }
            } catch(e) { logInfo('TrustManagerImpl not available on this runtime'); }
        });

        // OkHttp v3 CertificatePinner hooks (several overloads)
        installGuarded('OkHTTP CertificatePinner', function() {
            try {
                const CP = Java.use('okhttp3.CertificatePinner');
                try { CP.check.overload('java.lang.String','java.util.List').implementation = function(a,b) { logBypass('Bypassing OkHTTPv3 (list): ' + a); return; }; } catch(e){}
                try { CP.check.overload('java.lang.String','java.security.cert.Certificate').implementation = function(a,b) { logBypass('Bypassing OkHTTPv3 (cert): ' + a); return; }; } catch(e){}
                try { CP.check.overload('java.lang.String','[Ljava.security.cert.Certificate;').implementation = function(a,b) { logBypass('Bypassing OkHTTPv3 (cert array): ' + a); return; }; } catch(e){}
                try { CP['check$okhttp'] && (CP['check$okhttp'].implementation = function(a,b){ logBypass('Bypassing OkHTTPv3 ($okhttp): ' + a); return; }); } catch(e){}
                logSuccess('OkHTTPv3 CertificatePinner patched');
            } catch(e) { logInfo('okhttp3.CertificatePinner not present'); }
        });

        // Best-effort guarded hooks for other libraries
        const guardedTargets = [
            {name: 'Trustkit OkHostnameVerifier', path: 'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', fn: function(cls){ try{ cls.verify.overload('java.lang.String','javax.net.ssl.SSLSession').implementation = function(a,b){ logBypass('Bypassing Trustkit OkHostnameVerifier(SSLSession): '+a); return true; }; cls.verify.overload('java.lang.String','java.security.cert.X509Certificate').implementation = function(a,b){ logBypass('Bypassing Trustkit OkHostnameVerifier(cert): '+a); return true; }; }catch(e){} }},
            {name: 'Appmattus CT', path: 'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor', fn: function(cls){ try{ cls['intercept'].implementation = function(a){ logBypass('Bypassing Appmattus (CertificateTransparencyInterceptor)'); return a.proceed(a.request()); }; }catch(e){} }},
            {name: 'OpenSSLSocketImpl (conscrypt)', path: 'com.android.org.conscrypt.OpenSSLSocketImpl', fn: function(cls){ try{ cls.verifyCertificateChain.implementation = function(){ logBypass('Bypassing OpenSSLSocketImpl Conscrypt'); }; }catch(e){} }},
            {name: 'Worklight HostNameVerifier', path: 'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', fn: function(cls){ try{ cls.verify.overload('java.lang.String','javax.net.ssl.SSLSocket').implementation = function(a,b){ logBypass('Bypassing WorkLight HostNameVerifier (SSLSocket): '+a); return; }; cls.verify.overload('java.lang.String','javax.net.ssl.SSLSession').implementation = function(a,b){ logBypass('Bypassing WorkLight HostNameVerifier (SSLSession): '+a); return true; }; }catch(e){} }},
            {name: 'PhoneGap sslCertificateChecker', path: 'nl.xservices.plugins.sslCertificateChecker', fn: function(cls){ try{ cls.execute.overload('java.lang.String','org.json.JSONArray','org.apache.cordova.CallbackContext').implementation = function(a,b,c){ logBypass('Bypassing PhoneGap sslCertificateChecker: '+a); return true; }; }catch(e){} }}
        ];

        guardedTargets.forEach(function(t){
            try { let Cls = Java.use(t.path); t.fn(Cls); logSuccess(t.name + ' patched'); } catch(e) { logInfo(t.name + ' not present'); }
        });

        logSuccess('Unpinning setup completed');
        logSection('SSL Pinning Bypass (complete)');
    });
}, 0);

// ---------- END ----------
