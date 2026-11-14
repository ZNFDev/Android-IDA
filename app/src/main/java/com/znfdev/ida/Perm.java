package com.znfdev.ida;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;

import java.util.ArrayList;

/** Storage permission handling. API 30+ "all files access" is reached via reflection (compileSdk is 29). */
public final class Perm {
    private Perm() {}

    public static boolean haveRead(Context c) {
        if (Build.VERSION.SDK_INT < 23) return true;
        if (Build.VERSION.SDK_INT >= 33) return true;
        return c.checkSelfPermission("android.permission.READ_EXTERNAL_STORAGE") == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean haveWrite(Context c) {
        if (Build.VERSION.SDK_INT < 23) return true;
        if (Build.VERSION.SDK_INT >= 30) return false;   // handled by "all files access" instead
        return c.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean haveAllFiles() {
        if (Build.VERSION.SDK_INT < 30) return false;
        try {
            return (Boolean) Environment.class.getMethod("isExternalStorageManager").invoke(null);
        } catch (Exception e) { return false; }
    }

    public static boolean canReadFiles(Context c) {
        if (Build.VERSION.SDK_INT >= 30) return haveAllFiles();
        return haveRead(c);
    }

    /** Legacy READ/WRITE runtime request (API 23..29). */
    public static void requestBasics(Activity a) {
        if (Build.VERSION.SDK_INT < 23) return;
        ArrayList<String> want = new ArrayList<String>();
        if (!haveRead(a)) want.add("android.permission.READ_EXTERNAL_STORAGE");
        if (Build.VERSION.SDK_INT < 30 && !haveWrite(a)) want.add("android.permission.WRITE_EXTERNAL_STORAGE");
        if (want.isEmpty()) return;
        a.requestPermissions(want.toArray(new String[want.size()]), 901);
    }

    /** Open the system "All files access" screen (API 30+). */
    public static void requestAllFiles(Activity a) {
        if (Build.VERSION.SDK_INT < 30) return;
        try {
            Intent i = new Intent("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION");
            i.setData(Uri.parse("package:" + a.getPackageName()));
            a.startActivity(i);
        } catch (Exception e) {
            try { a.startActivity(new Intent("android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION")); } catch (Exception e2) { }
        }
    }

    public static void explain(final Activity a) {
        StringBuilder sb = new StringBuilder();
        sb.append("Read: ").append(haveRead(a) ? "granted" : "not granted").append('\n');
        if (Build.VERSION.SDK_INT >= 30) sb.append("All files access: ").append(haveAllFiles() ? "granted" : "not granted").append('\n');
        else sb.append("Write: ").append(haveWrite(a) ? "granted" : "not granted").append('\n');
        sb.append("\nNeeded to open ELF files and save analysis databases.");
        new AlertDialog.Builder(a, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Storage permissions").setMessage(sb.toString())
            .setPositiveButton("Grant", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) {
                    if (Build.VERSION.SDK_INT >= 30 && !haveAllFiles()) requestAllFiles(a);
                    else requestBasics(a);
                }
            }).setNegativeButton("Close", null).show();
    }
}
