package com.znfdev.ida;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import java.util.ArrayList;

/** Persistent app database: recent files and per-file UI state. */
public final class IdaDatabase {
    private final SQLiteDatabase db;

    public IdaDatabase(Context c) {
        db = c.openOrCreateDatabase("ida.db", 0, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS recents (path TEXT PRIMARY KEY, name TEXT, size INTEGER, mtime INTEGER, last INTEGER)");
        db.execSQL("CREATE TABLE IF NOT EXISTS uistate (path TEXT PRIMARY KEY, cursor INTEGER, hex_addr INTEGER, tab INTEGER)");
    }

    public void touch(String path, String name, long size, long mtime) {
        ContentValues v = new ContentValues();
        v.put("path", path); v.put("name", name); v.put("size", size); v.put("mtime", mtime);
        v.put("last", System.currentTimeMillis());
        db.insertWithOnConflict("recents", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    /** path \1 name \1 size \1 mtime \1 last, newest first. */
    public ArrayList<String[]> recents(int limit) {
        ArrayList<String[]> out = new ArrayList<String[]>();
        Cursor c = db.query("recents", new String[]{"path", "name", "size", "mtime", "last"},
                null, null, null, null, "last DESC", String.valueOf(limit));
        try {
            while (c.moveToNext()) out.add(new String[]{c.getString(0), c.getString(1),
                    String.valueOf(c.getLong(2)), String.valueOf(c.getLong(3)), String.valueOf(c.getLong(4))});
        } finally { c.close(); }
        return out;
    }

    public void remove(String path) {
        db.delete("recents", "path=?", new String[]{path});
        db.delete("uistate", "path=?", new String[]{path});
    }

    public void setUi(String path, long cursor, long hex, int tab) {
        ContentValues v = new ContentValues();
        v.put("path", path); v.put("cursor", cursor); v.put("hex_addr", hex); v.put("tab", tab);
        db.insertWithOnConflict("uistate", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    /** {cursor, hex, tab} or null. */
    public long[] getUi(String path) {
        Cursor c = db.query("uistate", new String[]{"cursor", "hex_addr", "tab"}, "path=?", new String[]{path}, null, null, null);
        try { if (c.moveToFirst()) return new long[]{c.getLong(0), c.getLong(1), c.getLong(2)}; } finally { c.close(); }
        return null;
    }

    public void close() { try { db.close(); } catch (Exception e) { } }
}
