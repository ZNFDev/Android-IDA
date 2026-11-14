package com.znfdev.ida;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Map;

/** IDA-style main window: menu bar, toolbar, navigation band, tabs, output window, status bar. */
public class MainActivity extends Activity implements DisasmView.Host, Session.Listener {

    private static final int REQ_OPEN = 71;
    private static final String[] TAB_NAMES = {"IDA View-A", "Pseudocode-A", "Hex View-A", "Functions", "Strings", "Imports", "Exports", "Names", "Segments"};

    private final Session s = new Session();
    private DisasmView dv;
    private HexView hv;
    private PseudoView pv;
    private NavBand nb;
    private final TableView[] tables = new TableView[6];
    private final View[] tabViews = new View[9];
    private final TextView[] tabLabels = new TextView[9];
    private int curTab = 0;
    private TextView statusLeft, statusRight, outText, outTitle;
    private ScrollView outScroll;
    private LinearLayout outPanel;
    private TextView btnBack, btnFwd;
    private volatile boolean searchCancel;
    private String lastNeedle = "";
    private IdaDatabase dbh;
    private final AnalysisEngine eng = new AnalysisEngine();
    private String snapPath;
    private int lastLoggedPct;
    private volatile long lastTblMs;

    private final AnalysisEngine.Listener engListener = new AnalysisEngine.Listener() {
        public void onProgress(int pct, int stage) { setAStatus(pct, stage); }
        public void onCheckpoint() { onCheckpointNow(); }
        public void onDone(long ms, boolean cancelled) {
            if (cancelled) log("Analysis cancelled - progress saved to the database.");
            else log("The initial autoanalysis has been finished. (" + ms + " ms)");
            rebuildAllTables();
            statusLeft.setText("AU: idle");
            lastLoggedPct = 0;
        }
        public void onError(String err) { log("Analysis error: " + err); }
    };

    // ---- construction ------------------------------------------------------------------------

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(Theme.PANEL);
        getWindow().setNavigationBarColor(Theme.PANEL);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Theme.BG);
        root.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            public WindowInsets onApplyWindowInsets(View v, WindowInsets in) {
                v.setPadding(in.getSystemWindowInsetLeft(), in.getSystemWindowInsetTop(), in.getSystemWindowInsetRight(), in.getSystemWindowInsetBottom());
                return in.consumeSystemWindowInsets();
            }
        });

        root.addView(buildMenuBar(), lp(-1, -2));
        root.addView(buildToolbar(), lp(-1, -2));
        nb = new NavBand(this, s);
        root.addView(nb, lp(-1, -2));
        root.addView(buildTabStrip(), lp(-1, -2));

        FrameLayout content = new FrameLayout(this);
        dv = new DisasmView(this, s); dv.setHost(this);
        hv = new HexView(this, s);
        pv = new PseudoView(this, s);
        tabViews[0] = dv; tabViews[1] = pv; tabViews[2] = hv;
        tables[0] = functionsTable(); tables[1] = stringsTable(); tables[2] = importsTable();
        tables[3] = exportsTable(); tables[4] = namesTable(); tables[5] = segmentsTable();
        for (int i = 0; i < 6; i++) tabViews[3 + i] = tables[i];
        for (int i = 0; i < 9; i++) {
            content.addView(tabViews[i], new FrameLayout.LayoutParams(-1, -1));
            tabViews[i].setVisibility(i == 0 ? View.VISIBLE : View.GONE);
        }
        root.addView(content, new LinearLayout.LayoutParams(-1, 0, 1f));
        root.addView(buildOutput(), lp(-1, -2));
        root.addView(buildStatus(), lp(-1, -2));
        setContentView(root);

        s.addListener(this);
        dbh = new IdaDatabase(this);
        Perm.requestBasics(this);
        selectTab(0);
        log("IDA for Android - AArch64 ELF analysis core");
        log("Use File > Open to load a shared object (.so).");
        handleIntent(getIntent());
    }

    @Override protected void onNewIntent(Intent i) { super.onNewIntent(i); handleIntent(i); }

    private void handleIntent(Intent i) {
        if (i != null && Intent.ACTION_VIEW.equals(i.getAction()) && i.getData() != null) openUri(i.getData());
    }

    private static LinearLayout.LayoutParams lp(int w, int h) { return new LinearLayout.LayoutParams(w, h); }

    private TextView label(String t, int color, float sp) {
        TextView v = new TextView(this);
        v.setText(t); v.setTextColor(color); v.setTextSize(sp);
        v.setTypeface(Theme.mono(this));
        v.setSingleLine(true);
        return v;
    }

    private View buildMenuBar() {
        HorizontalScrollView hs = new HorizontalScrollView(this);
        hs.setBackgroundColor(Theme.PANEL);
        hs.setHorizontalScrollBarEnabled(false);
        LinearLayout row = new LinearLayout(this);
        String[] names = {"File", "Edit", "Jump", "Search", "View", "Debugger", "Options", "Windows", "Help"};
        for (final String n : names) {
            final TextView t = label(n, Theme.TEXT, 13);
            t.setTypeface(android.graphics.Typeface.DEFAULT);
            t.setPadding(Theme.dp(this, 12), Theme.dp(this, 9), Theme.dp(this, 12), Theme.dp(this, 9));
            t.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { showMenu(n, t); } });
            row.addView(t);
        }
        hs.addView(row);
        return hs;
    }

    private View buildToolbar() {
        HorizontalScrollView hs = new HorizontalScrollView(this);
        hs.setBackgroundColor(Theme.BG_ALT);
        hs.setHorizontalScrollBarEnabled(false);
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        btnBack = tool("\u25C0", new View.OnClickListener() { public void onClick(View v) { s.back(MainActivity.this); } });
        btnFwd = tool("\u25B6", new View.OnClickListener() { public void onClick(View v) { s.forward(MainActivity.this); } });
        row.addView(btnBack); row.addView(btnFwd);
        row.addView(tool("Open", new View.OnClickListener() { public void onClick(View v) { openChooser(); } }));
        row.addView(tool("F5", new View.OnClickListener() { public void onClick(View v) { selectTab(1); } }));
        row.addView(tool("Go to", new View.OnClickListener() { public void onClick(View v) { jumpDialog(); } }));
        row.addView(tool("Xrefs", new View.OnClickListener() { public void onClick(View v) { xrefsHere(); } }));
        row.addView(tool("Search", new View.OnClickListener() { public void onClick(View v) { searchDialog(); } }));
        row.addView(tool("A-", new View.OnClickListener() { public void onClick(View v) { Toast.makeText(MainActivity.this, "Pinch the listing to zoom", Toast.LENGTH_SHORT).show(); } }));
        hs.addView(row);
        updateNavButtons();
        return hs;
    }

    private TextView tool(String t, View.OnClickListener l) {
        TextView v = label(t, Theme.TEXT, 13);
        v.setTypeface(android.graphics.Typeface.DEFAULT);
        v.setPadding(Theme.dp(this, 12), Theme.dp(this, 7), Theme.dp(this, 12), Theme.dp(this, 7));
        v.setOnClickListener(l);
        return v;
    }

    private void updateNavButtons() {
        if (btnBack == null) return;
        btnBack.setAlpha(s.canBack() ? 1f : 0.35f);
        btnFwd.setAlpha(s.canForward() ? 1f : 0.35f);
    }

    private View buildTabStrip() {
        HorizontalScrollView hs = new HorizontalScrollView(this);
        hs.setBackgroundColor(Theme.PANEL);
        hs.setHorizontalScrollBarEnabled(false);
        LinearLayout row = new LinearLayout(this);
        for (int i = 0; i < TAB_NAMES.length; i++) {
            final int idx = i;
            TextView t = label(TAB_NAMES[i], Theme.TEXT_DIM, 12);
            t.setTypeface(android.graphics.Typeface.DEFAULT);
            t.setPadding(Theme.dp(this, 14), Theme.dp(this, 8), Theme.dp(this, 14), Theme.dp(this, 8));
            t.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { selectTab(idx); } });
            tabLabels[i] = t;
            row.addView(t);
        }
        hs.addView(row);
        return hs;
    }

    private View buildOutput() {
        outPanel = new LinearLayout(this);
        outPanel.setOrientation(LinearLayout.VERTICAL);
        outPanel.setBackgroundColor(Theme.BG_ALT);
        outTitle = label("Output", Theme.TEXT, 11);
        outTitle.setTypeface(android.graphics.Typeface.DEFAULT);
        outTitle.setBackgroundColor(Theme.PANEL);
        outTitle.setPadding(Theme.dp(this, 10), Theme.dp(this, 3), Theme.dp(this, 10), Theme.dp(this, 3));
        outPanel.addView(outTitle, lp(-1, -2));
        outScroll = new ScrollView(this);
        outText = label("", Theme.TEXT, 11);
        outText.setSingleLine(false);
        outText.setPadding(Theme.dp(this, 10), Theme.dp(this, 2), Theme.dp(this, 10), Theme.dp(this, 2));
        outScroll.addView(outText);
        outPanel.addView(outScroll, lp(-1, Theme.dp(this, 64)));
        final EditText cmd = new EditText(this);
        cmd.setSingleLine(true); cmd.setHint("g <addr|name>   x <name>   find <text>");
        cmd.setTextColor(Theme.TEXT); cmd.setHintTextColor(Theme.TEXT_DIM);
        cmd.setTypeface(Theme.mono(this)); cmd.setTextSize(12);
        cmd.setBackgroundColor(Theme.BG);
        cmd.setImeOptions(EditorInfo.IME_ACTION_GO);
        cmd.setPadding(Theme.dp(this, 10), Theme.dp(this, 5), Theme.dp(this, 10), Theme.dp(this, 5));
        cmd.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int id, KeyEvent e) {
                runCommand(v.getText().toString().trim()); v.setText(""); return true;
            }
        });
        outPanel.addView(cmd, lp(-1, -2));
        outTitle.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                boolean show = outScroll.getVisibility() != View.VISIBLE;
                outScroll.setVisibility(show ? View.VISIBLE : View.GONE);
                cmd.setVisibility(show ? View.VISIBLE : View.GONE);
            }
        });
        return outPanel;
    }

    private View buildStatus() {
        LinearLayout row = new LinearLayout(this);
        row.setBackgroundColor(Theme.PANEL);
        row.setPadding(Theme.dp(this, 8), Theme.dp(this, 4), Theme.dp(this, 8), Theme.dp(this, 4));
        statusLeft = label("AU: idle   Down", Theme.TEXT, 11);
        statusRight = label("", Theme.C_PREFIX, 11);
        statusRight.setGravity(Gravity.RIGHT);
        statusRight.setEllipsize(android.text.TextUtils.TruncateAt.START);
        row.addView(statusLeft, new LinearLayout.LayoutParams(-2, -2));
        row.addView(statusRight, new LinearLayout.LayoutParams(0, -2, 1f));
        return row;
    }

    private void selectTab(int i) {
        curTab = i;
        for (int k = 0; k < tabViews.length; k++) tabViews[k].setVisibility(k == i ? View.VISIBLE : View.GONE);
        for (int k = 0; k < tabLabels.length; k++) {
            tabLabels[k].setTextColor(k == i ? Theme.TEXT : Theme.TEXT_DIM);
            tabLabels[k].setBackgroundColor(k == i ? Theme.BG : Theme.PANEL);
        }
        if (s.isOpen()) {
            if (i == 0 && dv != null) dv.syncTo(s.cur);
            if (i == 1 && pv != null) pv.showAt(s.cur);
            if (i == 2) hv.showAt(s.cur);
        }
    }

    // ---- logging / status --------------------------------------------------------------------

    private void log(String t) {
        outText.append(t + "\n");
        outScroll.post(new Runnable() { public void run() { outScroll.fullScroll(View.FOCUS_DOWN); } });
    }

    @Override public void onAddress(long addr, Object source) {
        statusRight.setText(s.segName(addr) + ":" + Fmt.hex16(addr) + "  " + s.describe(addr));
        eng.hexAddr = addr;
        updateNavButtons();
    }

    @Override public void onMessage(String m) { Toast.makeText(this, m, Toast.LENGTH_SHORT).show(); }

    @Override public void onXrefs(long addr, String name) { XrefDialog.show(this, s, addr, name, this); }

    @Override public void onHexAt(long addr) { eng.hexAddr = addr; s.setCursor(addr, this); selectTab(2); }

    // ---- menus -------------------------------------------------------------------------------

    private void showMenu(String name, View anchor) {
        PopupMenu pm = new PopupMenu(this, anchor);
        Menu m = pm.getMenu();
        if (name.equals("File")) {
            m.add(0, 1, 0, "Open...");
            m.add(0, 4, 1, "Recent files");
            m.add(0, 5, 2, "Save database");
            m.add(0, 6, 3, "Produce file");
            m.add(0, 2, 4, "Close");
            m.add(0, 3, 5, "Exit");
        } else if (name.equals("Edit")) {
            m.add(0, 10, 0, "Copy address");
            m.add(0, 11, 1, "Clear output");
        } else if (name.equals("Jump")) {
            m.add(0, 20, 0, "Jump to address...");
            m.add(0, 21, 1, "Jump to entry point");
            m.add(0, 22, 2, "Jump to function...");
            m.add(0, 23, 3, "Jump to xref to operand...");
            m.add(0, 24, 4, "Jump back");
            m.add(0, 25, 5, "Jump forward");
        } else if (name.equals("Search")) {
            m.add(0, 30, 0, "Text...");
            m.add(0, 31, 1, "Next text");
            m.add(0, 32, 2, "Next code");
            m.add(0, 33, 3, "Signature maker");
        } else if (name.equals("View")) {
            m.add(0, 40, 0, "Open subviews: Hex dump");
            m.add(0, 41, 1, "Open subviews: Strings");
            m.add(0, 42, 2, "Open subviews: Names");
            m.add(0, 43, 3, "Open subviews: Segments");
            m.add(0, 44, 4, "Toggle Output window");
            m.add(0, 45, 5, "Open subviews: Pseudocode");
        } else if (name.equals("Windows")) {
            for (int i = 0; i < TAB_NAMES.length; i++) m.add(1, 100 + i, i, TAB_NAMES[i]);
        } else if (name.equals("Options")) {
            m.add(0, 60, 0, "Storage permissions...");
            m.add(0, 61, 1, "Cancel analysis");
            m.add(0, 62, 2, "Resume analysis");
        } else if (name.equals("Help")) {
            m.add(0, 90, 0, "About");
        } else {
            m.add(0, 99, 0, name + " is not available in this build");
        }
        pm.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
            public boolean onMenuItemClick(MenuItem it) { menuAction(it.getItemId()); return true; }
        });
        pm.show();
    }

    private void menuAction(int id) {
        if (id >= 100 && id < 109) { selectTab(id - 100); return; }
        switch (id) {
            case 1: openChooser(); break;
            case 2: closeDb(); break;
            case 3: finish(); break;
            case 4: showRecents(); break;
            case 5: saveDatabase(); break;
            case 6: produceFile(); break;
            case 60: Perm.explain(this); break;
            case 61: if (eng.busy()) eng.cancel(); else onMessage("No analysis running"); break;
            case 62: if (eng.isPaused()) eng.resume(); else onMessage("Analysis is not paused"); break;
            case 10: if (s.isOpen()) { android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                     cm.setPrimaryClip(android.content.ClipData.newPlainText("addr", Fmt.hex16(s.cur))); onMessage("Copied"); } break;
            case 11: outText.setText(""); break;
            case 20: jumpDialog(); break;
            case 21: if (need()) { long e = firstCode(); s.jump(e, this); selectTab(0); } break;
            case 22: selectTab(3); break;
            case 23: xrefsHere(); break;
            case 24: s.back(this); break;
            case 25: s.forward(this); break;
            case 30: searchDialog(); break;
            case 31: if (lastNeedle.length() > 0) searchText(lastNeedle, true); else searchDialog(); break;
            case 32: nextCode(); break;
            case 33: sigDialog(); break;
            case 40: selectTab(2); break;
            case 41: selectTab(4); break;
            case 42: selectTab(7); break;
            case 43: selectTab(8); break;
            case 44: outTitle.performClick(); break;
            case 45: selectTab(1); break;
            case 90: new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
                    .setTitle("IDA for Android")
                    .setMessage("AArch64 ELF disassembler. Native core: libidacore.so (C++17). UI: IDA View, Hex View, Functions, Strings, Imports, Exports, Names, Segments.")
                    .setPositiveButton("OK", null).show(); break;
            default: break;
        }
    }

    private boolean need() {
        if (!s.isOpen()) { onMessage("Open a file first"); return false; }
        return true;
    }

    private long firstCode() {
        for (Session.Seg g : s.segs) if (g.exec()) return g.start;
        return s.minAddr();
    }

    // ---- opening files -----------------------------------------------------------------------

    private void openChooser() {
        new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Open")
            .setItems(new String[]{"Browse files...", "Enter path..."}, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int which) {
                    if (which == 0) {
                        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType("*/*");
                        startActivityForResult(i, REQ_OPEN);
                    } else pathDialog();
                }
            }).show();
    }

    private void pathDialog() {
        final EditText et = new EditText(this);
        et.setSingleLine(true); et.setHint("/sdcard/Download/libfoo.so");
        et.setTextColor(Theme.TEXT); et.setHintTextColor(Theme.TEXT_DIM); et.setTypeface(Theme.mono(this));
        new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Open path").setView(et)
            .setPositiveButton("Open", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) { openPath(et.getText().toString().trim()); }
            }).setNegativeButton("Cancel", null).show();
    }

    @Override protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_OPEN && res == RESULT_OK && data != null && data.getData() != null) openUri(data.getData());
    }

    private void openUri(final Uri uri) {
        final ProgressDialog pd = ProgressDialog.show(this, "", "Copying file...", true, false);
        new Thread(new Runnable() { public void run() {
            String out = null; String err = null;
            try {
                ContentResolver cr = getContentResolver();
                String name = "input.so";
                Cursor c = cr.query(uri, null, null, null, null);
                if (c != null) { try { if (c.moveToFirst()) { int ix = c.getColumnIndex(OpenableColumns.DISPLAY_NAME); if (ix >= 0) name = c.getString(ix); } } finally { c.close(); } }
                File dir = new File(getExternalFilesDir(null), "inbox");
                if (!dir.exists()) dir.mkdirs();
                File f = new File(dir, name.replace('/', '_'));
                InputStream in = cr.openInputStream(uri);
                OutputStream os = new FileOutputStream(f);
                byte[] buf = new byte[65536]; int n;
                while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
                os.close(); in.close();
                out = f.getAbsolutePath();
            } catch (Exception e) { err = "Cannot read file: " + e; }
            final String fo = out, fe = err;
            runOnUiThread(new Runnable() { public void run() {
                pd.dismiss();
                if (fo != null) openPath(fo); else log(fe);
            }});
        }}).start();
    }

    /** Opens live on a worker thread: partial analysis shows immediately, analysis continues in the background. */
    private void openPath(final String path) {
        if (path.length() == 0) return;
        final File f = new File(path);
        final ProgressDialog pd = ProgressDialog.show(this, "", "Loading " + f.getName() + "...", true, false);
        log("Loading " + path);
        new Thread(new Runnable() { public void run() {
            String err = null;
            try {
                if (eng.busy()) eng.stopAndWait();
                saveUiState();
                if (!f.canRead()) err = "Cannot read " + path + " (storage permission?)";
                else {
                    String sp = snapPathFor(path);
                    err = s.openLive(path, sp);
                    if (err == null) snapPath = sp;
                }
            } catch (Throwable t) { err = "Open failed: " + t; }
            final String ferr = err;
            runOnUiThread(new Runnable() { public void run() {
                pd.dismiss();
                if (ferr != null) { log("Failed: " + ferr); onMessage(ferr); return; }
                afterOpen(path, f);
            }});
        }}, "ida-open").start();
    }

    /** UI thread: runs once the native open finished. */
    private void afterOpen(String path, File f) {
        dbh.touch(path, f.getName(), f.length(), f.lastModified());
        log("Detected AArch64 ELF (machine " + s.machine + "), " + s.segs.length + " loadable sections.");
        if (s.resumed) log("Analysis resumed from the saved database.");
        // restore UI state: native snapshot cursor first, then the app UI-state table
        long cur = firstCode(), hex = cur; int tab = 0;
        if (s.resumed) {
            String[] sp = Fmt.split(NativeBridge.savedPos(s.h));
            if (sp.length > 0 && sp[0].length() > 0) { long a = Fmt.parseHex(sp[0]); if (a > 0) cur = a; }
            if (sp.length > 1 && sp[1].length() > 0) { long a = Fmt.parseHex(sp[1]); hex = a > 0 ? a : cur; }
        }
        long[] ui = dbh.getUi(path);
        if (ui != null) {
            if (ui[0] > 0) cur = ui[0];
            if (ui[1] > 0) hex = ui[1];
            tab = (int) ui[2];
            if (tab < 0 || tab >= tabViews.length) tab = 0;
        }
        s.setCursor(cur, this);
        eng.hexAddr = hex;
        selectTab(tab);
        if (tab == 2) hv.showAt(hex);
        String[] st = Fmt.split(NativeBridge.liveState(s.h));
        if (st.length > 0 && st[0].equals("1")) {
            log("The initial autoanalysis has been finished.");
            rebuildAllTables();
            return;
        }
        lastLoggedPct = 0;
        eng.start(s, snapPath, engListener);
        if (!eng.busy()) log("Warning: analysis engine did not start");
    }

    private void closeDb() {
        if (eng.busy()) eng.stopAndWait();
        saveUiState();
        eng.saveNow();
        s.close();
        for (int i = 0; i < 6; i++) tables[i].setRows(new ArrayList<String[]>());
        dv.invalidate(); hv.invalidate(); nb.rebuild();
        statusRight.setText("");
        statusLeft.setText("AU: idle");
        lastLoggedPct = 0;
        log("Database closed.");
    }

    // ---- persistence helpers -----------------------------------------------------------------

    /** Writes the current UI position into the app database. */
    private void saveUiState() {
        if (!s.isOpen() || dbh == null || s.path.length() == 0) return;
        long hex = hv.shownAddr() > 0 ? hv.shownAddr() : eng.hexAddr;
        if (hex <= 0) hex = s.cur;
        dbh.setUi(s.path, s.cur, hex, curTab);
    }

    /** Snapshot next to the file when writable, else in the app's external files area. */
    private String snapPathFor(String path) {
        File f = new File(path);
        File dir = f.getParentFile();
        if (dir != null && dir.canWrite()) return new File(dir, f.getName() + ".ida").getAbsolutePath();
        File d = new File(getExternalFilesDir(null), "databases");
        if (!d.exists()) d.mkdirs();
        String safe = f.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        return new File(d, safe + "_" + f.length() + ".ida").getAbsolutePath();
    }

    private void showRecents() {
        ArrayList<String[]> rec = dbh.recents(10);
        if (rec.isEmpty()) { onMessage("No recent files"); return; }
        final ArrayList<String> paths = new ArrayList<String>();
        ArrayList<String> labels = new ArrayList<String>();
        for (String[] r : rec) {
            paths.add(r[0]);
            labels.add(new File(r[0]).exists() ? r[1] : r[1] + " (missing)");
        }
        new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Recent files")
            .setItems(labels.toArray(new String[0]), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) { openPath(paths.get(w)); }
            }).show();
    }

    private void saveDatabase() {
        if (!need()) return;
        if (snapPath == null || snapPath.length() == 0) snapPath = snapPathFor(s.path);
        saveUiState();
        eng.saveNow();
        log("Database saved: " + snapPath);
    }

    /** File / Produce file: writes the full disassembly listing as an .asm text file. */
    private void produceFile() {
        if (!need()) return;
        final String base = s.path;
        final String outPath = producePathFor(base);
        final ProgressDialog pd = ProgressDialog.show(this, "", "Producing file...", true, false);
        log("Producing file: " + outPath);
        new Thread(new Runnable() { public void run() {
            String err = null;
            try {
                java.io.BufferedWriter w = new java.io.BufferedWriter(new java.io.FileWriter(outPath));
                w.write("; Disassembly listing produced by IDA for Android");
                w.newLine();
                w.write("; Input file: " + base);
                w.newLine();
                if (s.entry != 0) { w.write("; Entry point: " + Fmt.hex16(s.entry)); w.newLine(); }
                w.newLine();
                for (Session.Seg seg : s.segs) {
                    if (seg.end <= seg.start) continue;
                    w.write("; --------------------------------------------------------------");
                    w.newLine();
                    w.write("; " + seg.name + ": " + Fmt.hex16(seg.start) + " - " + Fmt.hex16(seg.end));
                    w.newLine();
                    w.write("; --------------------------------------------------------------");
                    w.newLine();
                    long a = seg.start;
                    while (a < seg.end) {
                        String[] rows = NativeBridge.disasm(s.h, a, 2000);
                        if (rows.length == 0) break;
                        for (int i = 0; i < rows.length; i++) {
                            String[] f = Fmt.split(rows[i]);
                            if (f.length < 10) continue;
                            String pad = "                ";
                            if (f[3].length() > 0) {
                                w.newLine();
                                w.write("; " + pad + pad + pad + pad + pad + pad + pad
                                        + "S U B R O U T I N E");
                                w.newLine();
                            }
                            if (f[5].length() > 0) {
                                w.write(f[0] + ":" + f[1] + " ; " + f[5]);
                                w.newLine();
                            }
                            String ln = f[0] + ":" + f[1] + " " + pad + pad;
                            if (f[4].length() > 0) {
                                w.write(ln + f[4] + ":");
                                w.newLine();
                            }
                            if (f[7].length() > 0) {
                                String mn = f[7];
                                while (mn.length() < 7) mn += " ";
                                w.write(ln + mn + " " + f[8]);
                                if (f[9].length() > 0) w.write(" ; " + f[9]);
                                w.newLine();
                            }
                        }
                        a += 4L * rows.length;
                    }
                }
                w.close();
            } catch (Throwable t) { err = t.toString(); }
            final String ferr = err;
            runOnUiThread(new Runnable() { public void run() {
                pd.dismiss();
                if (ferr != null) { log("Produce failed: " + ferr); onMessage("Produce failed: " + ferr); }
                else log("File written: " + outPath);
            }});
        }}, "ida-produce").start();
    }

    /** Output next to the binary when writable, else in the app's external files area. */
    private String producePathFor(String path) {
        File f = new File(path);
        String name = f.getName();
        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        File dir = f.getParentFile();
        if (dir != null && dir.canWrite()) return new File(dir, stem + ".asm").getAbsolutePath();
        File d = new File(getExternalFilesDir(null), "produce");
        if (!d.exists()) d.mkdirs();
        return new File(d, stem + ".asm").getAbsolutePath();
    }

    // ---- table data --------------------------------------------------------------------------

    private ArrayList<ArrayList<String[]>> buildTables() {
        ArrayList<ArrayList<String[]>> all = new ArrayList<ArrayList<String[]>>();
        for (int i = 0; i < 6; i++) all.add(tableRows(i));
        return all;
    }

    /** Rows for one table: 0 functions, 1 strings, 2 imports, 3 exports, 4 names, 5 segments. */
    private ArrayList<String[]> tableRows(int which) {
        ArrayList<String[]> out = new ArrayList<String[]>();
        if (s.h == 0) return out;
        if (which == 0) {
            for (String r : NativeBridge.functions(s.h)) {
                String[] f = Fmt.split(r);
                if (f.length < 4) continue;
                out.add(new String[]{f[0], f[3], f[1], Fmt.hex8(Fmt.parseHex(f[2]))});
            }
        } else if (which == 1) {
            for (String r : NativeBridge.strings(s.h)) {
                String[] f = Fmt.split(r);
                if (f.length < 4) continue;
                int bl; try { bl = f[3].getBytes("UTF-8").length + 1; } catch (Exception e) { bl = f[3].length() + 1; }
                out.add(new String[]{f[1] + ":" + f[0], Fmt.hex8(bl), "C", f[3]});
            }
        } else if (which == 2) {
            for (String r : NativeBridge.imports(s.h)) {
                String n = Fmt.split(r)[0];
                long a = s.lookup(n);
                out.add(new String[]{a != 0 ? s.segName(a) + ":" + Fmt.hex16(a) : "", "", n});
            }
        } else if (which == 3) {
            for (String r : NativeBridge.exports(s.h)) {
                String[] f = Fmt.split(r);
                if (f.length < 2) continue;
                long a = Fmt.parseHex(f[1]);
                String dn = f.length >= 3 && f[2].length() > 0 ? f[2] : f[0];
                out.add(new String[]{dn, s.segName(a) + ":" + f[1], ""});
            }
        } else if (which == 4) {
            for (String r : NativeBridge.names(s.h)) {
                String[] f = Fmt.split(r);
                if (f.length < 3) continue;
                String dn = f.length >= 4 && f[3].length() > 0 ? f[3] : f[0];
                out.add(new String[]{dn, f[2] + ":" + f[1], s.exportNames.contains(f[0]) ? "P" : ""});
            }
        } else if (which == 5) {
            for (Session.Seg g : s.allSegs) {
                String cls = g.exec() ? "CODE" : (g.type == 8 ? "BSS" : "DATA");
                out.add(new String[]{g.name, Fmt.hex16(g.start), Fmt.hex16(g.end),
                        (g.flags & 2) != 0 ? "R" : ".", g.write() ? "W" : ".", g.exec() ? "X" : ".", cls});
            }
        }
        return out;
    }

    /** Rebuilds every table on a worker thread and applies it on the UI thread. */
    private void rebuildAllTables() {
        new Thread(new Runnable() { public void run() {
            final ArrayList<ArrayList<String[]>> data = buildTables();
            runOnUiThread(new Runnable() { public void run() {
                if (!s.isOpen()) return;
                for (int i = 0; i < 6; i++) tables[i].setRows(data.get(i));
                nb.rebuild();
                if (curTab == 0) dv.refresh();
                if (curTab == 2) hv.showAt(s.cur);
            }});
        }}).start();
    }

    /** Engine checkpoint: keep the nav band and the visible table current. */
    private void onCheckpointNow() {
        nb.rebuild();
        long now = System.currentTimeMillis();
        if (now - lastTblMs < 600) return;
        lastTblMs = now;
        if (curTab >= 3 && curTab < 9) refreshTable(curTab);
        if (curTab == 0) dv.refresh();
    }

    private void refreshTable(final int which) {
        if (which < 3 || which > 8) return;
        new Thread(new Runnable() { public void run() {
            final ArrayList<String[]> rows = tableRows(which - 3);
            runOnUiThread(new Runnable() { public void run() {
                if (!s.isOpen()) return;
                tables[which - 3].setRows(rows);
            }});
        }}).start();
    }

    private void setAStatus(int pct, int stage) {
        String t;
        if (stage == 3 || pct >= 100) t = "AU: idle";
        else if (stage == 1) t = "AU: strings " + pct + "%";
        else if (stage == 2) t = "AU: naming";
        else t = "AU: analyzing " + pct + "%";
        statusLeft.setText(t);
        if (pct / 10 > lastLoggedPct) { lastLoggedPct = pct / 10; log("AU: analyzing " + pct + "%"); }
    }

    private TableView mk(String[] t, int[] w, int[] c, final int addrCol, final int tab) {
        TableView tv = new TableView(this, t, w, c);
        tv.setListener(new TableView.RowListener() {
            public void onRow(String[] row, boolean lp) {
                long a = cellAddr(row[addrCol]);
                if (a == 0) { onMessage("No address"); return; }
                if (lp) { XrefDialog.show(MainActivity.this, s, a, row[0], MainActivity.this); return; }
                s.jump(a, MainActivity.this);
                selectTab(0);
            }
        });
        return tv;
    }

    private static long cellAddr(String cell) {
        if (cell == null || cell.length() == 0) return 0;
        try { return Fmt.parseHex(cell.substring(cell.indexOf(':') + 1)); } catch (Exception e) { return 0; }
    }

    private TableView functionsTable() {
        return mk(new String[]{"Function name", "Segment", "Start", "Length"}, new int[]{34, 9, 16, 8},
                new int[]{Theme.C_FUNC, Theme.TEXT, Theme.C_PREFIX, Theme.C_NUM}, 2, 2);
    }
    private TableView stringsTable() {
        return mk(new String[]{"Address", "Length", "Type", "String"}, new int[]{26, 8, 4, 40},
                new int[]{Theme.C_PREFIX, Theme.C_NUM, Theme.TEXT, Theme.C_STRING}, 0, 3);
    }
    private TableView importsTable() {
        return mk(new String[]{"Address", "Ordinal", "Name"}, new int[]{26, 7, 40},
                new int[]{Theme.C_PREFIX, Theme.TEXT, Theme.C_EXTERN}, 0, 4);
    }
    private TableView exportsTable() {
        return mk(new String[]{"Name", "Address", "Ordinal"}, new int[]{36, 26, 7},
                new int[]{Theme.C_FUNC, Theme.C_PREFIX, Theme.TEXT}, 1, 5);
    }
    private TableView namesTable() {
        return mk(new String[]{"Name", "Address", "Public"}, new int[]{36, 26, 6},
                new int[]{Theme.C_LABEL, Theme.C_PREFIX, Theme.TEXT}, 1, 6);
    }
    private TableView segmentsTable() {
        return mk(new String[]{"Name", "Start", "End", "R", "W", "X", "Class"}, new int[]{16, 16, 16, 1, 1, 1, 6},
                new int[]{Theme.TEXT, Theme.C_PREFIX, Theme.C_PREFIX, Theme.TEXT, Theme.TEXT, Theme.TEXT, Theme.C_MNEM}, 1, 7);
    }

    // ---- actions -----------------------------------------------------------------------------

    private void jumpDialog() {
        if (!need()) return;
        final EditText et = new EditText(this);
        et.setSingleLine(true); et.setHint("address or name");
        et.setText(Fmt.hex16(s.cur).replaceFirst("^0+(?=.)", ""));
        et.setTextColor(Theme.TEXT); et.setHintTextColor(Theme.TEXT_DIM); et.setTypeface(Theme.mono(this));
        et.selectAll();
        new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Jump to address").setView(et)
            .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) { goTo(et.getText().toString().trim()); }
            }).setNegativeButton("Cancel", null).show();
    }

    private boolean goTo(String t) {
        if (!need() || t.length() == 0) return false;
        long a = s.lookup(t);
        if (a == 0) { try { a = Fmt.parseHex(t); } catch (Exception e) { onMessage("Command \"JumpAsk\" failed"); return false; } }
        if (s.snapForward(a) < 0) { onMessage("Command \"JumpAsk\" failed"); return false; }
        s.jump(a, this); selectTab(0);
        return true;
    }

    private void xrefsHere() {
        if (!need()) return;
        long a = dv.cursorAddr();
        XrefDialog.show(this, s, a, s.nameAt(a), this);
    }

    /** Search > Signature maker: SigMaker-style pattern for the function under the cursor. */
    private void sigDialog() {
        if (!need()) return;
        log("Making signature at " + s.segName(s.cur) + ":" + Fmt.hex16(s.cur) + " ...");
        new Thread(new Runnable() { public void run() {
            final String r = NativeBridge.sig(s.h, s.cur);
            runOnUiThread(new Runnable() { public void run() {
                if (r == null || r.length() == 0) { onMessage("No signature could be built"); return; }
                log(r.replace("\n", " | "));
                AlertDialog.Builder b = new AlertDialog.Builder(MainActivity.this, android.R.style.Theme_Material_Dialog_Alert)
                        .setTitle("Signature (" + s.nameAt(s.cur) + ")");
                TextView tv = new TextView(MainActivity.this);
                tv.setText(r);
                tv.setTypeface(Theme.mono(MainActivity.this));
                tv.setTextSize(12);
                tv.setTextColor(Theme.TEXT);
                tv.setTextIsSelectable(true);
                int p = Theme.dp(MainActivity.this, 16);
                tv.setPadding(p, p, p, p);
                ScrollView sc = new ScrollView(MainActivity.this);
                sc.addView(tv);
                b.setView(sc);
                b.setPositiveButton("Copy", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface d, int w) {
                        android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("sig", r));
                        onMessage("Copied");
                    }
                });
                b.setNegativeButton("Close", null);
                b.show();
            }});
        }}).start();
    }

    private void nextCode() {
        if (!need()) return;
        long a = dv.cursorAddr() + 4, st = s.funcEnd.ceilingKey(a) == null ? -1 : s.funcEnd.ceilingKey(a);
        if (st > 0) { s.jump(st, this); selectTab(0); } else onMessage("Search failed");
    }

    private void searchDialog() {
        if (!need()) return;
        final EditText et = new EditText(this);
        et.setSingleLine(true); et.setHint("text in disassembly");
        et.setText(lastNeedle);
        et.setTextColor(Theme.TEXT); et.setHintTextColor(Theme.TEXT_DIM); et.setTypeface(Theme.mono(this));
        new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Text search").setView(et)
            .setPositiveButton("Find", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) {
                    lastNeedle = et.getText().toString();
                    if (lastNeedle.length() > 0) searchText(lastNeedle, false);
                }
            }).setNegativeButton("Cancel", null).show();
    }

    /** Scans executable sections forward from the cursor on a worker thread. */
    private void searchText(final String needle, final boolean next) {
        if (!need()) return;
        final String nd = needle.toLowerCase();
        final long startAt = dv.cursorAddr() + (next ? 4 : 0);
        searchCancel = false;
        final ProgressDialog pd = new ProgressDialog(this);
        pd.setMessage("Searching for \"" + needle + "\"...");
        pd.setCancelable(true);
        pd.setOnCancelListener(new DialogInterface.OnCancelListener() { public void onCancel(DialogInterface d) { searchCancel = true; } });
        pd.show();
        new Thread(new Runnable() { public void run() {
            long found = -1;
            outer:
            for (Session.Seg g : s.segs) {
                if (!g.exec() || g.end <= startAt) continue;
                long a = Math.max(startAt, g.start);
                a = g.start + ((a - g.start) & ~3L);
                while (a < g.end) {
                    if (searchCancel) break outer;
                    int n = (int) Math.min(2048, (g.end - a) / 4);
                    if (n <= 0) break;
                    String[] recs = NativeBridge.disasm(s.h, a, n);
                    if (recs.length == 0) break;
                    for (String r : recs) {
                        String[] f = Fmt.split(r);
                        if (f.length < 10) continue;
                        String hay = (f[4] + " " + f[7] + " " + f[8] + " " + f[9]).toLowerCase();
                        if (hay.contains(nd)) { found = Fmt.parseHex(f[1]); break outer; }
                    }
                    a += 4L * recs.length;
                }
            }
            final long hit = found;
            runOnUiThread(new Runnable() { public void run() {
                pd.dismiss();
                if (hit >= 0) { s.jump(hit, MainActivity.this); selectTab(0); dv.setHighlight(needle); log("Found \"" + needle + "\" at " + s.segName(hit) + ":" + Fmt.hex16(hit)); }
                else if (!searchCancel) { onMessage("Search failed"); log("Search failed: \"" + needle + "\" not found"); }
            }});
        }}).start();
    }

    private void runCommand(String cmd) {
        if (cmd.length() == 0) return;
        log("> " + cmd);
        String lower = cmd.toLowerCase();
        if (lower.startsWith("g ")) goTo(cmd.substring(2).trim());
        else if (lower.startsWith("x ")) {
            long a = s.isOpen() ? s.lookup(cmd.substring(2).trim()) : 0;
            if (a != 0) XrefDialog.show(this, s, a, cmd.substring(2).trim(), this); else log("Unknown name");
        } else if (lower.startsWith("find ")) { lastNeedle = cmd.substring(5).trim(); searchText(lastNeedle, false); }
        else log("Commands: g <addr|name>, x <name>, find <text>");
    }

    // ---- keys / back -------------------------------------------------------------------------

    @Override public boolean onKeyDown(int code, KeyEvent e) {
        if (code == KeyEvent.KEYCODE_G && e.isCtrlPressed() == false && curTab == 0 && !(getCurrentFocus() instanceof EditText)) { jumpDialog(); return true; }
        if (code == KeyEvent.KEYCODE_X && curTab == 0 && !(getCurrentFocus() instanceof EditText)) { xrefsHere(); return true; }
        if (code == KeyEvent.KEYCODE_ESCAPE) { s.back(this); return true; }
        return super.onKeyDown(code, e);
    }

    @Override public void onBackPressed() {
        if (curTab != 0) { selectTab(0); return; }
        if (s.canBack()) { s.back(this); return; }
        super.onBackPressed();
    }

    @Override protected void onPause() {
        if (eng.busy()) eng.pause();
        saveUiState();
        if (s.isOpen()) eng.saveNow();
        super.onPause();
    }

    @Override protected void onResume() {
        super.onResume();
        if (eng.isPaused()) eng.resume();
    }

    @Override protected void onDestroy() {
        if (eng.busy()) eng.stopAndWait();
        if (s.isOpen()) saveUiState();
        if (s.isOpen()) eng.saveNow();
        if (dbh != null) dbh.close();
        s.close();
        super.onDestroy();
    }
}
