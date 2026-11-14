package com.znfdev.ida;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.view.ViewGroup;
import android.view.Window;

import java.util.ArrayList;

/** "xrefs to X" window: Direction | Type | Address | Text, tap a row to jump. */
public final class XrefDialog {
    private XrefDialog() {}

    public static void show(final Context c, final Session s, final long addr, String name, final Object src) {
        String[] raw = NativeBridge.xrefsTo(s.h, addr);
        ArrayList<String[]> rows = new ArrayList<String[]>();
        for (String r : raw) {
            String[] f = Fmt.split(r);
            if (f.length < 3) continue;
            long from = Fmt.parseHex(f[1]);
            String text = "";
            String[] d = NativeBridge.disasm(s.h, from, 1);
            if (d.length > 0) {
                String[] df = Fmt.split(d[0]);
                if (df.length >= 9) text = (df[7] + " " + df[8]).trim();
            }
            rows.add(new String[]{ from < addr ? "Up" : "Down", f[0], s.segName(from) + ":" + Fmt.hex16(from), text.length() > 0 ? text : f[2] });
        }
        TableView tv = new TableView(c, new String[]{"Direction", "Type", "Address", "Text"},
                new int[]{9, 4, 24, 30},
                new int[]{Theme.TEXT, Theme.C_NUM, Theme.C_PREFIX, Theme.C_MNEM});
        tv.setRows(rows);
        final AlertDialog dlg = new AlertDialog.Builder(c, android.R.style.Theme_Material_Dialog_Alert)
                .setTitle("xrefs to " + name + " (" + rows.size() + ")")
                .setView(tv)
                .setNegativeButton("Close", null)
                .create();
        tv.setListener(new TableView.RowListener() {
            public void onRow(String[] row, boolean longPress) {
                int colon = row[2].indexOf(':');
                try { s.jump(Fmt.parseHex(row[2].substring(colon + 1)), src); } catch (Exception e) { return; }
                dlg.dismiss();
            }
        });
        dlg.show();
        Window w = dlg.getWindow();
        if (w != null) w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, (int) (c.getResources().getDisplayMetrics().heightPixels * 0.7f));
    }
}
