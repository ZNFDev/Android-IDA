package com.znfdev.ida;

import android.content.Context;
import android.graphics.Color;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** HexRays-style pseudocode subview. Records: kind \1 text (H header, V var, B brace, S stmt). */
public class PseudoView extends LinearLayout {

    private final Session s;
    private final TextView header;
    private final TextView body;
    private final ScrollView scroll;
    private long shownAt = 0;
    private static final String KEY = "pseudoFont";
    private float font;

    public PseudoView(Context c, Session ses) {
        super(c);
        s = ses;
        setOrientation(VERTICAL);
        setBackgroundColor(Theme.BG);
        font = c.getSharedPreferences("ida_prefs", Context.MODE_PRIVATE).getFloat(KEY, 13f);

        LinearLayout hb = new LinearLayout(c);
        hb.setOrientation(HORIZONTAL);
        header = new TextView(c);
        header.setTypeface(android.graphics.Typeface.MONOSPACE);
        header.setTextSize(12);
        header.setTextColor(Theme.TEXT_DIM);
        header.setPadding(Theme.dp(c, 8), Theme.dp(c, 6), Theme.dp(c, 2), Theme.dp(c, 6));
        hb.addView(header, new LinearLayout.LayoutParams(-1, -2, 1f));
        TextView bm = fontBtn(c, "A-");
        TextView bp = fontBtn(c, "A+");
        bm.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { setFont(font - 1f); }
        });
        bp.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { setFont(font + 1f); }
        });
        hb.addView(bm);
        hb.addView(bp);
        addView(hb, new LinearLayout.LayoutParams(-1, -2));

        scroll = new ScrollView(c);
        scroll.setFillViewport(true);
        body = new TextView(c);
        body.setTypeface(android.graphics.Typeface.MONOSPACE);
        body.setTextSize(font);
        body.setTextColor(Theme.TEXT);
        body.setTextIsSelectable(true);
        body.setPadding(Theme.dp(c, 6), Theme.dp(c, 4), Theme.dp(c, 6), Theme.dp(c, 24));
        scroll.addView(body);
        addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1f));
    }

    private TextView fontBtn(Context c, String t) {
        TextView b = new TextView(c);
        b.setText(t);
        b.setTypeface(android.graphics.Typeface.MONOSPACE);
        b.setTextSize(12);
        b.setTextColor(Theme.TEXT);
        b.setBackgroundColor(Theme.PANEL);
        b.setPadding(Theme.dp(c, 10), Theme.dp(c, 4), Theme.dp(c, 10), Theme.dp(c, 4));
        return b;
    }

    private void setFont(float f) {
        font = Math.max(7f, Math.min(30f, f));
        body.setTextSize(font);
        getContext().getSharedPreferences("ida_prefs", Context.MODE_PRIVATE).edit().putFloat(KEY, font).apply();
    }

    public void showAt(long addr) {
        if (!s.isOpen()) return;
        long fs = s.funcStartOf(addr);
        if (fs == 0) fs = addr;
        shownAt = fs;
        String fn = s.names.containsKey(fs) ? s.names.get(fs) : Fmt.hex16(fs);
        if (s.dem.containsKey(fs)) fn = s.dem.get(fs);
        header.setText("Pseudocode — " + fn);
        final long at = fs;
        new Thread(new Runnable() { public void run() { load(at); } }).start();
    }

    private void load(final long fs) {
        final String[] rec = NativeBridge.pseudo(s.h, fs);
        post(new Runnable() { public void run() {
            if (shownAt != fs || rec == null) return;
            SpannableStringBuilder sb = new SpannableStringBuilder();
            for (int i = 0; i < rec.length; i++) {
                String r = rec[i];
                int p = r.indexOf('\u0001');
                String kind = p > 0 ? r.substring(0, p) : "S";
                String text = p > 0 ? r.substring(p + 1) : r;
                if (text.isEmpty() && !kind.equals("S")) continue;
                if (kind.equals("H")) {
                    int st = sb.length();
                    sb.append(text).append('\n');
                    sb.setSpan(new ForegroundColorSpan(Theme.C_FUNC), st, sb.length() - 1, 0);
                } else if (kind.equals("V")) {
                    int st = sb.length();
                    sb.append(text).append('\n');
                    sb.setSpan(new ForegroundColorSpan(Theme.TEXT_DIM), st, sb.length() - 1, 0);
                } else if (kind.equals("B")) {
                    sb.append(text).append('\n');
                } else {
                    color(sb, text);
                    sb.append('\n');
                }
            }
            body.setText(sb);
            scroll.smoothScrollTo(0, 0);
        }});
    }

    private static final String[] KW = {
        "if", "else", "while", "do", "for", "return", "switch", "case", "default",
        "break", "continue", "goto", "__int64", "__int128", "unsigned", "signed",
        "int", "char", "short", "float", "double", "void", "const", "volatile"
    };

    private void color(SpannableStringBuilder sb, String line) {
        int st = sb.length();
        sb.append(line);
        int n = line.length();
        int i = 0;
        while (i < n) {
            char ch = line.charAt(i);
            if (ch == '/' && i + 1 < n && line.charAt(i + 1) == '/') {
                sb.setSpan(new ForegroundColorSpan(Theme.C_COMMENT), st + i, st + n, 0);
                break;
            }
            if (ch == '"') {
                int e = i + 1;
                while (e < n && line.charAt(e) != '"') e++;
                if (e < n) sb.setSpan(new ForegroundColorSpan(Theme.C_STRING), st + i, st + e + 1, 0);
                i = e + 1;
                continue;
            }
            if (ch >= '0' && ch <= '9' && (i == 0 || !Character.isJavaIdentifierPart(line.charAt(i - 1)))) {
                int e = i;
                while (e < n && (Character.isDigit(line.charAt(e)) || line.charAt(e) == 'x' ||
                       (line.charAt(e) >= 'a' && line.charAt(e) <= 'f') ||
                       (line.charAt(e) >= 'A' && line.charAt(e) <= 'F') || line.charAt(e) == 'L')) e++;
                sb.setSpan(new ForegroundColorSpan(Theme.C_NUM), st + i, st + e, 0);
                i = e;
                continue;
            }
            if (Character.isJavaIdentifierStart(ch)) {
                int e = i;
                while (e < n && Character.isJavaIdentifierPart(line.charAt(e))) e++;
                String w = line.substring(i, e);
                boolean kw = false;
                for (int q = 0; q < KW.length; q++) if (KW[q].equals(w)) { kw = true; break; }
                if (kw) sb.setSpan(new ForegroundColorSpan(Theme.C_KEYWORD), st + i, st + e, 0);
                else if (e < n && line.charAt(e) == '(')
                    sb.setSpan(new ForegroundColorSpan(Theme.C_FUNC), st + i, st + e, 0);
                i = e;
                continue;
            }
            i++;
        }
        if (line.startsWith("LABEL_")) {
            sb.setSpan(new ForegroundColorSpan(Theme.C_PREFIX), st, st + line.indexOf(':') + 1, 0);
        }
    }

    public long shown() { return shownAt; }
}
