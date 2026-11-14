package com.znfdev.ida;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.view.View;

import java.util.Map;

/** The colour strip under the toolbar: whole address space, tap/drag to jump. */
public class NavBand extends View implements Session.Listener {

    private final Session s;
    private final Paint p = new Paint();
    private int[] colors = new int[0];
    private int builtFor = -1;

    public NavBand(Context c, Session session) {
        super(c);
        s = session;
        setBackgroundColor(Theme.PANEL);
        s.addListener(this);
    }

    @Override public void onAddress(long addr, Object source) { invalidate(); }

    public void rebuild() { builtFor = -1; invalidate(); }

    private long total() {
        long t = 0;
        for (Session.Seg g : s.segs) t += g.end - g.start;
        return t;
    }

    private void build(int w) {
        colors = new int[w];
        long total = total();
        if (total <= 0 || w <= 0) { builtFor = w; return; }
        // base colour per pixel: segment kind
        double perPx = (double) total / w;
        long acc = 0;
        for (Session.Seg g : s.segs) {
            long len = g.end - g.start;
            int a = (int) (acc / perPx), b = (int) ((acc + len) / perPx);
            for (int x = a; x < b && x < w; x++) colors[x] = g.exec() ? Theme.NB_INSN : Theme.NB_DATA;
            acc += len;
        }
        // overlay regular functions
        for (Map.Entry<Long, Long> e : s.funcEnd.entrySet()) {
            int a = pixelOf(e.getKey(), perPx), b = pixelOf(e.getValue(), perPx);
            for (int x = a; x <= b && x < w; x++) if (x >= 0) colors[x] = Theme.NB_FUNC;
        }
        // overlay exports (library functions) and string data
        for (Long a : s.exportAt.keySet()) {
            int x = pixelOf(a.longValue(), perPx);
            if (x >= 0 && x < w) colors[x] = Theme.NB_LIB;
        }
        for (Long a : s.stringAt.keySet()) {
            int x = pixelOf(a.longValue(), perPx);
            if (x >= 0 && x < w) colors[x] = Theme.NB_STR;
        }
        overlaySweep(w, perPx);
        builtFor = w;
    }

    /** During the native sweep, paint explored extents: swept sections keep their
     *  kind colour, everything not yet swept stays unexplored. */
    private void overlaySweep(int w, double perPx) {
        if (s.h == 0) return;
        String[] st = Fmt.split(NativeBridge.liveState(s.h));
        if (st.length < 7 || st[0].equals("1")) return;   // done -> full colours already right
        if (st[5].length() == 0) return;
        String sec = st[5];
        long off = Fmt.parseHex(st[6]);
        int idx = -1;
        for (int i = 0; i < s.allSegs.length; i++) if (s.allSegs[i].name.equals(sec)) { idx = i; break; }
        if (idx < 0) return;
        long acc = 0;
        for (int i = 0; i < s.allSegs.length; i++) {
            Session.Seg g = s.allSegs[i];
            long len = g.end - g.start;
            if (len <= 0) continue;
            int a = (int) (acc / perPx), b = (int) ((acc + len) / perPx);
            int kind = g.exec() ? Theme.NB_INSN : (g.type == 8 ? Theme.NB_DATA : Theme.NB_DATA);
            if (i < idx) {
                for (int x = a; x < b && x < w; x++) colors[x] = kind;
            } else if (i == idx) {
                long sweptLen = off * 4;
                if (sweptLen > len) sweptLen = len;
                int sb = (int) ((acc + sweptLen) / perPx);
                for (int x = a; x < sb && x < w; x++) colors[x] = kind;
            }
            acc += len;
        }
    }

    private long offsetOf(long addr) {
        long acc = 0;
        for (Session.Seg g : s.segs) {
            if (addr < g.start) return acc;
            if (addr < g.end) return acc + (addr - g.start);
            acc += g.end - g.start;
        }
        return acc;
    }
    private int pixelOf(long addr, double perPx) { return (int) (offsetOf(addr) / perPx); }

    private long addrOfPixel(float x) {
        long total = total();
        long off = (long) (x / (float) getWidth() * total);
        for (Session.Seg g : s.segs) {
            long len = g.end - g.start;
            if (off < len) return g.start + off;
            off -= len;
        }
        return s.maxAddr() - 1;
    }

    @Override protected void onMeasure(int wm, int hm) {
        setMeasuredDimension(MeasureSpec.getSize(wm), Theme.dp(getContext(), 18));
    }

    @Override protected void onDraw(Canvas c) {
        int w = getWidth(), h = getHeight();
        int pad = Theme.dp(getContext(), 3);
        if (!s.isOpen() || total() == 0) return;
        if (builtFor != w) build(w);
        for (int x = 0; x < w; x++) {
            p.setColor(colors[x] != 0 ? colors[x] : Theme.NB_UNEXPL);
            c.drawRect(x, pad, x + 1, h - pad, p);
        }
        double perPx = (double) total() / w;
        int cx = pixelOf(s.cur, perPx);
        p.setColor(Theme.NB_CURSOR);
        c.drawRect(cx - 1, 0, cx + 2, h, p);
    }

    @Override public boolean onTouchEvent(MotionEvent e) {
        if (!s.isOpen()) return true;
        int a = e.getActionMasked();
        if (a == MotionEvent.ACTION_DOWN || a == MotionEvent.ACTION_MOVE || a == MotionEvent.ACTION_UP) {
            float x = Math.max(0, Math.min(getWidth() - 1, e.getX()));
            if (a == MotionEvent.ACTION_UP) s.jump(addrOfPixel(x), this);
            else s.setCursor(addrOfPixel(x), this);
        }
        return true;
    }
}
