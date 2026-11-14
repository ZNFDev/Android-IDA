package com.znfdev.ida;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Toast;

/** Hex View-1: 16 bytes per row, IDA layout ("sec:addr  XX XX ...  ascii"). */
public class HexView extends View implements Session.JumpListener {

    private static final int PER_ROW = 16, CACHE_ROWS = 256;

    private final Session s;
    private final Paint tp = new Paint(Paint.ANTI_ALIAS_FLAG), fill = new Paint();
    private float charW, lineH, baseOff, scrollX;
    private long topRow;            // address of first visible row (16-aligned)
    private float subY;             // pixel offset inside the first row, 0..lineH
    private long selAddr = -1;
    private int prefCols = 25;     // "seg:addr  " width in characters (longest section name + 19)
    private byte[] cache; private long cacheBase = -1;
    private final GestureDetector gd;
    private float flingV; private long flingT; private boolean flinging;

    public HexView(Context c, Session session) {
        super(c);
        s = session;
        setBackgroundColor(Theme.BG);
        tp.setTypeface(Theme.mono(c));
        tp.setTextSize(Theme.dp(c, 12));
        charW = tp.measureText("0");
        lineH = (float) Math.ceil(tp.getFontSpacing() + Theme.dp(c, 1));
        baseOff = (lineH - (tp.descent() - tp.ascent())) / 2f - tp.ascent();
        gd = new GestureDetector(c, new GestureDetector.SimpleOnGestureListener() {
            @Override public boolean onDown(MotionEvent e) { flinging = false; return true; }
            @Override public boolean onScroll(MotionEvent a, MotionEvent b, float dx, float dy) {
                scrollX = Math.max(0, Math.min(maxX(), scrollX + dx)); moveBy(dy); return true;
            }
            @Override public boolean onFling(MotionEvent a, MotionEvent b, float vx, float vy) {
                flingV = -vy; flingT = System.nanoTime(); flinging = true; postOnAnimation(flinger); return true;
            }
            @Override public boolean onSingleTapUp(MotionEvent e) { select(e.getX(), e.getY()); return true; }
            @Override public void onLongPress(MotionEvent e) { copyRow(e.getY()); }
        });
        s.addJumpListener(this);
    }

    private float maxX() { return Math.max(0, charW * 100 - getWidth()); }

    @Override public void onJump(long addr, Object source) { showAt(addr); }

    /** Called when this tab becomes visible so it follows the IDA View cursor. */
    public void showAt(long addr) {
        int m = 5;
        for (Session.Seg g : s.segs) if (g.name.length() > m) m = g.name.length();
        prefCols = m + 1 + 16 + 2;
        selAddr = addr;
        topRow = (addr & ~0xFL) - 4 * PER_ROW;
        subY = 0;
        clampTop();
        invalidate();
    }

    /** Last address shown or tapped (for UI state persistence). */
    public long shownAddr() { return selAddr; }

    private void clampTop() {
        long lo = s.minAddr() & ~0xFL, hi = (s.maxAddr() + 15) & ~0xFL;
        if (topRow < lo) topRow = lo;
        if (topRow > hi - PER_ROW) topRow = Math.max(lo, hi - PER_ROW);
    }

    private void moveBy(float dy) {
        subY += dy;
        while (subY >= lineH) { subY -= lineH; topRow += PER_ROW; }
        while (subY < 0) { subY += lineH; topRow -= PER_ROW; }
        clampTop();
        invalidate();
    }

    private final Runnable flinger = new Runnable() {
        public void run() {
            if (!flinging) return;
            long now = System.nanoTime();
            float dt = Math.min(0.05f, (now - flingT) / 1e9f); flingT = now;
            moveBy(flingV * dt);
            flingV *= (float) Math.exp(-2.6 * dt);
            if (Math.abs(flingV) < 40) { flinging = false; return; }
            postOnAnimation(this);
        }
    };

    private void select(float x, float y) {
        int row = (int) Math.floor((y + subY) / lineH);
        long base = topRow + (long) row * PER_ROW;
        float x0 = -scrollX;
        int prefix = prefCols;
        int col = (int) Math.floor((x - x0) / charW) - prefix;
        int idx = col >= 0 ? col / 3 : -1;
        if (idx >= 0 && idx < PER_ROW) { selAddr = base + idx; s.setCursor(selAddr, this); invalidate(); }
    }

    /** Long-press: copy the full IDA-style row ("sec:addr  XX XX .. ..  ascii") to the clipboard. */
    private void copyRow(float y) {
        int row = (int) Math.floor((y + subY) / lineH);
        long base = topRow + (long) row * PER_ROW;
        if (base < 0 || base >= s.maxAddr()) return;
        Session.Seg seg = s.segAt(base);
        String sec = seg != null ? seg.name : s.segName(base + PER_ROW - 1);
        if (seg == null && sec.length() == 0) return;
        byte[] buf = bytes(base);
        StringBuilder sb = new StringBuilder(sec).append(':').append(Fmt.hex16(base)).append("  ");
        StringBuilder asc = new StringBuilder(PER_ROW);
        for (int i = 0; i < PER_ROW; i++) {
            long a = base + i;
            int bi = (int) (a - cacheBase);
            boolean valid = s.segAt(a) != null && bi >= 0 && bi < buf.length;
            int v = valid ? buf[bi] & 0xFF : -1;
            if (valid) { sb.append(String.format("%02X ", v)); asc.append(v >= 32 && v < 127 ? (char) v : '.'); }
            else { sb.append("?? "); asc.append(' '); }
            if (i == 7) sb.append(' ');
        }
        sb.append(' ').append(asc);
        copy(sb.toString());
    }

    private void copy(String text) {
        ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("hex", text));
            Toast.makeText(getContext(), "Copied", Toast.LENGTH_SHORT).show();
        }
    }

    private byte[] bytes(long base) {
        if (cache == null || base < cacheBase || base + PER_ROW > cacheBase + cache.length) {
            cacheBase = base - 16L * 32;
            if (cacheBase < 0) cacheBase = 0;
            cache = NativeBridge.readBytes(s.h, cacheBase, CACHE_ROWS * PER_ROW);
        }
        return cache;
    }

    @Override protected void onDraw(Canvas c) {
        if (!s.isOpen()) return;
        int h = getHeight();
        int rows = (int) (h / lineH) + 2;
        float x0 = -scrollX;
        byte[] buf = null;
        for (int r = 0; r < rows; r++) {
            long base = topRow + (long) r * PER_ROW;
            if (base >= s.maxAddr()) break;
            float yTop = r * lineH - subY, y = yTop + baseOff;
            Session.Seg seg = s.segAt(base);
            String sec = seg != null ? seg.name : s.segName(base + PER_ROW - 1);
            if (seg == null && sec.length() == 0) continue;     // gap between sections
            buf = bytes(base);
            tp.setColor(Theme.C_PREFIX);
            StringBuilder pb = new StringBuilder(sec).append(':').append(Fmt.hex16(base)).append("  ");
            while (pb.length() < prefCols) pb.append(' ');
            String pre = pb.toString();
            c.drawText(pre, x0, y, tp);
            float bx = x0 + prefCols * charW;
            StringBuilder asc = new StringBuilder(PER_ROW);
            for (int i = 0; i < PER_ROW; i++) {
                long a = base + i;
                int bi = (int) (a - cacheBase);
                boolean valid = s.segAt(a) != null && bi >= 0 && bi < buf.length;
                int v = valid ? buf[bi] & 0xFF : -1;
                float xx = bx + i * 3 * charW + (i >= 8 ? charW * 0.5f : 0);
                if (a == selAddr) { fill.setColor(Theme.TOKEN_HI); c.drawRect(xx - 1, yTop, xx + 2 * charW + 1, yTop + lineH, fill); }
                if (valid) {
                    tp.setColor(v == 0 ? Theme.TEXT_DIM : Theme.TEXT);
                    c.drawText(String.format("%02X", v), xx, y, tp);
                    asc.append(v >= 32 && v < 127 ? (char) v : '.');
                } else {
                    tp.setColor(Theme.TEXT_DIM); c.drawText("??", xx, y, tp); asc.append(' ');
                }
            }
            tp.setColor(Theme.C_STRING);
            c.drawText(asc.toString(), bx + PER_ROW * 3 * charW + charW * 1.5f, y, tp);
        }
    }

    @Override public boolean onTouchEvent(MotionEvent e) { gd.onTouchEvent(e); return true; }
    @Override protected void onDetachedFromWindow() { flinging = false; cache = null; super.onDetachedFromWindow(); }
}
