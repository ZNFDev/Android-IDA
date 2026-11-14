package com.znfdev.ida;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.ActionMode;
import android.view.GestureDetector;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

/** IDA View-A: scrolling listing with jump arrows, token highlight, xref and jump actions. */
public class DisasmView extends View implements Session.JumpListener {

    public interface Host {
        void onXrefs(long addr, String name);
        void onHexAt(long addr);
        void onMessage(String msg);
    }

    private static final int CHUNK_FWD = 250, MAX_LINES = 9000, MAX_LANES = 8;

    private final Session s;
    private final LineBuilder lb;
    private Host host;

    private final ArrayList<Line> lines = new ArrayList<Line>();
    private long bufStart, bufEnd;
    private boolean atTop, atEnd;
    private float scrollX, scrollY;
    private int cursorLine = -1;
    private int selA = -1, selB = -1;            // selected line range (inclusive); -1 = none
    private ActionMode am;
    private int maxChars;
    private String hi;
    private long pendingJump = -1;

    private final Paint tp = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fill = new Paint();
    private final Paint ap = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();
    private float charW, lineH, baseOff, gutter, laneW;

    private final GestureDetector gd;
    private final ScaleGestureDetector sd;
    private float textPx;
    private float flingV;                    // px/s
    private long flingT;
    private boolean flinging;

    public DisasmView(Context c, Session session) {
        super(c);
        s = session; lb = new LineBuilder(s);
        setBackgroundColor(Theme.BG);
        tp.setTypeface(Theme.mono(c));
        ap.setStyle(Paint.Style.STROKE);
        ap.setStrokeWidth(Theme.dp(c, 1.2f));
        applyTextSize(Theme.dp(c, 12));
        gd = new GestureDetector(c, new GestureDetector.SimpleOnGestureListener() {
            @Override public boolean onDown(MotionEvent e) { flinging = false; return true; }
            @Override public boolean onScroll(MotionEvent a, MotionEvent b, float dx, float dy) {
                if (am != null) {                                   // dragging a selection extends it instead of scrolling
                    int i = lineAt(b.getY());
                    if (i >= 0 && i < lines.size()) { selB = i; normSel(); invalidate(); }
                    return true;
                }
                scrollBy(dx, dy); return true;
            }
            @Override public boolean onFling(MotionEvent a, MotionEvent b, float vx, float vy) {
                flingV = -vy; flingT = System.nanoTime(); flinging = true; postOnAnimation(flinger); return true;
            }
            @Override public boolean onSingleTapUp(MotionEvent e) { tap(e.getX(), e.getY(), false); return true; }
            @Override public boolean onDoubleTap(MotionEvent e) { tap(e.getX(), e.getY(), true); return true; }
            @Override public void onLongPress(MotionEvent e) { longPress(e.getX(), e.getY()); }
        });
        sd = new ScaleGestureDetector(c, new ScaleGestureDetector.SimpleOnScaleGestureListener() {
            @Override public boolean onScale(ScaleGestureDetector d) {
                float top = lineH > 0 ? scrollY / lineH : 0;
                float px = Math.max(Theme.dp(getContext(), 7), Math.min(Theme.dp(getContext(), 30), textPx * d.getScaleFactor()));
                applyTextSize(px);
                scrollY = top * lineH;
                invalidate();
                return true;
            }
        });
        s.addJumpListener(this);
    }

    public void setHost(Host h) { host = h; }

    private void applyTextSize(float px) {
        textPx = px;
        tp.setTextSize(px);
        charW = tp.measureText("0");
        float fs = tp.getFontSpacing();
        lineH = (float) Math.ceil(fs + Theme.dp(getContext(), 1));
        baseOff = (lineH - (tp.descent() - tp.ascent())) / 2f - tp.ascent();
        laneW = charW * 0.75f;
        gutter = laneW * (MAX_LANES + 1);
    }

    // ---- buffer management ------------------------------------------------------------------

    private ArrayList<Line> buildRange(Session.Seg seg, long from, long limit, int max) {
        return seg.exec() ? lb.buildCode(from, limit, max) : lb.buildData(from, limit, max);
    }

    private void noteWidth(ArrayList<Line> add) {
        for (Line l : add) if (l.text.length() > maxChars) maxChars = l.text.length();
    }

    private boolean appendChunk() {
        if (atEnd) return false;
        long t = s.snapForward(bufEnd);
        if (t < 0) { atEnd = true; return false; }
        Session.Seg seg = s.segAt(t);
        ArrayList<Line> add = buildRange(seg, t, seg.end, CHUNK_FWD);
        if (add.isEmpty()) {
            bufEnd = seg.end;
            if (seg.end >= s.maxAddr()) atEnd = true;
            return !atEnd;
        }
        lines.addAll(add); noteWidth(add);
        bufEnd = Math.max(lb.end, t + 1);
        if (bufEnd >= s.maxAddr()) atEnd = true;
        return true;
    }

    private boolean prependChunk() {
        if (atTop) return false;
        long b = s.snapBackward(bufStart);
        if (b < 0) { atTop = true; return false; }
        Session.Seg seg = s.segAt(b);
        long limit = Math.min(bufStart, seg.end);
        long span = seg.exec() ? 4L * 120 : 8L * 120;
        long from = Math.max(seg.start, limit - span);
        from = seg.start + ((from - seg.start) & ~7L);
        ArrayList<Line> add = buildRange(seg, from, limit, 400);
        if (add.isEmpty()) {
            bufStart = from;
            if (from <= s.minAddr()) atTop = true;
            return !atTop;
        }
        lines.addAll(0, add); noteWidth(add);
        scrollY += add.size() * lineH;
        if (cursorLine >= 0) cursorLine += add.size();
        bufStart = add.get(0).addr;
        if (bufStart <= s.minAddr()) atTop = true;
        return true;
    }

    private void ensure() {
        if (lines.isEmpty() || getHeight() == 0) return;
        int guard = 0;
        while (scrollY < 40 * lineH && !atTop && guard++ < 3) prependChunk();
        guard = 0;
        while (scrollY + getHeight() > (lines.size() - 80) * lineH && !atEnd && guard++ < 3) appendChunk();
        if (lines.size() > MAX_LINES) trim();
        float total = lines.size() * lineH;
        if (atTop && scrollY < 0) scrollY = 0;
        if (atEnd && scrollY > total - getHeight() * 0.6f) scrollY = Math.max(0, total - getHeight() * 0.6f);
        float maxX = Math.max(0, gutter + maxChars * charW - getWidth() + charW * 2);
        scrollX = Math.max(0, Math.min(maxX, scrollX));
    }

    /** Drop lines far from the viewport, cutting only between address groups. */
    private void trim() {
        int viewMid = (int) ((scrollY + getHeight() / 2f) / lineH);
        int drop = lines.size() - MAX_LINES / 2;
        if (viewMid > lines.size() / 2) {            // drop from the front
            int k = Math.min(drop, Math.max(0, viewMid - 600));
            while (k > 0 && k < lines.size() && lines.get(k).addr == lines.get(k - 1).addr) k--;
            if (k <= 0) return;
            lines.subList(0, k).clear();
            scrollY -= k * lineH;
            if (cursorLine >= 0) cursorLine -= k;
            bufStart = lines.get(0).addr; atTop = false;
        } else {                                     // drop from the back
            int k = Math.max(lines.size() - drop, viewMid + 600);
            while (k < lines.size() && k > 0 && lines.get(k).addr == lines.get(k - 1).addr) k++;
            if (k >= lines.size()) return;
            bufEnd = lines.get(k).addr;
            lines.subList(k, lines.size()).clear(); atEnd = false;
        }
    }

    @Override public void onJump(long addr, Object source) { loadAround(addr); }

    private void loadAround(long t) {
        if (getHeight() == 0) { pendingJump = t; return; }
        Session.Seg seg = s.segAt(t);
        if (seg == null) return;
        if (seg.exec()) t = seg.start + ((t - seg.start) & ~3L);
        lines.clear(); atTop = atEnd = false; maxChars = 0; cursorLine = -1;
        selA = selB = -1;                                    // stale selection cannot survive a rebuild
        scrollX = 0; scrollY = 0; flinging = false;
        bufStart = bufEnd = t;
        prependChunk();
        appendChunk();
        int idx = -1;
        for (int i = 0; i < lines.size(); i++) {
            Line l = lines.get(i);
            if (l.addr == t && l.primary) { idx = i; break; }
            if (l.addr > t) { idx = i; break; }
        }
        if (idx < 0) idx = Math.max(0, lines.size() - 1);
        cursorLine = idx;
        int g = idx;
        while (g > 0 && lines.get(g - 1).addr == lines.get(idx).addr) g--;
        scrollY = g * lineH - getHeight() * 0.25f;
        ensure();
        invalidate();
    }

    @Override protected void onSizeChanged(int w, int h, int ow, int oh) {
        if (pendingJump >= 0 && h > 0) { long t = pendingJump; pendingJump = -1; loadAround(t); }
    }

    // ---- scrolling ---------------------------------------------------------------------------

    private void scrollBy(float dx, float dy) {
        scrollX += dx; scrollY += dy;
        ensure(); invalidate();
    }

    private final Runnable flinger = new Runnable() {
        public void run() {
            if (!flinging) return;
            long now = System.nanoTime();
            float dt = Math.min(0.05f, (now - flingT) / 1e9f);
            flingT = now;
            float before = scrollY;
            scrollY += flingV * dt;
            flingV *= (float) Math.exp(-2.6 * dt);
            ensure(); invalidate();
            if (Math.abs(flingV) < 40 || (atTop && scrollY <= 0 && flingV < 0)) { flinging = false; settleCursor(); return; }
            postOnAnimation(this);
        }
    };

    /** If the cursor line scrolled out of view, move it to the first visible line (like IDA following the view). */
    private void settleCursor() {
        if (lines.isEmpty()) return;
        int first = (int) Math.ceil(scrollY / lineH), last = (int) ((scrollY + getHeight()) / lineH) - 1;
        if (cursorLine >= first && cursorLine <= last) return;
        int i = Math.max(0, Math.min(lines.size() - 1, first + 3));
        setCursorLine(i);
    }

    private void setCursorLine(int i) {
        if (i < 0 || i >= lines.size()) return;
        cursorLine = i;
        s.setCursor(lines.get(i).addr, this);
        invalidate();
    }

    // ---- touch -------------------------------------------------------------------------------

    @Override public boolean onTouchEvent(MotionEvent ev) {
        sd.onTouchEvent(ev);
        if (!sd.isInProgress()) gd.onTouchEvent(ev);
        if (ev.getActionMasked() == MotionEvent.ACTION_UP && !flinging) settleCursor();
        return true;
    }

    private int lineAt(float y) { return (int) Math.floor((y + scrollY) / lineH); }

    private static boolean isTok(char c) { return Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '$' || c == '@' || c == '?'; }

    private String tokenAt(Line l, float x) {
        int col = (int) Math.floor((x - (gutter - scrollX)) / charW);
        String t = l.text;
        if (col < 0 || col >= t.length()) return null;
        int pre = t.indexOf(' ');
        if (col <= pre) return null;
        if (!isTok(t.charAt(col))) return null;
        int a = col, b = col;
        while (a > 0 && isTok(t.charAt(a - 1))) a--;
        while (b < t.length() && isTok(t.charAt(b))) b++;
        String tok = t.substring(a, b);
        while (tok.endsWith(".")) tok = tok.substring(0, tok.length() - 1);
        return tok.length() == 0 ? null : tok;
    }

    private static String bare(String tok) {
        int at = tok.indexOf('@');
        return at > 0 ? tok.substring(0, at) : tok;
    }

    private void tap(float x, float y, boolean dbl) {
        if (am != null) { am.finish(); return; }                // tap clears the selection
        int i = lineAt(y);
        if (i < 0 || i >= lines.size()) return;
        Line l = lines.get(i);
        String tok = tokenAt(l, x);
        if (!dbl) {
            hi = tok;
            setCursorLine(i);
            return;
        }
        long t = 0;
        if (tok != null) t = s.lookup(bare(tok));
        if (t == 0 && l.target != 0) t = l.target;
        if (t != 0) s.jump(t, this);
        else if (host != null) host.onMessage("Nothing to follow here");
    }

    private void longPress(float x, float y) {
        int i = lineAt(y);
        if (i < 0 || i >= lines.size()) return;
        final Line l = lines.get(i);
        final String tok = tokenAt(l, x);
        if (tok != null) {                                      // token press keeps the rich menu
            setCursorLine(i);
            lineMenu(l, tok);
            return;
        }
        if (am != null) { selB = i; normSel(); invalidate(); return; }   // extend
        selA = selB = i;
        am = startActionMode(selMode);
        invalidate();
    }

    private void normSel() { if (selA > selB) { int t = selA; selA = selB; selB = t; } }

    private final ActionMode.Callback selMode = new ActionMode.Callback() {
        public boolean onCreateActionMode(ActionMode m, Menu menu) {
            menu.add(0, 1, 0, "Copy");
            menu.add(0, 2, 0, "Copy line");
            menu.add(0, 3, 0, "More...");
            return true;
        }
        public boolean onPrepareActionMode(ActionMode m, Menu menu) { return false; }
        public boolean onActionItemClicked(ActionMode m, MenuItem it) {
            switch (it.getItemId()) {
                case 1: copySelection(); m.finish(); return true;
                case 2: if (selA >= 0 && selA < lines.size()) copy(lines.get(selA).text); m.finish(); return true;
                case 3: {
                    Line l = (selA >= 0 && selA < lines.size()) ? lines.get(selA) : null;
                    m.finish();
                    if (l != null) lineMenu(l, null);
                    return true;
                }
            }
            return false;
        }
        public void onDestroyActionMode(ActionMode m) { selA = selB = -1; am = null; invalidate(); }
    };

    private void copySelection() {
        int a = Math.min(selA, selB), b = Math.max(selA, selB);
        if (a < 0 || a >= lines.size()) return;
        b = Math.min(b, lines.size() - 1);
        StringBuilder sb = new StringBuilder();
        for (int i = a; i <= b; i++) { if (i > a) sb.append('\n'); sb.append(lines.get(i).text); }
        copy(sb.toString());
    }

    private void lineMenu(final Line l, final String tok) {
        final long tgt = tok != null ? s.lookup(bare(tok)) : (l.target);
        final ArrayList<String> labels = new ArrayList<String>();
        final ArrayList<Integer> ids = new ArrayList<Integer>();
        if (tgt != 0) { labels.add("Jump to " + s.nameAt(tgt)); ids.add(0); labels.add("Xrefs to " + s.nameAt(tgt)); ids.add(1); }
        labels.add("Xrefs to this address"); ids.add(2);
        labels.add("Hex dump here"); ids.add(3);
        labels.add("Copy line"); ids.add(4);
        labels.add("Copy address"); ids.add(5);
        if (hi != null) { labels.add("Clear highlight"); ids.add(6); }
        new AlertDialog.Builder(getContext(), android.R.style.Theme_Material_Dialog_Alert)
            .setItems(labels.toArray(new String[labels.size()]), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int which) {
                    switch (ids.get(which)) {
                        case 0: s.jump(tgt, DisasmView.this); break;
                        case 1: if (host != null) host.onXrefs(tgt, s.nameAt(tgt)); break;
                        case 2: if (host != null) host.onXrefs(l.addr, s.nameAt(l.addr)); break;
                        case 3: if (host != null) host.onHexAt(l.addr); break;
                        case 4: copy(l.text); break;
                        case 5: copy(Fmt.hex16(l.addr)); break;
                        case 6: hi = null; invalidate(); break;
                    }
                }
            }).show();
    }

    private void copy(String t) {
        ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("ida", t));
        if (host != null) host.onMessage("Copied");
    }

    /** Re-centre when the cursor was moved by another window (hex view, band) while this tab was hidden. */
    public void syncTo(long addr) {
        if (!s.isOpen()) return;
        if (cursorLine < 0 || cursorAddr() != addr) loadAround(addr);
    }

    public void setHighlight(String t) { hi = t; invalidate(); }

    /**
     * Rebuild the listing in place (background analysis added names/functions/xrefs).
     * Anchored at the top visible line: cursor, highlight, horizontal pan and scroll offset survive.
     */
    public void refresh() {
        if (!s.isOpen() || lines.isEmpty() || lineH <= 0 || getHeight() == 0) return;
        int firstIdx = Math.max(0, Math.min(lines.size() - 1, (int) Math.floor(scrollY / lineH)));
        long anchorAddr = lines.get(firstIdx).addr;
        float anchorY = firstIdx * lineH - scrollY;      // <= 0: partially visible top line
        Line cLine = (cursorLine >= 0 && cursorLine < lines.size()) ? lines.get(cursorLine) : null;
        String hiKeep = hi;
        float scrollXKeep = scrollX;
        loadAround(anchorAddr);
        int idx = -1;
        for (int i = 0; i < lines.size(); i++) {
            Line l = lines.get(i);
            if (l.addr == anchorAddr && l.primary) { idx = i; break; }
            if (l.addr > anchorAddr) { idx = i; break; }
        }
        if (idx < 0) idx = Math.max(0, lines.size() - 1);
        scrollY = idx * lineH - anchorY;
        if (scrollY < 0) scrollY = 0;
        if (cLine != null) {
            int ci = firstLineAt(cLine.addr, 0);
            if (ci >= 0) {
                for (int i = ci; i < lines.size() && lines.get(i).addr == cLine.addr; i++) if (lines.get(i).primary) { ci = i; break; }
                cursorLine = ci;
            }
        }
        hi = hiKeep; scrollX = scrollXKeep;
        ensure(); invalidate();
    }

    /** Address of the line currently selected (for the status bar). */
    public long cursorAddr() { return cursorLine >= 0 && cursorLine < lines.size() ? lines.get(cursorLine).addr : s.cur; }

    // ---- drawing -----------------------------------------------------------------------------

    @Override protected void onDraw(Canvas c) {
        int w = getWidth(), h = getHeight();
        if (!s.isOpen() || lines.isEmpty()) {
            tp.setColor(Theme.TEXT_DIM);
            c.drawText(s.isOpen() ? "" : "No database. Use File > Open to load an ELF .so", Theme.dp(getContext(), 16), lineH * 2, tp);
            return;
        }
        ensure();
        int first = Math.max(0, (int) Math.floor(scrollY / lineH));
        int last = Math.min(lines.size() - 1, (int) Math.floor((scrollY + h) / lineH));
        float x0 = gutter - scrollX;

        // cursor row and token highlights first (behind text)
        for (int i = first; i <= last; i++) {
            float y = i * lineH - scrollY;
            if (i == cursorLine) { fill.setColor(Theme.CUR_LINE); c.drawRect(0, y, w, y + lineH, fill); }
        }
        if (selA >= 0 && selB >= 0 && selA < lines.size() && selB < lines.size()) {
            int sa = Math.min(selA, selB), sb2 = Math.max(selA, selB);
            fill.setColor(0x334477CC);
            for (int i = Math.max(first, sa); i <= Math.min(last, sb2); i++) {
                float y = i * lineH - scrollY;
                c.drawRect(0, y, w, y + lineH, fill);
            }
        }
        if (hi != null && hi.length() > 0) {
            fill.setColor(Theme.TOKEN_HI);
            boolean word = true;
            for (int k = 0; k < hi.length(); k++) if (!isTok(hi.charAt(k))) { word = false; break; }
            for (int i = first; i <= last; i++) {
                String t = lines.get(i).text;
                int from = t.indexOf(' ') + 1, p;
                float y = i * lineH - scrollY;
                while ((p = t.indexOf(hi, from)) >= 0) {
                    int e = p + hi.length();
                    boolean ok = !word || ((p == 0 || !isTok(t.charAt(p - 1))) && (e >= t.length() || !isTok(t.charAt(e)) || t.charAt(e) == '@'));
                    if (ok) c.drawRect(x0 + p * charW, y, x0 + e * charW, y + lineH, fill);
                    from = e;
                }
            }
        }

        c.save();
        c.clipRect(gutter, 0, w, h);
        for (int i = first; i <= last; i++) {
            Line l = lines.get(i);
            float y = i * lineH - scrollY + baseOff;
            int[] r = l.runs; String t = l.text;
            for (int k = 0; k < r.length; k += 2) {
                int a = r[k], b = (k + 2 < r.length) ? r[k + 2] : t.length();
                tp.setColor(r[k + 1]);
                c.drawText(t, a, b, x0 + a * charW, y, tp);
            }
        }
        c.restore();

        drawArrows(c, first, last);
    }

    private static final class Arrow { int from, to; boolean cond; int lane; }

    private int firstLineAt(long addr, int hint) {
        int lo = 0, hi2 = lines.size() - 1, ans = -1;
        while (lo <= hi2) {
            int mid = (lo + hi2) >>> 1;
            long a = lines.get(mid).addr;
            if (a < addr) lo = mid + 1; else { ans = mid; hi2 = mid - 1; }
        }
        if (ans < 0 || lines.get(ans).addr != addr) return -1;
        for (int i = ans; i < lines.size() && lines.get(i).addr == addr; i++) if (lines.get(i).primary) return i;
        return ans;
    }

    private void drawArrows(Canvas c, int first, int last) {
        int lo = Math.max(0, first - 300), hiI = Math.min(lines.size() - 1, last + 300);
        ArrayList<Arrow> arrows = new ArrayList<Arrow>();
        for (int i = lo; i <= hiI; i++) {
            Line l = lines.get(i);
            if ((l.jumpType != 'j' && l.jumpType != 'c') || l.target == 0) continue;
            if (l.target < bufStart || l.target >= bufEnd) continue;
            int t = firstLineAt(l.target, i);
            if (t < 0 || t == i) continue;
            int a = Math.min(i, t), b = Math.max(i, t);
            if (b < first || a > last) continue;
            Arrow ar = new Arrow(); ar.from = i; ar.to = t; ar.cond = l.jumpType == 'c';
            arrows.add(ar);
        }
        if (arrows.isEmpty()) return;
        Collections.sort(arrows, new Comparator<Arrow>() {
            public int compare(Arrow p, Arrow q) { return Math.abs(p.from - p.to) - Math.abs(q.from - q.to); }
        });
        ArrayList<int[]> taken = new ArrayList<int[]>();
        ArrayList<Integer> laneOf = new ArrayList<Integer>();
        for (Arrow ar : arrows) {
            int a = Math.min(ar.from, ar.to), b = Math.max(ar.from, ar.to);
            int lane = 0;
            for (; lane < MAX_LANES; lane++) {
                boolean clash = false;
                for (int k = 0; k < taken.size(); k++)
                    if (laneOf.get(k) == lane && !(b < taken.get(k)[0] || a > taken.get(k)[1])) { clash = true; break; }
                if (!clash) break;
            }
            ar.lane = lane >= MAX_LANES ? MAX_LANES - 1 : lane;
            taken.add(new int[]{a, b}); laneOf.add(ar.lane);
        }
        c.save();
        c.clipRect(0, 0, gutter, getHeight());
        float arrowH = lineH * 0.22f;
        for (Arrow ar : arrows) {
            ap.setColor(ar.cond ? Theme.ARROW_COND : Theme.ARROW);
            ap.setPathEffect(ar.cond ? new DashPathEffect(new float[]{lineH * 0.25f, lineH * 0.2f}, 0) : null);
            float x = gutter - laneW * (ar.lane + 1) - charW * 0.2f;
            float y1 = ar.from * lineH - scrollY + lineH / 2f, y2 = ar.to * lineH - scrollY + lineH / 2f;
            float xe = gutter - charW * 0.1f;
            path.reset();
            path.moveTo(xe - laneW * 0.2f, y1); path.lineTo(x, y1); path.lineTo(x, y2); path.lineTo(xe - arrowH, y2);
            c.drawPath(path, ap);
            fill.setColor(ap.getColor());
            path.reset();
            path.moveTo(xe, y2); path.lineTo(xe - arrowH * 1.4f, y2 - arrowH); path.lineTo(xe - arrowH * 1.4f, y2 + arrowH); path.close();
            ap.setPathEffect(null);
            c.drawPath(path, fill);
        }
        c.restore();
    }

    @Override protected void onDetachedFromWindow() { flinging = false; super.onDetachedFromWindow(); }
}
