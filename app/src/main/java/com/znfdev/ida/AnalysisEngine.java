package com.znfdev.ida;

import android.os.Handler;
import android.os.Looper;

/**
 * Drives NativeBridge.analyzeStep on a background thread.
 * All heavy work (native queries, map rebuilds, snapshot writes) happens on this
 * worker thread; the UI thread only receives prebuilt results to apply.
 */
public final class AnalysisEngine {

    public interface Listener {
        void onProgress(int percent, int stage);
        void onCheckpoint();
        void onDone(long elapsedMs, boolean cancelled);
        void onError(String err);
    }

    private static final int BUDGET = 3000;      // words or bytes per analyzeStep call
    private static final int POST_MS = 250;      // UI checkpoint interval
    private static final int SAVE_MS = 4000;     // autosave interval

    private final Handler ui = new Handler(Looper.getMainLooper());
    private Session s;
    private String snapPath;
    private Listener l;
    private long h;
    private Thread worker;
    private volatile boolean running, paused, cancelReq;
    public volatile long hexAddr;               // Hex View position, stored in the database
    private long lastPost, lastSave, t0;
    private String lastState = "";              // last liveState seen; unchanged -> skip map rebuild

    public boolean busy() { return running; }
    public boolean isPaused() { return paused; }

    public synchronized void start(Session sess, String snapshot, Listener lis) {
        if (running || sess == null || sess.h == 0) return;
        s = sess; snapPath = snapshot; l = lis; h = s.h;
        cancelReq = false; paused = false;
        t0 = System.currentTimeMillis();
        lastPost = lastSave = 0;
        lastState = "";
        running = true;
        worker = new Thread(new Runnable() { public void run() { work(); } }, "ida-analysis");
        worker.setPriority(Thread.NORM_PRIORITY - 1);
        worker.start();
    }

    private void work() {
        String err = null; boolean cancelled = false; int n = 1;
        try {
            while (true) {
                synchronized (this) {
                    while (paused && !cancelReq && running) {
                        try { wait(); } catch (InterruptedException e) { break; }
                    }
                }
                if (cancelReq) { cancelled = true; break; }
                n = NativeBridge.analyzeStep(h, BUDGET);
                if (n < 0) { err = NativeBridge.lastError(); break; }
                if (n == 0) break;
                long now = System.currentTimeMillis();
                if (now - lastPost >= POST_MS) { lastPost = now; checkpoint(); }
                if (now - lastSave >= SAVE_MS) { lastSave = now; saveSnapshot(); }
            }
        } catch (Throwable t) { err = t.toString(); }
        saveSnapshot();
        running = false;
        postEnd(err, cancelled, System.currentTimeMillis() - t0);
    }

    public void pause() {
        if (!running || paused) return;
        paused = true;
        saveSnapshot();
    }

    public void resume() {
        if (!paused) return;
        paused = false;
        synchronized (this) { notifyAll(); }
    }

    public void cancel() {
        cancelReq = true;
        synchronized (this) { notifyAll(); }
    }

    public void stopAndWait() {
        cancel();
        Thread w = worker;
        if (w != null) { try { w.join(3000); } catch (InterruptedException e) { } }
    }

    /** Immediate save; safe from the UI thread (native side is mutex-protected). */
    public void saveNow() {
        if (h != 0 && s != null) saveSnapshot();
    }

    private void saveSnapshot() {
        long cur = s != null ? s.cur : 0;
        String err = NativeBridge.saveState(h, snapPath, cur, hexAddr);
        if (err.length() > 0 && l != null) {
            final String e = err;
            ui.post(new Runnable() { public void run() { if (l != null) l.onError(e); } });
        }
    }

    /** Runs on the worker thread: native state read + fresh map build, then a light UI apply. */
    private void checkpoint() {
        String st0 = NativeBridge.liveState(h);
        String[] st = Fmt.split(st0);
        if (st0.equals(lastState)) return;   // nothing changed since the last checkpoint
        lastState = st0;
        Session.Maps mm;
        try { mm = s.buildMaps(); } catch (Throwable t) { mm = null; }
        final Session.Maps m = mm;
        final int pct = st.length > 2 ? parseInt(st[2]) : 0;
        final int stage = st.length > 1 ? parseInt(st[1]) : 0;
        ui.post(new Runnable() { public void run() { apply(pct, stage, m, false); } });
    }

    private void postEnd(final String err, final boolean cancelled, final long ms) {
        final long hh = h;
        Session.Maps mm;
        try { mm = s.buildMaps(); } catch (Throwable t) { mm = null; }
        final Session.Maps m = mm;
        String[] st;
        try { st = Fmt.split(NativeBridge.liveState(h)); } catch (Throwable t) { st = new String[0]; }
        final int pct = st.length > 2 ? parseInt(st[2]) : 0;
        ui.post(new Runnable() { public void run() {
            if (l == null || s == null || s.h != hh) return;
            apply(pct, 3, m, true);
            if (err != null) l.onError(err);
            else l.onDone(ms, cancelled);
        }});
    }

    /** UI thread only: swap in the prebuilt maps, update status, refresh visible views. */
    private void apply(final int pct, final int stage, final Session.Maps m, final boolean end) {
        if (l == null || s == null || s.h != h) return;
        if (m != null) s.applyMaps(m);
        l.onProgress(pct, stage);
        l.onCheckpoint();
    }

    private static int parseInt(String t) { try { return Integer.parseInt(t.trim()); } catch (Exception e) { return 0; } }
}
