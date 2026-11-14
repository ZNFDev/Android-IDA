package com.znfdev.ida;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;

/** Everything the views share: the open database, segments, history and the current address. */
public final class Session {

    public static final class Seg {
        public String name;
        public long start, end;
        public long flags;
        public int type;
        public boolean exec() { return (flags & 4) != 0; }
        public boolean write() { return (flags & 1) != 0; }
    }

    public interface Listener { void onAddress(long addr, Object source); }

    public long h;
    public String path = "";
    public int machine;
    public long entry;
    public Seg[] segs = new Seg[0];                  // alloc, non-NOBITS sections sorted by start
    public Seg[] allSegs = new Seg[0];               // everything with a name (Segments window)
    public TreeMap<Long, Long> funcEnd = new TreeMap<Long, Long>();
    public HashSet<String> funcNames = new HashSet<String>();
    public HashSet<String> importNames = new HashSet<String>();
    public HashSet<String> exportNames = new HashSet<String>();
    public HashMap<Long, String> exportAt = new HashMap<Long, String>();
    public HashMap<Long, String> stringAt = new HashMap<Long, String>();
    public HashMap<Long, String> names = new HashMap<Long, String>();
    public HashMap<Long, String> dem = new HashMap<Long, String>();
    private final HashMap<String, Long> lookupCache = new HashMap<String, Long>();

    /** Fresh analysis maps built off the UI thread, then swapped in atomically. */
    public static final class Maps {
        public final TreeMap<Long, Long> funcEnd = new TreeMap<Long, Long>();
        public final HashSet<String> funcNames = new HashSet<String>();
        public final HashSet<String> importNames = new HashSet<String>();
        public final HashSet<String> exportNames = new HashSet<String>();
        public final HashMap<Long, String> exportAt = new HashMap<Long, String>();
        public final HashMap<Long, String> stringAt = new HashMap<Long, String>();
        public final HashMap<Long, String> names = new HashMap<Long, String>();
        public final HashMap<Long, String> dem = new HashMap<Long, String>();
    }

    public volatile long cur;
    public boolean resumed;
    private final ArrayList<Long> hist = new ArrayList<Long>();
    private int hpos = -1;
    private final ArrayList<Listener> listeners = new ArrayList<Listener>();

    public boolean isOpen() { return h != 0; }

    public String open(String p) {
        close();
        long hh = NativeBridge.open(p);
        if (hh == 0) return NativeBridge.lastError();
        h = hh; resumed = false;
        return finishOpen(p, hh);
    }

    /** Open with live analysis: loads partial results immediately, analysis continues via analyzeStep(). */
    public String openLive(String p, String snapshotPath) {
        close();
        long hh = NativeBridge.openLive(p, snapshotPath);
        if (hh == 0) return NativeBridge.lastError();
        h = hh;
        resumed = NativeBridge.resumed(hh);
        return finishOpen(p, hh);
    }

    private String finishOpen(String p, long hh) {
        machine = NativeBridge.machine(hh);
        entry = NativeBridge.entry(hh);

        ArrayList<Seg> a = new ArrayList<Seg>(), all = new ArrayList<Seg>();
        for (String r : NativeBridge.sections(hh)) {
            String[] f = Fmt.split(r);
            if (f.length < 6) continue;
            Seg s = new Seg();
            s.name = f[0]; s.start = Fmt.parseHex(f[1]); s.end = Fmt.parseHex(f[2]);
            s.flags = Long.parseLong(f[3]); s.type = Integer.parseInt(f[5]);
            all.add(s);
            if ((s.flags & 2) != 0 && s.type != 8 && s.end > s.start) a.add(s);
        }
        segs = sortSegs(a); allSegs = all.toArray(new Seg[all.size()]);

        loadDynamicMaps();
        hist.clear(); hpos = -1;
        cur = entry != 0 ? entry : minAddr();
        path = p;
        return null;
    }

    private void loadDynamicMaps() { applyMaps(buildMaps()); }

    /** Builds a complete map set (native calls included); safe on any thread, no shared mutation. */
    public Maps buildMaps() {
        Maps m = new Maps();
        if (h == 0) return m;
        for (String r : NativeBridge.functions(h)) {
            String[] f = Fmt.split(r);
            if (f.length < 3) continue;
            long st = Fmt.parseHex(f[1]);
            m.funcEnd.put(st, st + Fmt.parseHex(f[2]));
            m.funcNames.add(f[0]);
        }
        for (String r : NativeBridge.imports(h)) m.importNames.add(Fmt.split(r)[0]);
        for (String r : NativeBridge.exports(h)) {
            String[] f = Fmt.split(r);
            if (f.length < 2) continue;
            m.exportNames.add(f[0]);
            m.exportAt.put(Fmt.parseHex(f[1]), f[0]);
        }
        for (String r : NativeBridge.strings(h)) {
            String[] f = Fmt.split(r);
            if (f.length >= 4) m.stringAt.put(Fmt.parseHex(f[0]), f[3]);
        }
        for (String r : NativeBridge.names(h)) {
            String[] f = Fmt.split(r);
            if (f.length >= 2) {
                long na = Fmt.parseHex(f[1]);
                m.names.put(na, f[0]);
                if (f.length >= 4 && f[3].length() > 0) m.dem.put(na, f[3]);
            }
        }
        return m;
    }

    /** Swaps in freshly built maps; call only from the UI thread. */
    public void applyMaps(Maps m) {
        funcEnd = m.funcEnd; funcNames = m.funcNames; importNames = m.importNames;
        exportNames = m.exportNames; exportAt = m.exportAt; stringAt = m.stringAt; names = m.names;
        dem = m.dem;
        lookupCache.clear();
    }

    private static Seg[] sortSegs(ArrayList<Seg> a) {
        Seg[] r = a.toArray(new Seg[a.size()]);
        java.util.Arrays.sort(r, new java.util.Comparator<Seg>() {
            public int compare(Seg x, Seg y) { return x.start < y.start ? -1 : (x.start > y.start ? 1 : 0); }
        });
        return r;
    }

    public void close() {
        if (h != 0) { NativeBridge.close(h); h = 0; }
        resumed = false;
        segs = new Seg[0]; allSegs = new Seg[0];
    }

    // ---- address space ----------------------------------------------------------------------

    public Seg segAt(long a) {
        for (Seg s : segs) if (a >= s.start && a < s.end) return s;
        return null;
    }
    /** Next valid address >= a, hopping over gaps between segments. -1 when past the end. */
    public long snapForward(long a) {
        for (Seg s : segs) {
            if (a < s.start) return s.start;
            if (a < s.end) return a;
        }
        return -1;
    }
    /** Last valid address < a (or -1). */
    public long snapBackward(long a) {
        for (int i = segs.length - 1; i >= 0; i--) {
            Seg s = segs[i];
            if (a > s.end) return s.end - 1;
            if (a > s.start) return a - 1;
        }
        return -1;
    }
    public long minAddr() { return segs.length == 0 ? 0 : segs[0].start; }
    public long maxAddr() { return segs.length == 0 ? 0 : segs[segs.length - 1].end; }

    // ---- functions / names ------------------------------------------------------------------

    public long funcStartOf(long a) {
        Map.Entry<Long, Long> e = funcEnd.floorEntry(a);
        if (e == null || a >= e.getValue()) return 0;
        return e.getKey();
    }
    public boolean isFuncStart(long a) { return funcEnd.containsKey(a); }
    public long funcEndOf(long start) { Long e = funcEnd.get(start); return e == null ? 0 : e; }

    public String nameAt(long a) { return NativeBridge.nameAt(h, a); }

    /** 0 when unknown. Caches because the views call it per visible line. */
    public long lookup(String name) {
        Long c = lookupCache.get(name);
        if (c != null) return c;
        long v = NativeBridge.lookup(h, name);
        lookupCache.put(name, v);
        return v;
    }

    public static final int NK_NONE = 0, NK_FUNC = 1, NK_LABEL = 2, NK_DATA = 3, NK_EXTERN = 4;

    public int nameKind(String n) {
        if (importNames.contains(n)) return NK_EXTERN;
        if (n.startsWith("loc_")) return NK_LABEL;
        if (n.startsWith("sub_") || funcNames.contains(n) || exportNames.contains(n)) return NK_FUNC;
        if (n.startsWith("unk_") || n.startsWith("byte_") || n.startsWith("word_") || n.startsWith("dword_")
                || n.startsWith("qword_") || n.startsWith("off_") || n.startsWith("stru_")
                || (n.length() > 1 && n.charAt(0) == 'a' && Character.isUpperCase(n.charAt(1)))) return NK_DATA;
        return NK_NONE;
    }

    /** "sub_1000+C" style description for the status bar. */
    public String describe(long a) {
        long f = funcStartOf(a);
        if (f != 0) {
            String n = nameAt(f);
            return a == f ? n : n + "+" + Long.toHexString(a - f).toUpperCase();
        }
        String n = nameAt(a);
        return n.startsWith("0x") ? "" : n;
    }

    public String segName(long a) { Seg s = segAt(a); return s == null ? "" : s.name; }

    // ---- navigation -------------------------------------------------------------------------

    public void addListener(Listener l) { if (!listeners.contains(l)) listeners.add(l); }

    /** Set the cursor without touching history (scrolling, taps inside a view). */
    public void setCursor(long a, Object src) {
        cur = a;
        for (Listener l : new ArrayList<Listener>(listeners)) l.onAddress(a, src);
    }

    /** Jump somewhere and remember where we came from. */
    public void jump(long a, Object src) {
        long t = snapForward(a);
        if (t < 0) t = snapBackward(a);
        if (t < 0) return;
        if (hist.isEmpty()) { hist.add(cur); hpos = 0; }
        while (hist.size() > hpos + 1) hist.remove(hist.size() - 1);
        hist.set(hpos, cur);                 // remember where the user had scrolled to
        hist.add(t); hpos = hist.size() - 1;
        setCursor(t, src);
        jumpRequested(t, src);
    }

    /** Views that need to re-centre listen to this extra hook. */
    public interface JumpListener { void onJump(long addr, Object source); }
    private final ArrayList<JumpListener> jl = new ArrayList<JumpListener>();
    public void addJumpListener(JumpListener l) { if (!jl.contains(l)) jl.add(l); }
    private void jumpRequested(long a, Object src) {
        for (JumpListener l : new ArrayList<JumpListener>(jl)) l.onJump(a, src);
    }

    public boolean canBack() { return hpos > 0; }
    public boolean canForward() { return hpos >= 0 && hpos < hist.size() - 1; }
    public void back(Object src) {
        if (!canBack()) return;
        hpos--; long a = hist.get(hpos); setCursor(a, src); jumpRequested(a, src);
    }
    public void forward(Object src) {
        if (!canForward()) return;
        hpos++; long a = hist.get(hpos); setCursor(a, src); jumpRequested(a, src);
    }
}
