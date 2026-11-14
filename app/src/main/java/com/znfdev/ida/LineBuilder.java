package com.znfdev.ida;

import java.util.ArrayList;

/** Turns native records into IDA-looking lines (prefix, label, xref comments, headers). */
public final class LineBuilder {

    public static final int INDENT = 16;        // instruction indent after "seg:addr "
    public static final int MNEM_W = 16;
    public static final int CMT_COL = 40;       // comment column, relative to the end of the prefix

    private final Session s;
    public long end;                            // address right after the last emitted item

    public LineBuilder(Session s) { this.s = s; }

    // ---- row helper --------------------------------------------------------------------------

    private static final class Row {
        final StringBuilder sb = new StringBuilder(96);
        int[] runs = new int[16]; int n = 0;
        int prefixLen;
        void add(String t, int color) {
            if (t.length() == 0) return;
            if (n + 2 > runs.length) runs = java.util.Arrays.copyOf(runs, runs.length * 2);
            runs[n++] = sb.length(); runs[n++] = color;
            sb.append(t);
        }
        int bodyLen() { return sb.length() - prefixLen; }
        void padBody(int col) { while (bodyLen() < col) sb.append(' '); }
        Line finish(Line l) { l.text = sb.toString(); l.runs = java.util.Arrays.copyOf(runs, n); return l; }
    }

    private Row row(String sec, long addr) {
        Row r = new Row();
        r.add(sec + ":" + Fmt.hex16(addr) + " ", Theme.C_PREFIX);
        r.prefixLen = r.sb.length();
        return r;
    }

    private Line blank(String sec, long addr) {
        Line l = new Line(addr, Line.BLANK);
        return row(sec, addr).finish(l);
    }

    private Line comment(String sec, long addr, String text, int col) {
        Line l = new Line(addr, Line.COMMENT);
        Row r = row(sec, addr);
        if (col > 0) { r.add(spaces(col), Theme.C_OPS); }
        r.add(text, Theme.C_COMMENT);
        return r.finish(l);
    }

    private static String spaces(int n) {
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++) b.append(' ');
        return b.toString();
    }

    private static String trimXref(String x) {
        int cnt = 0, idx = -1;
        for (int i = 0; i + 1 < x.length(); i++) {
            if (x.charAt(i) == ',' && x.charAt(i + 1) == ' ') { cnt++; if (cnt == 4) { idx = i; break; } }
        }
        return idx < 0 ? x : x.substring(0, idx) + ", ...";
    }

    private int nameColor(String name) {
        switch (s.nameKind(name)) {
            case Session.NK_FUNC:   return Theme.C_FUNC;
            case Session.NK_LABEL:  return Theme.C_LABEL;
            case Session.NK_EXTERN: return Theme.C_EXTERN;
            default:                return Theme.C_DATA;
        }
    }

    // ---- executable code ---------------------------------------------------------------------

    /** Build lines for instructions with addr in [from, limit). Stops at the section end. */
    public ArrayList<Line> buildCode(long from, long limit, int maxInsns) {
        ArrayList<Line> out = new ArrayList<Line>(maxInsns * 2);
        Session.Seg seg = s.segAt(from);
        end = from;
        if (seg == null) return out;
        long stop = Math.min(limit, seg.end);
        int count = (int) Math.min((long) maxInsns, (stop - from + 3) / 4);
        if (count <= 0) return out;
        String[] recs = NativeBridge.disasm(s.h, from, count);
        for (int i = 0; i < recs.length; i++) {
            String[] f = Fmt.split(recs[i]);
            if (f.length < 10) continue;
            long a = Fmt.parseHex(f[1]);
            if (a >= stop) break;
            emitInsn(out, f, a);
            end = a + 4;
        }
        return out;
    }

    private void emitInsn(ArrayList<Line> out, String[] f, long a) {
        String sec = f[0], fn = f[3], lbl = f[4], cx = f[5], dx = f[6], mn = f[7], ops = f[8], cm = f[9];

        if (fn.length() > 0) {
            Line h = new Line(a, Line.HEADER);
            Row r = row(sec, a);
            r.add("; =============== S U B R O U T I N E =======================================", Theme.C_HEADER);
            out.add(r.finish(h));
            out.add(blank(sec, a));
            if (s.exportNames.contains(fn)) {
                Line e = new Line(a, Line.COMMENT);
                Row er = row(sec, a);
                er.add(spaces(INDENT), Theme.C_OPS);
                er.add("EXPORT ", Theme.C_MNEM);
                er.add(fn, Theme.C_FUNC);
                out.add(er.finish(e));
            }
        }
        boolean primaryDone = false;
        if (lbl.length() > 0) {
            if (dx.length() > 0 && cx.length() > 0)
                out.add(comment(sec, a, "; DATA XREF: " + trimXref(dx), 0));
            Line l = new Line(a, Line.LABEL);
            l.primary = true; primaryDone = true;
            Row r = row(sec, a);
            r.add(lbl, nameColor(lbl));
            String x = cx.length() > 0 ? "; CODE XREF: " + trimXref(cx) : (dx.length() > 0 ? "; DATA XREF: " + trimXref(dx) : "");
            if (x.length() > 0) {
                r.padBody(CMT_COL);
                r.add(x, Theme.C_COMMENT);
            }
            out.add(r.finish(l));
        }

        // unnamed function definition: draw the sub_xxx proc line (fn is synthesized by the core)
        if (fn.length() > 0 && lbl.length() == 0) {
            Line l = new Line(a, Line.LABEL);
            l.primary = true; primaryDone = true;
            Row r = row(sec, a);
            r.add(fn, nameColor(fn));
            String x = cx.length() > 0 ? "; CODE XREF: " + trimXref(cx) : (dx.length() > 0 ? "; DATA XREF: " + trimXref(dx) : "");
            if (x.length() > 0) {
                r.padBody(CMT_COL);
                r.add(x, Theme.C_COMMENT);
            }
            out.add(r.finish(l));
        }

        Line l = new Line(a, Line.INSN);
        l.primary = !primaryDone; l.size = 4;
        Row r = row(sec, a);
        r.add(spaces(INDENT), Theme.C_OPS);
        r.add(mn, Theme.C_MNEM);
        if (ops.length() > 0) {
            r.padBody(INDENT + MNEM_W);
            if (r.bodyLen() == INDENT + mn.length()) r.add(" ", Theme.C_OPS);
            String tn = scanOps(r, ops, mn);
            if (tn != null && isBranch(mn)) {
                l.target = s.lookup(tn);
                l.jumpType = mn.equals("BL") ? 'p' : (mn.equals("B") ? 'j' : 'c');
            }
        } else if (mn.equals("RET") || mn.equals("NOP")) {
            // IDA pads RET with trailing spaces; nothing to add
        }
        if (cm.length() > 0) {
            if (r.bodyLen() < CMT_COL) r.padBody(CMT_COL); else r.add(" ", Theme.C_OPS);
            r.add("; ", Theme.C_COMMENT);
            r.add(cm, Theme.C_STRING);
        }
        out.add(r.finish(l));

        // end of function?
        long fs = s.funcStartOf(a);
        if (fs != 0 && a + 4 >= s.funcEndOf(fs)) {
            String pn = s.dem.containsKey(fs) ? s.dem.get(fs)
                    : (s.names.containsKey(fs) ? s.names.get(fs)
                    : "sub_" + Long.toHexString(fs).toUpperCase());
            out.add(comment(sec, a, "; End of function " + pn, 0));
            out.add(blank(sec, a));
        }
    }

    private static boolean isBranch(String m) {
        return m.equals("B") || m.equals("BL") || m.startsWith("B.") || m.equals("CBZ") || m.equals("CBNZ")
                || m.equals("TBZ") || m.equals("TBNZ");
    }

    // ---- operand colouring -------------------------------------------------------------------

    private static boolean isIdStart(char c) { return Character.isLetter(c) || c == '_'; }
    private static boolean isIdChar(char c) { return Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '$' || c == '@' || c == '?'; }
    private static boolean isNumCh(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == 'x' || c == 'X'; }

    private static final String[] WORDS = {
        "SP", "WSP", "XZR", "WZR", "LR", "FP", "PC", "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL", "VS", "VC",
        "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV", "LSL", "LSR", "ASR", "ROR", "MSL", "UXTB", "UXTH", "UXTW",
        "UXTX", "SXTB", "SXTH", "SXTW", "SXTX"
    };

    static boolean isReg(String t) {
        for (String w : WORDS) if (w.equals(t)) return true;
        if (t.length() >= 2 && "XWVQDSBHZPT".indexOf(t.charAt(0)) >= 0 && Character.isDigit(t.charAt(1))) return true;
        return false;
    }

    /** Appends coloured operands to r; returns the last non-register name token (branch target) or null. */
    private String scanOps(Row r, String ops, String mn) {
        String last = null;
        int i = 0, n = ops.length();
        while (i < n) {
            char c = ops.charAt(i);
            if (c == '#') {
                int j = i + 1;
                if (j < n && isIdStart(ops.charAt(j))) { r.add("#", Theme.C_OPS); i = j; continue; }
                if (j < n && ops.charAt(j) == '-') j++;
                while (j < n && isNumCh(ops.charAt(j))) j++;
                r.add(ops.substring(i, j), Theme.C_NUM);
                i = j;
            } else if (Character.isDigit(c)) {
                int j = i;
                while (j < n && isNumCh(ops.charAt(j))) j++;
                r.add(ops.substring(i, j), Theme.C_NUM);
                i = j;
            } else if (isIdStart(c)) {
                int j = i;
                while (j < n && isIdChar(ops.charAt(j))) j++;
                String tok = ops.substring(i, j);
                if (isReg(tok)) r.add(tok, Theme.C_OPS);
                else {
                    int at = tok.indexOf('@');
                    String nm = at > 0 ? tok.substring(0, at) : tok;
                    r.add(tok, nameColor(nm));
                    last = nm;
                }
                i = j;
            } else {
                r.add(String.valueOf(c), Theme.C_OPS);
                i++;
            }
        }
        return last;
    }

    // ---- data --------------------------------------------------------------------------------

    /** Build data lines for items with addr in [from, limit) inside a non-code section. */
    public ArrayList<Line> buildData(long from, long limit, int maxItems) {
        ArrayList<Line> out = new ArrayList<Line>(maxItems);
        Session.Seg seg = s.segAt(from);
        end = from;
        if (seg == null) return out;
        long stop = Math.min(limit, seg.end);
        if (stop <= from) return out;
        int span = (int) Math.min(stop - from + 8, (long) maxItems * 8 + 256);
        byte[] buf = NativeBridge.readBytes(s.h, from, span);
        long a = from;
        int items = 0;
        while (a < stop && items < maxItems) {
            int off = (int) (a - from);
            if (off >= buf.length) break;
            long next = emitData(out, seg, a, buf, off, seg.end);
            if (next <= a) next = a + 1;
            a = next; items++;
        }
        end = a;
        return out;
    }

    private long le(byte[] b, int off, int n) {
        long v = 0;
        for (int i = n - 1; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xFF);
        return v;
    }

    private long emitData(ArrayList<Line> out, Session.Seg seg, long a, byte[] b, int off, long segEnd) {
        String sec = seg.name;
        String name = s.dem.containsKey(a) ? s.dem.get(a) : s.names.get(a);
        String mn, ops; int opsColor = Theme.C_OPS; long size; long tgt = 0;
        String str = s.stringAt.get(a);
        if (str != null) {
            int bl; try { bl = str.getBytes("UTF-8").length; } catch (Exception e) { bl = str.length(); }
            mn = "DCB";
            ops = "\"" + esc(str) + "\",0";
            opsColor = Theme.C_STRING;
            size = bl + 1;
        } else if ((a & 7) == 0 && a + 8 <= segEnd && off + 8 <= b.length) {
            long q = le(b, off, 8);
            mn = "DCQ"; size = 8;
            String qn = q != 0 ? (s.dem.containsKey(q) ? s.dem.get(q) : s.names.get(q)) : null;
            if (qn != null) { ops = qn; opsColor = nameColor(qn); tgt = q; }
            else { ops = q >= 0 && q < 10 ? Long.toString(q) : "0x" + Long.toHexString(q).toUpperCase(); opsColor = Theme.C_NUM; }
        } else if ((a & 3) == 0 && a + 4 <= segEnd && off + 4 <= b.length) {
            mn = "DCD"; size = 4;
            ops = "0x" + Long.toHexString(le(b, off, 4)).toUpperCase(); opsColor = Theme.C_NUM;
        } else {
            mn = "DCB"; size = 1;
            ops = "0x" + Integer.toHexString(b[off] & 0xFF).toUpperCase(); opsColor = Theme.C_NUM;
        }
        Line l = new Line(a, Line.DATA);
        l.primary = true; l.size = (int) size; l.target = tgt;
        Row r = row(sec, a);
        if (name != null) {
            r.add(name, nameColor(name));
            if (r.bodyLen() < INDENT) r.padBody(INDENT); else r.add(" ", Theme.C_OPS);
        } else {
            r.add(spaces(INDENT), Theme.C_OPS);
        }
        int mstart = r.bodyLen();
        r.add(mn, Theme.C_MNEM);
        r.padBody(mstart + MNEM_W);
        if (r.bodyLen() == mstart + mn.length()) r.add(" ", Theme.C_OPS);
        r.add(ops, opsColor);
        if (name != null) {
            String[] xr = NativeBridge.xrefsTo(s.h, a);
            if (xr.length > 0) {
                StringBuilder sb = new StringBuilder("; DATA XREF: ");
                int shown = 0;
                for (String x : xr) {
                    String[] xf = Fmt.split(x);
                    if (xf.length < 3) continue;
                    if (shown == 4) { sb.append(", ..."); break; }
                    if (shown++ > 0) sb.append(", ");
                    long from = Fmt.parseHex(xf[1]);
                    sb.append(xf[2]).append(from < a ? "\u2191" : "\u2193").append(xf[0]);
                }
                if (r.bodyLen() < CMT_COL) r.padBody(CMT_COL); else r.add(" ", Theme.C_OPS);
                r.add(sb.toString(), Theme.C_COMMENT);
            }
        }
        out.add(r.finish(l));
        return a + size;
    }

    private static String esc(String t) {
        if (t.length() > 120) t = t.substring(0, 120) + "...";
        StringBuilder b = new StringBuilder(t.length());
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '\n') b.append("\",0Ah,\""); else if (c == '\t') b.append("\",9,\"");
            else if (c == '"') b.append("\"\"");
            else if (c < 32) b.append('?'); else b.append(c);
        }
        return b.toString();
    }
}
