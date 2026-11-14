package com.znfdev.ida;

import java.util.ArrayList;

/** Small string helpers. */
public final class Fmt {
    private Fmt() {}

    /** Split on \1 and keep empty fields (String.split drops trailing ones). */
    public static String[] split(String s) {
        ArrayList<String> out = new ArrayList<String>(10);
        int st = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\u0001') { out.add(s.substring(st, i)); st = i + 1; }
        }
        out.add(s.substring(st));
        return out.toArray(new String[out.size()]);
    }

    public static String hex16(long v) {
        String h = Long.toHexString(v).toUpperCase();
        StringBuilder sb = new StringBuilder(16);
        for (int i = h.length(); i < 16; i++) sb.append('0');
        return sb.append(h).toString();
    }

    public static String hex8(long v) {
        String h = Long.toHexString(v).toUpperCase();
        StringBuilder sb = new StringBuilder(8);
        for (int i = h.length(); i < 8; i++) sb.append('0');
        return sb.append(h).toString();
    }

    public static long parseHex(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        if (s.endsWith("h") || s.endsWith("H")) s = s.substring(0, s.length() - 1);
        return Long.parseLong(s, 16);
    }

    public static void pad(StringBuilder sb, int col) {
        while (sb.length() < col) sb.append(' ');
    }
}
