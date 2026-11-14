package com.znfdev.ida;

/** JNI entry points of the native IDA-style core. Java 7 compatible. */
public final class NativeBridge {
    static { System.loadLibrary("idacore"); }
    private NativeBridge() {}

    public static native long open(String path);          // 0 on failure -> lastError()
    public static native String lastError();
    public static native void close(long h);
    public static native long entry(long h);
    public static native int machine(long h);              // 183 = AArch64

    /** name \1 start \1 end \1 flags \1 fileOff \1 type   (addresses are 16-digit hex) */
    public static native String[] sections(long h);
    /** name \1 addr \1 size \1 section */
    public static native String[] functions(long h);
    /** name \1 addr \1 section */
    public static native String[] names(long h);
    /** addr \1 section \1 name \1 text */
    public static native String[] strings(long h);
    public static native String[] imports(long h);
    /** name \1 addr */
    public static native String[] exports(long h);
    /**
     * One record per instruction, fields separated by \1:
     * 0 section, 1 addr, 2 bytes, 3 funcName(non-empty = function start), 4 label,
     * 5 codeXrefs, 6 dataXrefs, 7 mnemonic, 8 operands, 9 comment
     */
    public static native String[] disasm(long h, long addr, int count);
    /** H header, V var decl, B brace, S stmt; kind \1 text */
    public static native String[] pseudo(long h, long addr);
    /** multi-line signature block (IDA / x64dbg / C array / bitmask / addr / length / matches) */
    public static native String sig(long h, long addr);
    /** type(p/j/o/r/w) \1 fromAddr \1 fromName+off */
    public static native String[] xrefsTo(long h, long addr);
    public static native byte[] readBytes(long h, long addr, int len);
    public static native String nameAt(long h, long addr);
    public static native long lookup(long h, String name);
    public static native long funcStart(long h, long addr);

    // live analysis (database persistence)
    public static native long openLive(String path, String snapshotPath); // 0 on failure -> lastError()
    public static native boolean resumed(long h);
    public static native int analyzeStep(long h, int budget);             // 1 = more work, 0 = done
    /** done \1 stage \1 percent \1 functions \1 strings \1 currentSection \1 currentOffsetHex */
    public static native String liveState(long h);
    /** Saves progress; returns "" on success or an error message. */
    public static native String saveState(long h, String snapshotPath, long cursor, long hexAddr);
    /** hex cursor \1 hex addr of the last save (snapshot state loaded at open). */
    public static native String savedPos(long h);
}
