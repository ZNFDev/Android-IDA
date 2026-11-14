package com.znfdev.ida;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;

/** IDA dark palette + shared metrics. Java 7. */
public final class Theme {
    private Theme() {}

    public static final int BG        = 0xFF1B1C1F;
    public static final int BG_ALT    = 0xFF232428;
    public static final int PANEL     = 0xFF2B2D31;
    public static final int PANEL_HI  = 0xFF35373C;
    public static final int BORDER    = 0xFF3F4146;
    public static final int TEXT      = 0xFFD4D4D4;
    public static final int TEXT_DIM  = 0xFF8C8F96;

    // IDA View colours
    public static final int C_PREFIX  = 0xFF7F8C99;   // .text:0000000000001000
    public static final int C_MNEM    = 0xFF6FB1FC;   // instruction
    public static final int C_OPS     = 0xFFD4D4D4;   // registers, punctuation
    public static final int C_NUM     = 0xFF7FD17F;   // #0x10
    public static final int C_FUNC    = 0xFF8FB8FF;   // sub_xxx / function names
    public static final int C_LABEL   = 0xFFE0E0E0;   // loc_xxx
    public static final int C_DATA    = 0xFFD7BA7D;   // unk_ / a<String> / data names
    public static final int C_EXTERN  = 0xFFE57BA0;   // imports (PLT)
    public static final int C_COMMENT = 0xFF8A94A6;   // ; CODE XREF ...
    public static final int C_STRING  = 0xFFE6B673;   // "text"
    public static final int C_HEADER  = 0xFFA7B1C2;   // ; ==== S U B R O U T I N E ====
    public static final int C_KEYWORD = 0xFFC586C0;   // EXPORT, DCB, DCD
    public static final int C_BYTES   = 0xFFB0B0B0;

    public static final int SEL_LINE  = 0xFF2A3F5F;
    public static final int CUR_LINE  = 0xFF26364F;
    public static final int TOKEN_HI  = 0xFF4A5F80;
    public static final int FOUND_HI  = 0xFF6B5B1F;
    public static final int ARROW     = 0xFF9AA5B5;
    public static final int ARROW_COND= 0xFF6C7686;

    // Navigation band colours (IDA legend)
    public static final int NB_FUNC    = 0xFF5B8DB8;   // regular function
    public static final int NB_LIB     = 0xFF55B8B8;   // library function
    public static final int NB_INSN    = 0xFFA77B55;   // instruction
    public static final int NB_DATA    = 0xFF8C8C8C;   // data
    public static final int NB_UNEXPL  = 0xFF5C5E4F;   // unexplored
    public static final int NB_EXTERN  = 0xFFD070A0;   // external
    public static final int NB_STR     = 0xFFC9A96A;   // string data
    public static final int NB_CURSOR  = 0xFFFFE04A;

    private static Typeface mono;

    /** Uses assets/fonts/mono.ttf when present (e.g. Consolas-like), else system monospace. */
    public static Typeface mono(Context c) {
        if (mono == null) {
            try { mono = Typeface.createFromAsset(c.getAssets(), "fonts/mono.ttf"); }
            catch (Throwable t) { mono = Typeface.MONOSPACE; }
        }
        return mono;
    }

    public static int dp(Context c, float v) {
        return (int) (v * c.getResources().getDisplayMetrics().density + 0.5f);
    }

    public static int alpha(int color, int a) {
        return Color.argb(a, Color.red(color), Color.green(color), Color.blue(color));
    }
}
