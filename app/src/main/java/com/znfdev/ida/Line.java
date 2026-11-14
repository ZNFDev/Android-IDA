package com.znfdev.ida;

/** One rendered line of IDA View: text + colour runs. */
public final class Line {
    public static final int INSN = 0, LABEL = 1, COMMENT = 2, BLANK = 3, DATA = 4, HEADER = 5;

    public long addr;      // address this line belongs to
    public int size;       // bytes this item covers (only set on the primary line of an item)
    public int kind;
    public boolean primary;// true on the line that "is" the address (label/insn/data)
    public String text;    // full text including "sec:addr " prefix
    public int[] runs;     // pairs: start index, colour
    public long target;    // branch / data target (0 = none)
    public char jumpType;  // 'j' unconditional, 'c' conditional, 'p' call, 0 none

    public Line(long addr, int kind) { this.addr = addr; this.kind = kind; }
}
