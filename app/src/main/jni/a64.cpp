// AArch64 decoder producing IDA-flavoured text (upper-case mnemonics, IDA operand style).
#include "ida_core.h"
#include <cstdio>
#include <cstring>
#include <cmath>
using std::string;

namespace {
inline uint32_t B(uint32_t w, int hi, int lo) { return (w >> lo) & (uint32_t)((1ULL << (hi - lo + 1)) - 1); }
inline int64_t SX(uint64_t v, int bits) { uint64_t m = 1ULL << (bits - 1); v &= ((m << 1) - 1); return (int64_t)((v ^ m) - m); }

string num(unsigned long long v) { char b[32]; if (v < 10) snprintf(b, 32, "%llu", v); else snprintf(b, 32, "0x%llX", v); return b; }
string H(int64_t v) { if (v < 0) return "-" + num((unsigned long long)(-(v + 1)) + 1ULL); return num((unsigned long long)v); }
string IM(int64_t v) { return "#" + H(v); }
string HU(uint64_t v) { return num(v); }
string S(int v) { return std::to_string(v); }

string R(int n, bool x, bool sp = false) {
    if (n == 31) return sp ? (x ? "SP" : "WSP") : (x ? "XZR" : "WZR");
    char b[8]; snprintf(b, 8, "%c%d", x ? 'X' : 'W', n); return b;
}
string FR(char t, int n) { char b[8]; snprintf(b, 8, "%c%d", t, n); return b; }
const char* CC[16] = {"EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","AL","NV"};
const char* SHN[4] = {"LSL","LSR","ASR","ROR"};
const char* EXT[8] = {"UXTB","UXTH","UXTW","UXTX","SXTB","SXTH","SXTW","SXTX"};

bool decodeBitMask(int N, int imms, int immr, int M, uint64_t& out) {
    uint32_t val = ((uint32_t)N << 6) | ((~(uint32_t)imms) & 0x3f);
    if (!val) return false;
    int len = 0; for (int b = 6; b >= 0; --b) if (val >> b & 1) { len = b; break; }
    if (len < 1) return false;
    int esize = 1 << len; if (esize > M) return false;
    int levels = esize - 1; int Sx = imms & levels, Rx = immr & levels;
    if (Sx == levels) return false;
    uint64_t welem = (Sx + 1 == 64) ? ~0ULL : ((1ULL << (Sx + 1)) - 1);
    uint64_t me = (esize == 64) ? ~0ULL : ((1ULL << esize) - 1);
    uint64_t rot = Rx ? (((welem >> Rx) | (welem << (esize - Rx))) & me) : welem;
    uint64_t res = 0; for (int i = 0; i < M; i += esize) res |= rot << i;
    if (M == 32) res &= 0xFFFFFFFFULL;
    out = res; return true;
}

string sysreg(uint32_t w) {
    int o0 = 2 + B(w,19,19), op1 = B(w,18,16), crn = B(w,15,12), crm = B(w,11,8), op2 = B(w,7,5);
    struct E { int a,b,c,d,e; const char* n; };
    static const E tbl[] = {
        {3,3,13,0,2,"TPIDR_EL0"},{3,3,13,0,3,"TPIDRRO_EL0"},{3,0,4,2,0,"NZCV"},{3,3,4,2,0,"NZCV"},
        {3,3,4,4,0,"FPCR"},{3,3,4,4,1,"FPSR"},{3,3,14,0,2,"CNTVCT_EL0"},{3,3,14,0,0,"CNTFRQ_EL0"},
        {3,0,13,0,4,"TPIDR_EL1"},{3,0,0,0,0,"S3_0_C0_C0_0"},{3,3,0,0,1,"CTR_EL0"},{3,3,0,0,7,"DCZID_EL0"},
        {3,0,0,0,5,"MPIDR_EL1"},{3,0,0,0,0,"MIDR_EL1"}
    };
    for (auto& e : tbl) if (e.a==o0 && e.b==op1 && e.c==crn && e.d==crm && e.e==op2) return e.n;
    char b[40]; snprintf(b, 40, "S%d_%d_C%d_C%d_%d", o0, op1, crn, crm, op2); return b;
}

const char* barrier(int crm) {
    switch (crm) { case 15: return "SY"; case 14: return "ST"; case 13: return "LD"; case 11: return "ISH"; case 10: return "ISHST";
        case 9: return "ISHLD"; case 7: return "NSH"; case 6: return "NSHST"; case 5: return "NSHLD"; case 3: return "OSH";
        case 2: return "OSHST"; case 1: return "OSHLD"; } return nullptr;
}

// ---------------- data processing (immediate) ----------------
bool dpImm(Insn& i, uint32_t w, uint64_t pc) {
    int op = B(w,25,23), sf = B(w,31,31), Rd = B(w,4,0), Rn = B(w,9,5); bool x = sf;
    if ((op >> 1) == 0) {
        int64_t imm = SX(((uint64_t)B(w,23,5) << 2) | B(w,30,29), 21);
        i.hasTarget = true; i.kind = K_ADDR;
        if (sf) { i.mnem = "ADRP"; i.target = (pc & ~0xFFFULL) + ((uint64_t)imm << 12); i.ops = R(Rd,true) + ", #" TG "@PAGE"; }
        else    { i.mnem = "ADR";  i.target = pc + (uint64_t)imm; i.ops = R(Rd,true) + ", " TG; }
        return true;
    }
    if (op == 2) {
        int opb = B(w,30,30), Sf = B(w,29,29), sh = B(w,22,22); uint32_t imm12 = B(w,21,10);
        string rd = R(Rd,x,!Sf), rn = R(Rn,x,true);
        string imms = "#" + num(imm12) + (sh ? ",LSL#12" : "");
        if (!Sf && !opb && imm12 == 0 && !sh && (Rd == 31 || Rn == 31)) { i.mnem = "MOV"; i.ops = rd + ", " + rn; }
        else if (Sf && Rd == 31) { i.mnem = opb ? "CMP" : "CMN"; i.ops = rn + ", " + imms; }
        else { i.mnem = opb ? (Sf ? "SUBS" : "SUB") : (Sf ? "ADDS" : "ADD"); i.ops = rd + ", " + rn + ", " + imms; }
        return true;
    }
    if (op == 4) {
        int opc = B(w,30,29), N = B(w,22,22), immr = B(w,21,16), imms = B(w,15,10);
        if (!sf && N) return false;
        uint64_t m; if (!decodeBitMask(N, imms, immr, sf ? 64 : 32, m)) return false;
        string rd = R(Rd, x, opc != 3), rn = R(Rn, x);
        if (opc == 1 && Rn == 31) { i.mnem = "MOV"; i.ops = rd + ", #" + HU(m); }
        else if (opc == 3 && Rd == 31) { i.mnem = "TST"; i.ops = rn + ", #" + HU(m); }
        else { static const char* nm[4] = {"AND","ORR","EOR","ANDS"}; i.mnem = nm[opc]; i.ops = rd + ", " + rn + ", #" + HU(m); }
        return true;
    }
    if (op == 5) {
        int opc = B(w,30,29), hw = B(w,22,21); uint64_t imm16 = B(w,20,5);
        if (opc == 1 || (!sf && hw > 1)) return false;
        uint64_t v = imm16 << (hw * 16);
        if (opc == 0) { uint64_t val = ~v; if (!sf) val &= 0xFFFFFFFFULL; i.mnem = "MOV"; i.ops = R(Rd,x) + ", #" + HU(val); }
        else if (opc == 2) { i.mnem = "MOV"; i.ops = R(Rd,x) + ", #" + HU(v); }
        else { i.mnem = "MOVK"; i.ops = R(Rd,x) + ", #" + num(imm16) + (hw ? ",LSL#" + S(hw * 16) : ""); }
        return true;
    }
    if (op == 6) {
        int opc = B(w,30,29), N = B(w,22,22), immr = B(w,21,16), imms = B(w,15,10), size = sf ? 64 : 32;
        if (opc == 3 || N != sf) return false;
        if (!sf && (immr > 31 || imms > 31)) return false;
        string rd = R(Rd,x), rn = R(Rn,x);
        if (opc == 2) {
            if (imms != size - 1 && imms + 1 == immr) { i.mnem = "LSL"; i.ops = rd + ", " + rn + ", #" + num(size - 1 - imms); }
            else if (imms == size - 1) { i.mnem = "LSR"; i.ops = rd + ", " + rn + ", #" + num(immr); }
            else if (immr == 0 && !sf && imms == 7)  { i.mnem = "UXTB"; i.ops = rd + ", " + rn; }
            else if (immr == 0 && !sf && imms == 15) { i.mnem = "UXTH"; i.ops = rd + ", " + rn; }
            else if (imms >= immr) { i.mnem = "UBFX"; i.ops = rd + ", " + rn + ", #" + num(immr) + ", #" + num(imms - immr + 1); }
            else { i.mnem = "UBFIZ"; i.ops = rd + ", " + rn + ", #" + num(size - immr) + ", #" + num(imms + 1); }
        } else if (opc == 0) {
            if (imms == size - 1) { i.mnem = "ASR"; i.ops = rd + ", " + rn + ", #" + num(immr); }
            else if (immr == 0 && imms == 7)  { i.mnem = "SXTB"; i.ops = rd + ", " + R(Rn,false); }
            else if (immr == 0 && imms == 15) { i.mnem = "SXTH"; i.ops = rd + ", " + R(Rn,false); }
            else if (immr == 0 && imms == 31 && sf) { i.mnem = "SXTW"; i.ops = rd + ", " + R(Rn,false); }
            else if (imms >= immr) { i.mnem = "SBFX"; i.ops = rd + ", " + rn + ", #" + num(immr) + ", #" + num(imms - immr + 1); }
            else { i.mnem = "SBFIZ"; i.ops = rd + ", " + rn + ", #" + num(size - immr) + ", #" + num(imms + 1); }
        } else {
            if (imms < immr) {
                if (Rn == 31) { i.mnem = "BFC"; i.ops = rd + ", #" + num(size - immr) + ", #" + num(imms + 1); }
                else { i.mnem = "BFI"; i.ops = rd + ", " + rn + ", #" + num(size - immr) + ", #" + num(imms + 1); }
            } else { i.mnem = "BFXIL"; i.ops = rd + ", " + rn + ", #" + num(immr) + ", #" + num(imms - immr + 1); }
        }
        return true;
    }
    if (op == 7) {
        int N = B(w,22,22), Rm = B(w,20,16), imms = B(w,15,10);
        if (B(w,30,29) != 0 || B(w,21,21) != 0 || N != sf || (!sf && imms > 31)) return false;
        if (Rn == Rm) { i.mnem = "ROR"; i.ops = R(Rd,x) + ", " + R(Rn,x) + ", #" + num(imms); }
        else { i.mnem = "EXTR"; i.ops = R(Rd,x) + ", " + R(Rn,x) + ", " + R(Rm,x) + ", #" + num(imms); }
        return true;
    }
    return false;
}

// ---------------- branches / system ----------------
bool branchSys(Insn& i, uint32_t w, uint64_t pc) {
    auto T = [&](uint64_t t, int k) { i.target = t; i.hasTarget = true; i.kind = k; };
    int Rt = B(w,4,0), Rn = B(w,9,5);
    if (B(w,30,26) == 5) {
        bool bl = B(w,31,31); T(pc + (uint64_t)(SX(B(w,25,0), 26) * 4), bl ? K_CALL : K_JUMP);
        i.mnem = bl ? "BL" : "B"; i.ops = TG; return true;
    }
    if (B(w,30,25) == 0x1A) {
        T(pc + (uint64_t)(SX(B(w,23,5), 19) * 4), K_CJUMP);
        i.mnem = B(w,24,24) ? "CBNZ" : "CBZ"; i.ops = R(Rt, B(w,31,31)) + ", " TG; return true;
    }
    if (B(w,30,25) == 0x1B) {
        int b5 = B(w,31,31), bit = (b5 << 5) | B(w,23,19);
        T(pc + (uint64_t)(SX(B(w,18,5), 14) * 4), K_CJUMP);
        i.mnem = B(w,24,24) ? "TBNZ" : "TBZ"; i.ops = R(Rt, b5) + ", #" + num(bit) + ", " TG; return true;
    }
    if (B(w,31,25) == 0x2A && !B(w,4,4)) {
        T(pc + (uint64_t)(SX(B(w,23,5), 19) * 4), K_CJUMP);
        i.mnem = string("B.") + CC[B(w,3,0)]; i.ops = TG; return true;
    }
    if (B(w,31,25) == 0x6B) {
        int opc = B(w,24,21), op2 = B(w,20,16), op3 = B(w,15,10), op4 = B(w,4,0);
        if (op2 != 0x1F) return false;
        if (op3 == 0) {
            if (opc == 0 && op4 == 0) { i.mnem = "BR";  i.ops = R(Rn,true); i.kind = K_IJUMP; return true; }
            if (opc == 1 && op4 == 0) { i.mnem = "BLR"; i.ops = R(Rn,true); i.kind = K_ICALL; return true; }
            if (opc == 2 && op4 == 0) { i.mnem = "RET"; i.ops = Rn == 30 ? "" : R(Rn,true); i.kind = K_RET; return true; }
            if (opc == 4 && op4 == 0 && Rn == 31) { i.mnem = "ERET"; i.kind = K_RET; return true; }
        } else if ((op3 == 2 || op3 == 3) && opc == 2 && Rn == 31 && op4 == 31) {
            i.mnem = op3 == 2 ? "RETAA" : "RETAB"; i.kind = K_RET; return true;
        }
        return false;
    }
    if (B(w,31,24) == 0xD4 && B(w,4,2) == 0) {
        int opc = B(w,23,21), ll = B(w,1,0); uint32_t imm = B(w,20,5);
        if (opc == 0 && ll >= 1) { static const char* n[4] = {"","SVC","HVC","SMC"}; i.mnem = n[ll]; i.ops = num(imm); return true; }
        if (opc == 1 && ll == 0) { i.mnem = "BRK"; i.ops = num(imm); return true; }
        if (opc == 2 && ll == 0) { i.mnem = "HLT"; i.ops = num(imm); return true; }
        return false;
    }
    if ((w & 0xFFFFF01F) == 0xD503201F) {
        int h = B(w,11,5);
        switch (h) {
            case 0: i.mnem = "NOP"; return true;   case 1: i.mnem = "YIELD"; return true;
            case 2: i.mnem = "WFE"; return true;   case 3: i.mnem = "WFI"; return true;
            case 4: i.mnem = "SEV"; return true;   case 5: i.mnem = "SEVL"; return true;
            case 25: i.mnem = "PACIASP"; return true; case 27: i.mnem = "PACIBSP"; return true;
            case 29: i.mnem = "AUTIASP"; return true; case 31: i.mnem = "AUTIBSP"; return true;
            case 32: i.mnem = "BTI"; return true;  case 34: i.mnem = "BTI"; i.ops = "c"; return true;
            case 36: i.mnem = "BTI"; i.ops = "j"; return true; case 38: i.mnem = "BTI"; i.ops = "jc"; return true;
            default: i.mnem = "HINT"; i.ops = "#" + num(h); return true;
        }
    }
    if ((w & 0xFFFFF01F) == 0xD503301F) {
        int crm = B(w,11,8), op2 = B(w,7,5); const char* b = barrier(crm);
        if (op2 == 2) { i.mnem = "CLREX"; if (crm != 15) i.ops = "#" + num(crm); return true; }
        if (op2 == 4 || op2 == 5) { i.mnem = op2 == 4 ? "DSB" : "DMB"; i.ops = b ? b : "#" + num(crm); return true; }
        if (op2 == 6) { i.mnem = "ISB"; if (crm != 15) i.ops = "#" + num(crm); else i.ops = "SY"; return true; }
        return false;
    }
    if ((w & 0xFFF00000) == 0xD5300000) { i.mnem = "MRS"; i.ops = R(Rt,true) + ", " + sysreg(w); return true; }
    if ((w & 0xFFF00000) == 0xD5100000) { i.mnem = "MSR"; i.ops = sysreg(w) + ", " + R(Rt,true); return true; }
    return false;
}

// ---------------- loads / stores ----------------
bool ldst(Insn& i, uint32_t w, uint64_t pc) {
    int Rt = B(w,4,0), Rn = B(w,9,5), vf = B(w,26,26), t29 = B(w,29,27);
    string base = R(Rn, true, true);
    auto mem = [&](int64_t off) { return off ? "[" + base + "," + IM(off) + "]" : "[" + base + "]"; };

    if (B(w,29,24) == 8) {   // exclusive / ordered
        int size = B(w,31,30), o2 = B(w,23,23), L = B(w,22,22), o1 = B(w,21,21), Rs = B(w,20,16), o0 = B(w,15,15);
        if (o1) return false;
        const char* n;
        if (!o2) n = L ? (o0 ? "LDAXR" : "LDXR") : (o0 ? "STLXR" : "STXR");
        else     n = L ? (o0 ? "LDAR" : "LDLAR") : (o0 ? "STLR" : "STLLR");
        string m = n; if (size == 0) m += "B"; else if (size == 1) m += "H";
        string rt = R(Rt, size == 3);
        i.mnem = m;
        i.ops = (!o2 && !L) ? R(Rs,false) + ", " + rt + ", [" + base + "]" : rt + ", [" + base + "]";
        return true;
    }
    if (t29 == 3 && B(w,25,24) == 0) {   // literal
        int opc = B(w,31,30);
        i.target = pc + (uint64_t)(SX(B(w,23,5), 19) * 4); i.hasTarget = true; i.kind = K_LIT;
        if (vf) { if (opc == 3) return false; i.mnem = "LDR"; i.ops = FR(opc == 0 ? 'S' : opc == 1 ? 'D' : 'Q', Rt) + ", =" TG; }
        else if (opc == 0) { i.mnem = "LDR"; i.ops = R(Rt,false) + ", =" TG; }
        else if (opc == 1) { i.mnem = "LDR"; i.ops = R(Rt,true) + ", =" TG; }
        else if (opc == 2) { i.mnem = "LDRSW"; i.ops = R(Rt,true) + ", =" TG; }
        else { i.mnem = "PRFM"; i.ops = "#" + num(Rt) + ", =" TG; }
        return true;
    }
    if (t29 == 5) {   // pairs
        int opc = B(w,31,30), type = B(w,24,23), L = B(w,22,22), Rt2 = B(w,14,10);
        int64_t imm7 = SX(B(w,21,15), 7); int scale; string a, b; string m;
        if (opc == 3) return false;
        if (!vf) {
            bool x = opc == 2; scale = x ? 3 : 2;
            if (opc == 1) { if (!L) return false; m = "LDPSW"; a = R(Rt,true); b = R(Rt2,true); }
            else { m = L ? "LDP" : "STP"; a = R(Rt,x); b = R(Rt2,x); }
        } else {
            char t = opc == 0 ? 'S' : opc == 1 ? 'D' : 'Q'; scale = 2 + opc;
            m = L ? "LDP" : "STP"; a = FR(t,Rt); b = FR(t,Rt2);
        }
        if (type == 0) { if (opc == 1) return false; m = L ? "LDNP" : "STNP"; }
        int64_t off = imm7 * (int64_t)(1 << scale);
        string mm;
        if (type == 1) mm = "[" + base + "]," + IM(off);
        else if (type == 3) mm = "[" + base + "," + IM(off) + "]!";
        else mm = mem(off);
        i.mnem = m; i.ops = a + ", " + b + ", " + mm; return true;
    }
    if (t29 == 7) {
        int size = B(w,31,30), opc = B(w,23,22), scale; string m, rt;
        if (!vf) {
            if (opc == 0) { m = size == 0 ? "STRB" : size == 1 ? "STRH" : "STR"; rt = R(Rt, size == 3); }
            else if (opc == 1) { m = size == 0 ? "LDRB" : size == 1 ? "LDRH" : "LDR"; rt = R(Rt, size == 3); }
            else if (opc == 2) { if (size == 3) { m = "PRFM"; rt = "#" + num(Rt); } else { m = size == 0 ? "LDRSB" : size == 1 ? "LDRSH" : "LDRSW"; rt = R(Rt,true); } }
            else { if (size >= 2) return false; m = size == 0 ? "LDRSB" : "LDRSH"; rt = R(Rt,false); }
            scale = size; if (m == "PRFM") scale = 3;
        } else {
            if (size == 0 && opc >= 2) { m = opc == 2 ? "STR" : "LDR"; rt = FR('Q',Rt); scale = 4; }
            else { if (opc > 1) return false; m = opc ? "LDR" : "STR"; rt = FR("BHSD"[size], Rt); scale = size; }
        }
        string mm;
        if (B(w,24,24)) {
            mm = mem((int64_t)B(w,21,10) << scale);
        } else if (!B(w,21,21)) {
            int64_t imm9 = SX(B(w,20,12), 9); int ty = B(w,11,10);
            if (ty == 0) {
                if (m == "PRFM") m = "PRFUM"; else m = m.substr(0,2) + "UR" + m.substr(3);
                mm = mem(imm9);
            } else if (ty == 1) mm = "[" + base + "]," + IM(imm9);
            else if (ty == 3) mm = "[" + base + "," + IM(imm9) + "]!";
            else return false;
        } else {
            if (B(w,11,10) != 2) return false;
            int Rm = B(w,20,16), opt = B(w,15,13), Sb = B(w,12,12);
            if (opt != 2 && opt != 3 && opt != 6 && opt != 7) return false;
            mm = "[" + base + "," + R(Rm, opt & 1);
            if (opt == 3) { if (Sb) mm += ",LSL#" + S(scale); }
            else mm += string(",") + EXT[opt] + (Sb ? "#" + S(scale) : "");
            mm += "]";
        }
        i.mnem = m; i.ops = rt + ", " + mm; return true;
    }
    return false;
}

// ---------------- data processing (register) ----------------
bool dpReg(Insn& i, uint32_t w, uint64_t) {
    int sf = B(w,31,31), Rd = B(w,4,0), Rn = B(w,9,5), Rm = B(w,20,16); bool x = sf;
    if (!B(w,28,28)) {
        int shift = B(w,23,22), imm6 = B(w,15,10);
        if (!B(w,24,24)) {
            int opc = B(w,30,29), N = B(w,21,21);
            if (!sf && imm6 >= 32) return false;
            string sh = imm6 ? string(",") + SHN[shift] + "#" + S(imm6) : "";
            string rd = R(Rd,x), rn = R(Rn,x), rm = R(Rm,x);
            if (opc == 1 && !N && Rn == 31 && imm6 == 0 && shift == 0) { i.mnem = "MOV"; i.ops = rd + ", " + rm; }
            else if (opc == 1 && N && Rn == 31) { i.mnem = "MVN"; i.ops = rd + ", " + rm + sh; }
            else if (opc == 3 && !N && Rd == 31) { i.mnem = "TST"; i.ops = rn + ", " + rm + sh; }
            else { static const char* nm[2][4] = {{"AND","ORR","EOR","ANDS"},{"BIC","ORN","EON","BICS"}}; i.mnem = nm[N][opc]; i.ops = rd + ", " + rn + ", " + rm + sh; }
            return true;
        }
        int op = B(w,30,30), Sf = B(w,29,29);
        if (!B(w,21,21)) {
            if (shift == 3 || (!sf && imm6 >= 32)) return false;
            string sh = imm6 ? string(",") + SHN[shift] + "#" + S(imm6) : "";
            string rd = R(Rd,x), rn = R(Rn,x), rm = R(Rm,x);
            if (Sf && Rd == 31) { i.mnem = op ? "CMP" : "CMN"; i.ops = rn + ", " + rm + sh; }
            else if (op && Rn == 31) { i.mnem = Sf ? "NEGS" : "NEG"; i.ops = rd + ", " + rm + sh; }
            else { i.mnem = op ? (Sf ? "SUBS" : "SUB") : (Sf ? "ADDS" : "ADD"); i.ops = rd + ", " + rn + ", " + rm + sh; }
            return true;
        }
        if (B(w,23,22) != 0) return false;
        int option = B(w,15,13), imm3 = B(w,12,10); if (imm3 > 4) return false;
        string rd = R(Rd,x,!Sf), rn = R(Rn,x,true), rm = R(Rm, (option & 3) == 3);
        bool lsl = ((!Sf && Rd == 31) || Rn == 31) && option == (sf ? 3 : 2);
        string ex = lsl ? (imm3 ? ",LSL#" + S(imm3) : "") : string(",") + EXT[option] + (imm3 ? "#" + S(imm3) : "");
        if (Sf && Rd == 31) { i.mnem = op ? "CMP" : "CMN"; i.ops = R(Rn,x,true) + ", " + rm + ex; }
        else { i.mnem = op ? (Sf ? "SUBS" : "SUB") : (Sf ? "ADDS" : "ADD"); i.ops = rd + ", " + rn + ", " + rm + ex; }
        return true;
    }
    int top = B(w,28,21);
    if (top == 0xD0) {
        int op = B(w,30,30), Sf = B(w,29,29); if (B(w,15,10)) return false;
        if (op && Rn == 31) { i.mnem = Sf ? "NGCS" : "NGC"; i.ops = R(Rd,x) + ", " + R(Rm,x); return true; }
        i.mnem = op ? (Sf ? "SBCS" : "SBC") : (Sf ? "ADCS" : "ADC");
        i.ops = R(Rd,x) + ", " + R(Rn,x) + ", " + R(Rm,x); return true;
    }
    if (top == 0xD2) {
        int op = B(w,30,30); if (!B(w,29,29) || B(w,10,10) || B(w,4,4)) return false;
        string rhs = B(w,11,11) ? "#" + num(Rm) : R(Rm,x);
        i.mnem = op ? "CCMP" : "CCMN"; i.ops = R(Rn,x) + ", " + rhs + ", #" + num(B(w,3,0)) + ", " + CC[B(w,15,12)]; return true;
    }
    if (top == 0xD4) {
        int op = B(w,30,30), op2 = B(w,11,10), cond = B(w,15,12); if (B(w,29,29) || op2 > 1) return false;
        int sel = (op << 1) | op2; string rd = R(Rd,x), rn = R(Rn,x), rm = R(Rm,x);
        if (sel == 1 && Rm == 31 && Rn == 31 && cond < 14) { i.mnem = "CSET"; i.ops = rd + ", " + CC[cond ^ 1]; }
        else if (sel == 2 && Rm == 31 && Rn == 31 && cond < 14) { i.mnem = "CSETM"; i.ops = rd + ", " + CC[cond ^ 1]; }
        else if (sel >= 1 && Rn == Rm && Rn != 31 && cond < 14) { i.mnem = sel == 1 ? "CINC" : sel == 2 ? "CINV" : "CNEG"; i.ops = rd + ", " + rn + ", " + CC[cond ^ 1]; }
        else { static const char* nm[4] = {"CSEL","CSINC","CSINV","CSNEG"}; i.mnem = nm[sel]; i.ops = rd + ", " + rn + ", " + rm + ", " + CC[cond]; }
        return true;
    }
    if (top == 0xD6) {
        if (!B(w,30,30)) {
            int opc = B(w,15,10); if (B(w,29,29)) return false;
            const char* n = opc == 2 ? "UDIV" : opc == 3 ? "SDIV" : opc == 8 ? "LSL" : opc == 9 ? "LSR" : opc == 10 ? "ASR" : opc == 11 ? "ROR" : nullptr;
            if (!n) return false; i.mnem = n; i.ops = R(Rd,x) + ", " + R(Rn,x) + ", " + R(Rm,x); return true;
        }
        int opc = B(w,15,10); if (B(w,29,29) || B(w,20,16)) return false;
        const char* n = nullptr;
        if (opc == 0) n = "RBIT"; else if (opc == 1) n = "REV16"; else if (opc == 2) n = sf ? "REV32" : "REV";
        else if (opc == 3 && sf) n = "REV"; else if (opc == 4) n = "CLZ"; else if (opc == 5) n = "CLS";
        if (!n) return false; i.mnem = n; i.ops = R(Rd,x) + ", " + R(Rn,x); return true;
    }
    if (B(w,28,24) == 0x1B) {
        int op31 = B(w,23,21), o0 = B(w,15,15), Ra = B(w,14,10);
        if (op31 == 0) {
            if (Ra == 31) { i.mnem = o0 ? "MNEG" : "MUL"; i.ops = R(Rd,x) + ", " + R(Rn,x) + ", " + R(Rm,x); }
            else { i.mnem = o0 ? "MSUB" : "MADD"; i.ops = R(Rd,x) + ", " + R(Rn,x) + ", " + R(Rm,x) + ", " + R(Ra,x); }
            return true;
        }
        if (!sf) return false;
        if (op31 == 1 || op31 == 5) {
            bool u = op31 == 5;
            if (Ra == 31) { i.mnem = u ? (o0 ? "UMNEGL" : "UMULL") : (o0 ? "SMNEGL" : "SMULL"); i.ops = R(Rd,true) + ", " + R(Rn,false) + ", " + R(Rm,false); }
            else { i.mnem = u ? (o0 ? "UMSUBL" : "UMADDL") : (o0 ? "SMSUBL" : "SMADDL"); i.ops = R(Rd,true) + ", " + R(Rn,false) + ", " + R(Rm,false) + ", " + R(Ra,true); }
            return true;
        }
        if ((op31 == 2 || op31 == 6) && !o0) { i.mnem = op31 == 2 ? "SMULH" : "UMULH"; i.ops = R(Rd,true) + ", " + R(Rn,true) + ", " + R(Rm,true); return true; }
    }
    return false;
}

// ---------------- scalar floating point (subset) ----------------
string fpimm(int imm8) {
    int s = imm8 >> 7, b6 = (imm8 >> 6) & 1, r = (imm8 >> 4) & 3, f = imm8 & 15;
    int n = b6 ? (r - 3) : (r + 1);
    double v = (16.0 + f) / 16.0 * std::pow(2.0, n); if (s) v = -v;
    char b[40]; snprintf(b, 40, "%.10g", v); string o = b; if (o.find('.') == string::npos && o.find('e') == string::npos) o += ".0"; return o;
}
bool simdfp(Insn& i, uint32_t w, uint64_t) {
    uint32_t top = B(w,31,24); int type = B(w,23,22), Rd = B(w,4,0), Rn = B(w,9,5), Rm = B(w,20,16);
    auto ft = [&](int t) -> char { return t == 0 ? 'S' : t == 1 ? 'D' : t == 3 ? 'H' : 0; };
    char t = ft(type);
    if (top == 0x1F) {
        if (!t) return false; int o1 = B(w,21,21), o0 = B(w,15,15), Ra = B(w,14,10);
        static const char* n[4] = {"FMADD","FMSUB","FNMADD","FNMSUB"}; i.mnem = n[o1 * 2 + o0];
        i.ops = FR(t,Rd) + ", " + FR(t,Rn) + ", " + FR(t,Rm) + ", " + FR(t,Ra); return true;
    }
    if (top != 0x1E && top != 0x9E) return false;
    if (!B(w,21,21)) return false;
    if (top == 0x1E) {
        if (!t) return false;
        if (B(w,11,10) == 2) {
            static const char* n[9] = {"FMUL","FDIV","FADD","FSUB","FMAX","FMIN","FMAXNM","FMINNM","FNMUL"};
            int op = B(w,15,12); if (op > 8) return false;
            i.mnem = n[op]; i.ops = FR(t,Rd) + ", " + FR(t,Rn) + ", " + FR(t,Rm); return true;
        }
        if (B(w,11,10) == 3) { i.mnem = "FCSEL"; i.ops = FR(t,Rd) + ", " + FR(t,Rn) + ", " + FR(t,Rm) + ", " + CC[B(w,15,12)]; return true; }
        if (B(w,13,10) == 8 && B(w,15,14) == 0) {
            int opc = B(w,4,3); i.mnem = (opc & 2) ? "FCMPE" : "FCMP";
            i.ops = FR(t,Rn) + ", " + ((opc & 1) ? string("#0.0") : FR(t,Rm)); return true;
        }
        if (B(w,12,10) == 4 && B(w,9,5) == 0) { i.mnem = "FMOV"; i.ops = FR(t,Rd) + ", #" + fpimm(B(w,20,13)); return true; }
        if (B(w,14,10) == 0x10) {
            int op = B(w,20,15);
            static const char* n1[4] = {"FMOV","FABS","FNEG","FSQRT"};
            if (op < 4) { i.mnem = n1[op]; i.ops = FR(t,Rd) + ", " + FR(t,Rn); return true; }
            if (op == 4 || op == 5 || op == 7) { char d = op == 4 ? 'S' : op == 5 ? 'D' : 'H'; if (d == t) return false; i.mnem = "FCVT"; i.ops = FR(d,Rd) + ", " + FR(t,Rn); return true; }
            if (op >= 8 && op <= 15 && op != 13) {
                static const char* nr[8] = {"FRINTN","FRINTP","FRINTM","FRINTZ","FRINTA","","FRINTX","FRINTI"};
                i.mnem = nr[op - 8]; i.ops = FR(t,Rd) + ", " + FR(t,Rn); return true;
            }
            return false;
        }
    }
    if (B(w,15,10) == 0) {
        int sf = B(w,31,31), rmode = B(w,20,19), opc = B(w,18,16);
        if (!t || type == 2) return false;
        if ((sf == 0 && type == 1 && false) ) return false;
        if (rmode == 0 && opc == 6) { i.mnem = "FMOV"; i.ops = R(Rd,sf) + ", " + FR(t,Rn); return true; }
        if (rmode == 0 && opc == 7) { i.mnem = "FMOV"; i.ops = FR(t,Rd) + ", " + R(Rn,sf); return true; }
        if (rmode == 0 && (opc == 2 || opc == 3)) { i.mnem = opc == 2 ? "SCVTF" : "UCVTF"; i.ops = FR(t,Rd) + ", " + R(Rn,sf); return true; }
        if (opc <= 1) {
            static const char* n[4][2] = {{"FCVTNS","FCVTNU"},{"FCVTPS","FCVTPU"},{"FCVTMS","FCVTMU"},{"FCVTZS","FCVTZU"}};
            i.mnem = n[rmode][opc]; i.ops = R(Rd,sf) + ", " + FR(t,Rn); return true;
        }
        if (rmode == 0 && (opc == 4 || opc == 5)) { i.mnem = opc == 4 ? "FCVTAS" : "FCVTAU"; i.ops = R(Rd,sf) + ", " + FR(t,Rn); return true; }
    }
    return false;
}
} // namespace

Insn a64_decode(uint64_t pc, uint32_t w) {
    Insn i; i.addr = pc; i.raw = w;
    int op0 = B(w,28,25); bool ok = false;
    if ((op0 & 0xE) == 0x8) ok = dpImm(i, w, pc);
    else if ((op0 & 0xE) == 0xA) ok = branchSys(i, w, pc);
    else if ((op0 & 5) == 4) ok = ldst(i, w, pc);
    else if ((op0 & 7) == 5) ok = dpReg(i, w, pc);
    else if ((op0 & 7) == 7) ok = simdfp(i, w, pc);
    if (!ok) { i = Insn(); i.addr = pc; i.raw = w; char b[24]; snprintf(b, 24, "0x%08X", w); i.mnem = "DCD"; i.ops = b; }
    return i;
}
