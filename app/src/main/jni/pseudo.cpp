// HexRays-style pseudocode generator for AArch64.

#include "ida_core.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

namespace {

bool startsWith(const std::string &s, const char *p) {
    size_t n = strlen(p);
    return s.size() >= n && memcmp(s.data(), p, n) == 0;
}

std::string trim(const std::string &s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> opsSplit(const std::string &s) {
    std::vector<std::string> r;
    size_t p = 0;
    for (;;) {
        size_t c = s.find(", ", p);
        if (c == std::string::npos) { r.push_back(s.substr(p)); break; }
        r.push_back(s.substr(p, c - p));
        p = c + 2;
    }
    return r;
}

// register numbering: 0..30 general, 31 SP, -1 ZR;
// 64+n S, 128+n D, 192+n Q, 256+n H, 320+n B
int parseReg(const std::string &t) {
    if (t == "SP" || t == "WSP") return 31;
    if (t.size() >= 3 && t[1] == 'Z' && t[2] == 'R' && (t[0] == 'X' || t[0] == 'W')) return -1;
    if (t.size() >= 2 && (t[0] == 'X' || t[0] == 'W') && t[1] >= '0' && t[1] <= '9') {
        int n = atoi(t.c_str() + 1);
        if (n >= 0 && n <= 30) return n;
    }
    if (t.size() >= 2 && t[1] >= '0' && t[1] <= '9') {
        static const char *nm = "SDQHB";
        const char *q = strchr(nm, t[0]);
        if (q) {
            int n = atoi(t.c_str() + 1);
            if (n >= 0 && n <= 31) return (int)(q - nm) * 64 + 64 + n;
        }
    }
    return -2;
}

bool isFloatReg(int r) { return r >= 64; }

const char *ftype(int r) {
    if (r < 128) return "float";
    if (r < 192) return "double";
    if (r < 256) return "__int128";
    return "__fp16";
}

// free version; the PGen method delegates with its own anyX array
std::string rawRegTxt(int r, const bool *anyX) {
    char b[16];
    if (r == 31) return "SP";
    if (r < 0) return "0";
    if (r >= 320) { snprintf(b, 16, "b%d", r - 320); return b; }
    if (r >= 256) { snprintf(b, 16, "h%d", r - 256); return b; }
    if (r >= 192) { snprintf(b, 16, "q%d", r - 192); return b; }
    if (r >= 128) { snprintf(b, 16, "d%d", r - 128); return b; }
    if (r >= 64) { snprintf(b, 16, "s%d", r - 64); return b; }
    snprintf(b, 16, "%s%d", anyX[r] ? "x" : "w", r);
    return b;
}

std::string constOfs(long long v) {
    char b[40];
    if (v >= 2147483648LL || v < -2147483648LL) { snprintf(b, 40, "%lldLL", v); return b; }
    snprintf(b, 40, "%lld", v);
    return b;
}

long long parseImm(const std::string &t) {
    std::string s = t;
    if (!s.empty() && s[0] == '#') s = s.substr(1);
    if (!s.empty() && s[0] == '=') s = s.substr(1);
    return strtoll(s.c_str(), NULL, 0);
}

const int CCINV[16] = {1,0,3,2,5,4,7,6,9,8,11,10,13,12,14,15};
const char *CCN[16] = {"EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","AL","NV"};
// per condition: hexrays operator text; "#6"/"#7" are OFSUB markers
const char *CCOP[16] = {"==","!=",">=","<","<",">=","#6","#7",">","<=",">=","<",">","<=","1","1"};

struct Cond {
    int kind;       // 0: cmp, 1: zero check, 2: bit test
    int ci;         // condition code index for kind 0
    std::string l, r, v;
    bool nz;
    long long bv;
    bool inv_;
    Cond() : kind(0), ci(0), nz(false), bv(0), inv_(false) {}
    std::string text() const {
        if (kind == 0) {
            int e = inv_ ? CCINV[ci] : ci;
            const char *op = CCOP[e];
            if (e == 14 || e == 15) return std::string("1");
            if (op[0] == '#') {
                std::string o = std::string("__OFSUB__(") + l + ", " + r + ")";
                if (op[1] == '6') return o;
                return "!" + o;
            }
            return "(" + l + " " + op + " " + r + ")";
        }
        if (kind == 1) return "(" + v + (inv_ ? (nz ? " == 0" : " != 0") : (nz ? " != 0" : " == 0")) + ")";
        return "(" + v + " & " + bitmask() + (inv_ ? (nz ? ") == 0" : ") != 0") : (nz ? ") != 0" : ") == 0"));
    }
    Cond inv() const {
        Cond c = *this;
        c.inv_ = !c.inv_;
        return c;
    }
private:
    std::string bitmask() const {
        char b[32];
        snprintf(b, 32, "%llu", (unsigned long long)(1ULL << bv));
        return b;
    }
};

struct MemP {
    int base;            // register number
    int idx;             // register number or -2
    int scale;           // 1 << shift for [base, idx, LSL #n]
    long long imm;
    bool pre, post, ok;
    MemP() : base(-2), idx(-2), scale(1), imm(0), pre(false), post(false), ok(false) {}
    bool isSP() const { return base == 31; }
};

MemP parseMem(const std::string &tok) {
    MemP m;
    size_t a = tok.find('[');
    size_t b = tok.find(']');
    if (a == std::string::npos || b == std::string::npos || b < a) return m;
    std::string inner = tok.substr(a + 1, b - a - 1);
    std::string after = tok.substr(b + 1);
    m.pre = after.find('!') != std::string::npos;
    m.post = false;
    size_t pc = after.find("#");
    if (pc != std::string::npos && !m.pre) {
        m.post = true;
        m.imm = parseImm(after.substr(pc));
    }
    std::vector<std::string> parts;
    size_t p = 0;
    for (;;) {
        size_t c = inner.find(',', p);
        if (c == std::string::npos) { parts.push_back(trim(inner.substr(p))); break; }
        parts.push_back(trim(inner.substr(p, c - p)));
        p = c + 1;
    }
    if (parts.empty()) return m;
    m.base = parseReg(parts[0]);
    if (m.base < 0) return m;
    if (parts.size() == 1) { m.ok = true; return m; }
    if (parts.size() >= 2 && (parts[1][0] == '#' || parts[1][0] == '-')) { m.imm = parseImm(parts[1]); m.ok = true; return m; }
    m.idx = parseReg(parts[1]);
    if (m.idx >= 0 && parts.size() >= 3) {
        size_t sh = parts[2].find("LSL #");
        if (sh != std::string::npos) m.scale = 1 << atoi(parts[2].c_str() + sh + 5);
    }
    m.ok = true;
    return m;
}

std::string memText(const std::string &base, long long off) {
    if (off == 0) return base;
    if (off > 0) return "(" + base + " + " + constOfs(off) + ")";
    return "(" + base + " - " + constOfs(-off) + ")";
}

struct Opd {
    int reg;             // register number, -1 ZR, -2 not a reg
    bool isImm, ok;
    long long imm;
    std::string sh;      // ", LSL #3" style suffix
    Opd() : reg(-2), isImm(false), ok(false), imm(0) {}
};

Opd parseOpd(const std::string &t) {
    Opd o;
    if (!t.empty() && (t[0] == '#' || t[0] == '-')) {
        o.isImm = true;
        o.imm = parseImm(t);
        o.ok = true;
        return o;
    }
    o.reg = parseReg(t);
    if (o.reg != -2) o.ok = true;
    return o;
}

} // namespace

// ---------- pseudocode generator ----------

namespace pseudo_ns {

struct Var {
    std::string name, type, cmt;
    bool used;
    Var() : used(false) {}
};

struct RS {
    bool w, isArg, hasC, hasP;
    long long cv;
    unsigned long long pAddr;
    std::string pName, txt;
    int vn;
    RS() : w(false), isArg(false), hasC(false), hasP(false), cv(0), pAddr(0), vn(-1) {}
};

struct Blk {
    uint64_t lo, hi;
    int b, e, tIx, term;
    uint64_t tj;
    bool lh;
    Blk() : lo(0), hi(0), b(0), e(0), tIx(-1), term(0), tj(0), lh(false) {}
};

struct LoopC {
    uint64_t cont, brk;
    LoopC() : cont(0), brk(0) {}
};

struct PGen {
    const Database *db;
    uint64_t fs, fe;
    std::vector<Insn> ins;
    std::map<uint64_t, int> iMap;
    std::vector<Blk> blocks;
    std::map<uint64_t, int> bMap;
    std::set<uint64_t> litT;
    std::set<int> supp;
    std::set<uint64_t> needLabel;
    std::vector<LoopC> loops;
    std::set<int> claimed;
    std::vector<bool> reach;
    int depth;
    bool twEver[384], reNC[384], anyX[384];
    int regVn[384];
    bool written0, anyX0;
    int argRegs[8], nArgs;
    std::vector<Var> vars;
    RS rs[384];
    uint64_t spCur, frame;
    std::map<long long, int> slotIdx;
    std::string lastL, lastR;
    int inPro;

    PGen(const Database *d, uint64_t fa) : db(d), fs(fa), fe(0), written0(false), anyX0(false), nArgs(0), spCur(0), frame(0), inPro(0), fRet(0), depth(0) {
        for (int i = 0; i < 384; i++) { twEver[i] = false; reNC[i] = false; anyX[i] = false; regVn[i] = -1; assignEver[i] = false; }
        uint64_t st = 0, en = 0;
        db->funcContaining(fa, st, en);
        fs = st;
        fe = en;
    }

    void decode() {
        for (uint64_t a = fs; a + 4 <= fe; a += 4) {
            uint32_t w = 0;
            if (!db->readMem(a, &w, 4)) break;
            Insn n = a64_decode(a, w);
            if (n.mnem.empty()) continue;
            if (n.kind == K_LIT) { litT.insert(n.target); litT.insert(n.target + 4); }
            ins.push_back(n);
        }
        std::vector<Insn> v2;
        v2.reserve(ins.size());
        for (size_t i = 0; i < ins.size(); i++) if (!litT.count(ins[i].addr)) v2.push_back(ins[i]);
        ins.swap(v2);
        for (size_t i = 0; i < ins.size(); i++) iMap[ins[i].addr] = (int)i;
    }

    int blkOf(uint64_t a) {
        std::map<uint64_t, int>::iterator it = bMap.upper_bound(a);
        if (it == bMap.begin()) return -1;
        --it;
        return it->second;
    }

    void buildBlocks() {
        if (ins.empty()) return;
        std::set<uint64_t> st;
        st.insert(ins[0].addr);
        for (size_t i = 0; i + 1 < ins.size(); i++) {
            const Insn &n = ins[i];
            int k = n.kind;
            if (k == K_JUMP || k == K_CJUMP || k == K_RET || k == K_IJUMP) st.insert(ins[i + 1].addr);
            if ((k == K_JUMP || k == K_CJUMP) && n.hasTarget && n.target > fs && n.target < fe) st.insert(n.target);
        }
        std::vector<uint64_t> sa;
        for (std::set<uint64_t>::iterator it = st.begin(); it != st.end(); ++it) {
            std::map<uint64_t, int>::iterator m = iMap.lower_bound(*it);
            if (m != iMap.end()) sa.push_back(m->first);
        }
        sa.erase(std::unique(sa.begin(), sa.end()), sa.end());
        for (size_t i = 0; i < sa.size(); i++) {
            Blk bl;
            bl.lo = sa[i];
            bl.hi = (i + 1 < sa.size()) ? sa[i + 1] : fe;
            bl.b = iMap[bl.lo];
            bl.e = (i + 1 < sa.size()) ? iMap[sa[i + 1]] : (int)ins.size();
            bl.tIx = bl.e - 1;
            bl.term = ins[bl.tIx].kind;
            bl.tj = ins[bl.tIx].hasTarget ? ins[bl.tIx].target : 0;
            blocks.push_back(bl);
            bMap[bl.lo] = (int)i;
        }
        for (size_t i = 0; i < blocks.size(); i++) {
            const Insn &n = ins[blocks[i].tIx];
            if ((n.kind == K_JUMP || n.kind == K_CJUMP) && n.hasTarget && n.target < blocks[i].lo && n.target > fs) {
                int t = blkOf(n.target);
                if (t >= 0) blocks[t].lh = true;
            }
        }
    }

    bool csReg(int r) {
        return r == 29 || r == 30 || (r >= 19 && r <= 28) || (r >= 128 + 8 && r <= 128 + 15);
    }

    bool isPrologue(const Insn &n) {
        const std::string &m = n.mnem;
        if (m == "NOP" || m == "YIELD" || m == "WFE" || m == "WFI" || m == "SEV" || m == "SEVL" ||
            m == "BTI" || m == "PACIASP" || m == "PACIBSP" || m == "AUTIASP" || m == "AUTIBSP" ||
            m == "DSB" || m == "DMB" || m == "ISB" || m == "CLREX") return true;
        std::vector<std::string> t = opsSplit(n.ops);
        if (m == "MOV" && t.size() == 2 && ((t[0] == "X29" && t[1] == "SP") || (t[0] == "SP" && t[1] == "X29"))) return true;
        if ((m == "SUB" || m == "ADD") && t.size() == 3 && t[0] == "SP" && t[1] == "SP" && t[2][0] == '#') return true;
        if ((m == "STP" || m == "LDP" || m == "STNP" || m == "LDNP") && t.size() >= 3) {
            if (!csReg(parseReg(t[0])) && !csReg(parseReg(t[1]))) return false;
            MemP mp = parseMem(t[2]);
            return mp.ok && mp.base == 31;
        }
        if ((m == "STR" || m == "LDR" || m == "STUR" || m == "LDUR") && t.size() >= 2) {
            if (!csReg(parseReg(t[0]))) return false;
            MemP mp = parseMem(t[1]);
            return mp.ok && mp.base == 31;
        }
        return false;
    }

    void updSP(const Insn &n, uint64_t &sp) {
        const std::string &m = n.mnem;
        std::vector<std::string> t = opsSplit(n.ops);
        if ((m == "SUB" || m == "ADD") && t.size() == 3 && t[0] == "SP" && t[1] == "SP" && t[2][0] == '#') {
            long long v = parseImm(t[2]);
            sp = (m == "SUB") ? sp - v : sp + v;
            return;
        }
        if (m == "STP" || m == "LDP" || m == "STNP" || m == "LDNP" || m == "STR" || m == "LDR" || m == "STUR" || m == "LDUR") {
            size_t mi = (m == "STP" || m == "LDP" || m == "STNP" || m == "LDNP") ? 2 : 1;
            if (t.size() <= mi) return;
            MemP mp = parseMem(t[mi]);
            if (!mp.ok || mp.base != 31) return;
            if (mp.pre) sp += mp.imm;
            else if (mp.post) sp += mp.imm;
        }
    }

    static int dstCount(const std::string &m) {
        if (m == "LDP" || m == "LDNP" || m == "LDPSW") return 2;
        static const char *w1[] = {
            "MOV","MOVK","MVN","NEG","NEGS","NGC","NGCS","SBC","SBCS","ADC","ADCS",
            "ADD","ADDS","SUB","SUBS","AND","ANDS","ORR","ORN","EOR","EON","BIC","BICS",
            "LSL","LSR","ASR","ROR","UXTB","UXTH","UXTW","SXTB","SXTH","SXTW",
            "UBFX","SBFX","UBFIZ","SBFIZ","BFI","BFC","BFXIL","EXTR",
            "MUL","MADD","MSUB","SMULL","UMULL","SDIV","UDIV",
            "CSET","CSETM","CINC","CINV","CNEG","CSEL","CSINC","CSINV","CSNEG",
            "MRS","ADRP","ADR","CLZ","CLS","RBIT","REV","REV16","REV32",
            "LDR","LDRB","LDRH","LDRSB","LDRSH","LDRSW",
            "LDUR","LDURB","LDURH","LDURSB","LDURSH","LDURSW",
            "LDXR","LDAXR","LDLAR","STXR","STLXR","STLLR",
            "FMOV","FADD","FSUB","FMUL","FDIV","FCVT","FCVTZS","FCVTZU","FCVTL","FCVTN",
            "SCVTF","UCVTF","FABS","FNEG","FSQRT","FMAX","FMIN","FSEL", NULL };
        for (int i = 0; w1[i]; i++) if (m == w1[i]) return 1;
        return 0;
    }

    void pass1() {
        bool tw[384], re[384], argMark[384];
        for (int i = 0; i < 384; i++) { tw[i] = false; re[i] = false; argMark[i] = false; }
        written0 = false; anyX0 = false; nArgs = 0;
        uint64_t sp = 0;
        inPro = 0;
        while (inPro < (int)ins.size() && isPrologue(ins[inPro])) {
            supp.insert(inPro);
            updSP(ins[inPro], sp);
            inPro++;
        }
        frame = sp;
        for (int i = inPro; i < (int)ins.size(); i++) {
            const Insn &n = ins[i];
            std::vector<std::string> t = opsSplit(n.ops);
            bool callLike = (n.kind == K_CALL || n.kind == K_ICALL) ||
                            (n.kind == K_JUMP && n.hasTarget && (n.target < fs || n.target >= fe));
            if (callLike) {
                for (int r = 0; r < 8; r++)
                    if (!tw[r] && !argMark[r]) { argMark[r] = true; argRegs[nArgs++] = r; re[r] = true; }
                if (n.kind == K_ICALL && !t.empty()) {
                    int tr = parseReg(t[0]);
                    if (tr >= 0) re[tr] = true;
                }
                if (n.kind == K_CALL || n.kind == K_ICALL) {
                    if (!tw[0]) {
                        tw[0] = true;
                        regVn[0] = (int)vars.size();
                        Var v; v.name = "v" + std::to_string(vars.size() + 1);
                        v.cmt = "// x0";
                        vars.push_back(v);
                    }
                    tw[30] = true;
                }
                continue;
            }
            size_t nd = (size_t)dstCount(n.mnem);
            for (size_t k = nd; k < t.size(); k++) {
                int r = parseReg(t[k]);
                if (r >= 0) {
                    re[r] = true;
                    reNC[r] = true;
                    if (r < 8 && !tw[r] && !argMark[r]) { argMark[r] = true; argRegs[nArgs++] = r; }
                }
            }
            for (size_t k = 0; k < nd && k < t.size(); k++) {
                int r = parseReg(t[k]);
                if (r >= 0) {
                    if (t[k][0] == 'X') anyX[r] = true;
                    if (!tw[r]) {
                        tw[r] = true;
                        twEver[r] = true;
                        if (r != 29 && r != 30 && r != 31) {
                            regVn[r] = (int)vars.size();
                            Var v; v.name = "v" + std::to_string(vars.size() + 1);
                            v.cmt = "// " + ::rawRegTxt(r, anyX);
                            vars.push_back(v);
                        }
                    }
                }
            }
        }
        std::sort(argRegs, argRegs + nArgs);
        written0 = tw[0];
        anyX0 = anyX[0];
        // variable types and comments
        for (int r = 0; r < 384; r++) {
            if (regVn[r] < 0) continue;
            Var &v = vars[regVn[r]];
            if (isFloatReg(r)) { v.type = ftype(r); v.cmt = std::string("// ") + ::rawRegTxt(r, anyX); }
            else { v.type = anyX[r] ? "__int64" : "int"; v.cmt = std::string("// ") + (anyX[r] ? "x" : "w") + std::to_string(r); }
        }
        for (int i = inPro; i < (int)ins.size(); i++) {
            if (ins[i].kind != K_RET) continue;
            int j = i - 1;
            while (j >= inPro) {
                const Insn &m = ins[j];
                std::vector<std::string> t = opsSplit(m.ops);
                bool ok = false;
                if ((m.mnem == "LDP" || m.mnem == "LDNP") && t.size() >= 3 && (csReg(parseReg(t[0])) || csReg(parseReg(t[1])))) {
                    MemP mp = parseMem(t[2]);
                    ok = mp.ok && mp.base == 31;
                } else if ((m.mnem == "STR" || m.mnem == "STUR") && t.size() >= 2 && csReg(parseReg(t[0]))) {
                    MemP mp = parseMem(t[1]);
                    ok = mp.ok && mp.base == 31;
                } else if ((m.mnem == "ADD" || m.mnem == "SUB") && t.size() == 3 && t[0] == "SP" && t[1] == "SP") {
                    ok = true;
                } else if (m.mnem == "MOV" && t.size() == 2 && t[0] == "SP" && t[1] == "X29") {
                    ok = true;
                } else if (m.mnem == "NOP" || m.mnem == "PACIASP" || m.mnem == "AUTIASP" || m.mnem == "BTI") {
                    ok = true;
                }
                if (!ok) break;
                supp.insert(j);
                j--;
            }
        }
    }

    // --- extended state ---
    bool assignEver[384];
    int fRet;
    std::vector<std::string> records;

    // --- text helpers ---
    std::string pad(int n) { return std::string(n, ' '); }

    std::string rawRegTxt(int r) { return ::rawRegTxt(r, anyX); }

    void markUsed(int vn) {
        if (vn >= 0 && vn < (int)vars.size()) vars[vn].used = true;
    }

    std::string varName(int r) {
        if (r < 0 || r == 29 || r == 30 || r == 31) return rawRegTxt(r);
        RS &s = rs[r];
        if (s.vn < 0) {
            Var v;
            v.name = "v" + std::to_string(vars.size() + 1);
            v.type = isFloatReg(r) ? ftype(r) : (anyX[r] ? "__int64" : "int");
            v.cmt = "// " + rawRegTxt(r);
            vars.push_back(v);
            s.vn = (int)vars.size() - 1;
        }
        return vars[s.vn].name;
    }

    void setReg(int r) {
        if (r < 0 || r == 29 || r == 30 || r == 31) return;
        RS &s = rs[r];
        s.w = true;
        s.hasC = false;
        s.hasP = false;
        assignEver[r] = true;
        s.txt = varName(r);
        markUsed(s.vn);
    }

    int slotVar(long long key, const char *ty) {
        std::map<long long, int>::iterator it = slotIdx.find(key);
        if (it != slotIdx.end()) return it->second;
        Var v;
        v.name = "v" + std::to_string(vars.size() + 1);
        v.type = ty;
        char cb[40];
        if (key >= 0) snprintf(cb, 40, "// [sp+%llXh]", (unsigned long long)key);
        else snprintf(cb, 40, "// [sp-%llXh]", (unsigned long long)(-key));
        v.cmt = cb;
        v.used = true;
        vars.push_back(v);
        int id = (int)vars.size() - 1;
        slotIdx[key] = id;
        return id;
    }

    std::string regText(int r) {
        if (r < 0) return "0";
        if (r == 29 || r == 30 || r == 31) return rawRegTxt(r);
        RS &s = rs[r];
        if (s.hasC) return constOfs(s.cv);
        if (s.hasP) return "(__int64)&" + s.pName;
        if (!s.txt.empty()) {
            markUsed(s.vn);
            return s.txt;
        }
        return rawRegTxt(r);
    }

    bool touched(int r) {
        if (r < 0) return false;
        RS &s = rs[r];
        if (s.w || s.hasC || s.hasP) return true;
        if (s.isArg && (r == 0 || twEver[r] || reNC[r])) return true;
        return false;
    }

    std::string buildArgs() {
        std::string r;
        for (int i = 0; i < 8; i++) {
            if (!touched(i)) break;
            if (!r.empty()) r += ", ";
            r += regText(i);
        }
        return r;
    }

    int ccIndex(const std::string &cc) {
        for (int i = 0; i < 16; i++) if (cc == CCN[i]) return i;
        return 14;
    }

    std::string callName(uint64_t a) {
        std::string n = db->nameAt(a);
        if (n.empty()) { char b[40]; snprintf(b, 40, "sub_%llX", (unsigned long long)a); n = b; }
        if (n.size() > 2 && n[0] == '0' && n[1] == 'x') {   // unnamed target: IDA-style sub_offset
            char b[40];
            snprintf(b, 40, "sub_%llX", (unsigned long long)a);
            n = b;
        }
        std::string d = cxxDemangle(n);
        return d.empty() ? n : d;
    }

    std::string ptrName(uint64_t a) {
        std::string n = db->nameAt(a);
        if (n.empty()) { char b[40]; snprintf(b, 40, "qword_%llX", (unsigned long long)a); n = b; }
        return n;
    }

    std::string opsResolved(const Insn &n) {
        std::string s = n.ops;
        size_t p;
        while ((p = s.find("\x02")) != std::string::npos)
            s.replace(p, 1, n.hasTarget ? callName(n.target) : "?");
        return s;
    }

    std::string asmLine(int ind, const Insn &n) {
        return pad(ind) + "__asm { " + n.mnem + (n.ops.size() ? " " + opsResolved(n) : "") + " };";
    }

    static bool isStoreMnemonic(const std::string &m) {
        return m == "STR" || m == "STRB" || m == "STRH" || m == "STUR" || m == "STURB" || m == "STURH" ||
               m == "STP" || m == "STNP" || m == "STXR" || m == "STLXR" || m == "STLLR" || m == "STLR";
    }

    static bool isLoadMnemonic(const std::string &m) {
        return m == "LDR" || m == "LDRB" || m == "LDRH" || m == "LDRSB" || m == "LDRSH" || m == "LDRSW" ||
               m == "LDUR" || m == "LDURB" || m == "LDURH" || m == "LDURSB" || m == "LDURSH" || m == "LDURSW" ||
               m == "LDP" || m == "LDNP" || m == "LDPSW" || m == "LDXR" || m == "LDAXR" || m == "LDLAR" || m == "LDAR";
    }

    // type glyph used for deref casts
    std::string glyph(const std::string &m, int r) {
        if (m == "LDRSB" || m == "LDURSB") return "char";
        if (m == "LDRSH" || m == "LDURSH") return "short";
        if (m == "LDRSW" || m == "LDURSW" || m == "LDPSW") return "int";
        if (m == "LDRB" || m == "LDURB" || m == "STRB" || m == "STURB") return "_BYTE";
        if (m == "LDRH" || m == "LDURH" || m == "STRH" || m == "STURH") return "_WORD";
        if (isFloatReg(r)) return ftype(r);
        if (r >= 0 && anyX[r]) return "_QWORD";
        return "_DWORD";
    }

    const char *slotTy(const std::string &m, int r) {
        if (m == "LDRB" || m == "LDURB" || m == "STRB" || m == "STURB" || m == "LDRSB" || m == "LDURSB") return "char";
        if (m == "LDRH" || m == "LDURH" || m == "STRH" || m == "STURH" || m == "LDRSH" || m == "LDURSH") return "__int16";
        if (m == "LDRSW" || m == "LDURSW" || m == "LDPSW") return "int";
        if (isFloatReg(r)) return ftype(r);
        if (r >= 0 && anyX[r]) return "__int64";
        return "int";
    }

    int slotWidth(const std::string &m, int r) {
        if (m == "LDRB" || m == "LDURB" || m == "STRB" || m == "STURB" || m == "LDRSB" || m == "LDURSB") return 1;
        if (m == "LDRH" || m == "LDURH" || m == "STRH" || m == "STURH" || m == "LDRSH" || m == "LDURSH") return 2;
        if (isFloatReg(r)) return r < 128 ? 4 : 8;
        return (r >= 0 && anyX[r]) ? 8 : 4;
    }

    std::string valOf(const std::string &tok) {
        Opd o = parseOpd(tok);
        if (o.isImm) return constOfs(o.imm);
        return regText(o.reg);
    }

    // wraps x with a shift suffix token like "LSL #3"
    std::string shTxt(const std::vector<std::string> &t, size_t ix, const std::string &x, int sr) {
        if (ix >= t.size()) return x;
        const std::string &s = t[ix];
        size_t p = s.find('#');
        if (p == std::string::npos) {
            Opd o = parseOpd(s.substr(0, s.find(' ')));
            if (o.reg >= 0) return "(" + x + " << " + regText(o.reg) + ")";
            return x;
        }
        long long n = parseImm(s.substr(p));
        if (startsWith(s, "LSL")) return "(" + x + " << " + constOfs(n) + ")";
        if (startsWith(s, "LSR") || startsWith(s, "ASR")) return "(" + x + " >> " + constOfs(n) + ")";
        if (startsWith(s, "ROR"))
            return std::string((sr >= 0 && anyX[sr]) ? "__ROR8__(" : "__ROR4__(") + x + ", " + constOfs(n) + ")";
        return x;
    }

    void emitAssign(int r, const std::string &expr, int ind, std::vector<std::string> &out) {
        if (r < 0 || r == 29 || r == 30 || r == 31) return;
        varName(r);
        out.push_back(pad(ind) + vars[rs[r].vn].name + " = " + expr + ";");
        setReg(r);
    }

    void condAfter(const std::string &expr) {
        lastL = expr;
        lastR = "0";
    }

    void setCond(const Insn &n, const std::vector<std::string> &t) {
        const std::string &m = n.mnem;
        if (t.empty()) { lastL = "1"; lastR = "0"; return; }
        Opd a = parseOpd(t[0]);
        std::string L = a.isImm ? constOfs(a.imm) : regText(a.reg);
        std::string R = "0";
        if (t.size() > 1) {
            Opd b = parseOpd(t[1]);
            R = b.isImm ? constOfs(b.imm) : regText(b.reg);
        }
        if (m == "CMN" || m == "CCMN") { lastL = "(" + L + " + " + R + ")"; lastR = "0"; }
        else if (m == "TST") { lastL = "(" + L + " & " + R + ")"; lastR = "0"; }
        else { lastL = L; lastR = R; }
    }

    // would the result register x0 be read (1), overwritten (2) or unused (0) after insn ii
    int x0Use(int ii) {
        for (int k = ii + 1; k < (int)ins.size() && k <= ii + 24; k++) {
            const Insn &m2 = ins[k];
            if (m2.kind == K_CALL || m2.kind == K_ICALL) return 2;
            std::vector<std::string> t2 = opsSplit(m2.ops);
            size_t nd2 = (size_t)dstCount(m2.mnem);
            for (size_t q = 0; q < nd2 && q < t2.size(); q++)
                if (parseReg(t2[q]) == 0) return 2;
            for (size_t q = nd2; q < t2.size(); q++)
                if (parseReg(t2[q]) == 0) return 1;
            if (m2.kind == K_RET || m2.kind == K_JUMP || m2.kind == K_CJUMP || m2.kind == K_IJUMP) return 0;
        }
        return 0;
    }

    void emitCall(int ii, const Insn &n, const std::vector<std::string> &t, int ind, std::vector<std::string> &out, bool indirect) {
        std::string nm;
        if (indirect) {
            if (!t.empty()) {
                Opd a = parseOpd(t[0]);
                if (a.reg >= 0) {
                    RS &s = rs[a.reg];
                    if (s.hasP) { nm = s.pName; }
                    else if (!s.txt.empty()) { nm = s.txt; markUsed(s.vn); }
                }
            }
            if (nm.empty()) { out.push_back(asmLine(ind, n)); rs[0] = RS(); rs[30] = RS(); return; }
        } else {
            nm = cxxDemangle(callName(n.target));
            if (nm.empty()) nm = callName(n.target);
        }
        std::string args = buildArgs();
        int use = x0Use(ii);
        if (use == 1) {
            varName(0);
            out.push_back(pad(ind) + vars[rs[0].vn].name + " = " + nm + "(" + args + ");");
            setReg(0);
        } else {
            out.push_back(pad(ind) + nm + "(" + args + ");");
            setReg(0);
        }
        rs[30] = RS();
    }

    void emitMem(const Insn &n, const std::vector<std::string> &t, const std::string &m, int ind, std::vector<std::string> &out) {
        bool st = isStoreMnemonic(m);
        bool pair = (m == "STP" || m == "STNP" || m == "LDP" || m == "LDNP" || m == "LDPSW");
        bool excl = (m == "STXR" || m == "STLXR" || m == "STLLR");
        size_t mi = (pair || excl) ? 2 : 1;
        if (t.size() <= mi) { out.push_back(asmLine(ind, n)); return; }
        MemP mp = parseMem(t[mi]);
        if (!mp.ok) { out.push_back(asmLine(ind, n)); return; }
        size_t v0 = excl ? 1 : 0;
        if (mp.isSP()) {
            long long slot;
            if (mp.pre) { slot = (long long)spCur + mp.imm; spCur += mp.imm; }
            else if (mp.post) { slot = (long long)spCur; spCur += mp.imm; }
            else slot = (long long)spCur + mp.imm;
            int nv = pair ? 2 : 1;
            for (int q = 0; q < nv; q++) {
                if (v0 + q >= t.size()) break;
                int r = parseReg(t[v0 + q]);
                if (r >= 19 && r <= 30) continue;
                const char *ty = slotTy(m, r);
                int id = slotVar(slot + (long long)(q * slotWidth(m, r)), ty);
                if (st) {
                    out.push_back(pad(ind) + vars[id].name + " = " + regText(r) + ";");
                    markUsed(rs[r].vn);
                } else {
                    if (r < 0 || r == 29 || r == 30 || r == 31) continue;
                    varName(r);
                    out.push_back(pad(ind) + vars[rs[r].vn].name + " = " + vars[id].name + ";");
                    setReg(r);
                }
            }
            if (excl) {
                int sr = parseReg(t[0]);
                if (sr >= 0) {
                    RS &s = rs[sr];
                    s.w = true; s.hasC = true; s.cv = 0; s.hasP = false; s.txt = "";
                }
            }
            return;
        }
        int br = mp.base;
        std::string bs;
        bool baseVar = false;
        if (mp.pre || mp.post) {
            if (br < 0 || br == 29 || br == 30 || br == 31) {
                bs = rawRegTxt(br);
            } else {
                varName(br);
                bs = vars[rs[br].vn].name;
                baseVar = true;
            }
        }
        else bs = regText(br);
        std::string addr;
        if (mp.idx >= 0) {
            std::string is = regText(mp.idx);
            int lg = 0;
            while ((1 << lg) < mp.scale) lg++;
            if (mp.scale == 1) addr = "(" + bs + " + " + is + ")";
            else if ((1 << lg) == mp.scale && mp.scale <= 8) addr = "(" + bs + " + (" + is + " << " + std::to_string(lg) + "))";
            else addr = "(" + bs + " + " + is + " * " + std::to_string(mp.scale) + ")";
        } else {
            addr = memText(bs, mp.imm);
        }
        int vr = st ? (int)parseReg(t[v0]) : (int)parseReg(t[0]);
        bool csv = (vr >= 19 && vr <= 30) && (mp.base == 29 || mp.base == 31);
        std::string g = glyph(m, vr);
        if (st) {
            if (!csv) {
                out.push_back(pad(ind) + "*(" + g + " *)(" + addr + ") = " + regText(vr) + ";");
                markUsed(rs[vr].vn);
            }
        } else {
            if (csv) {
                // callee-save restore from frame: suppressed
            } else if (vr < 0 || vr == 29 || vr == 30 || vr == 31) {
                if (vr >= 0)
                    out.push_back(pad(ind) + rawRegTxt(vr) + " = *(" + g + " *)(" + addr + ");");
            } else {
                varName(vr);
                out.push_back(pad(ind) + vars[rs[vr].vn].name + " = *(" + g + " *)(" + addr + ");");
                setReg(vr);
            }
        }
        if (excl) {
            int sr = parseReg(t[0]);
            if (sr >= 0) {
                RS &s = rs[sr];
                s.w = true; s.hasC = true; s.cv = 0; s.hasP = false; s.txt = "";
            }
        }
        if (mp.pre || mp.post) {
            if (baseVar)
                out.push_back(pad(ind) + vars[rs[br].vn].name + " += " + constOfs(mp.imm) + ";");
            else
                out.push_back(pad(ind) + rawRegTxt(br) + " += " + constOfs(mp.imm) + ";");
        }
    }

    void emitInsn(int ii, std::vector<std::string> &out, int ind) {
        const Insn &n = ins[ii];
        if (supp.count(ii)) { updSP(n, spCur); return; }
        updSP(n, spCur);
        const std::string &m = n.mnem;
        std::vector<std::string> t = opsSplit(n.ops);
        if (n.kind == K_JUMP || n.kind == K_CJUMP || n.kind == K_RET || n.kind == K_IJUMP) return;
        if (m == "CMP" || m == "CMN" || m == "TST" || m == "CCMP" || m == "CCMN" || m == "FCMP") { setCond(n, t); return; }
        if (m == "NOP" || m == "YIELD" || m == "WFE" || m == "WFI" || m == "SEV" || m == "SEVL" ||
            m == "BTI" || m == "PACIASP" || m == "PACIBSP" || m == "AUTIASP" || m == "AUTIBSP" ||
            m == "DSB" || m == "DMB" || m == "ISB" || m == "CLREX" || m == "PRFM" || m == "PRFUM") return;

        // literal pool load: LDR X0, =TG
        if (n.kind == K_LIT) {
            Opd a = parseOpd(t[0]);
            if (a.reg < 0) return;
            int sz = isFloatReg(a.reg) ? (a.reg < 128 ? 4 : 8) : (anyX[a.reg] ? 8 : 4);
            unsigned long long v = 0;
            db->readMem(n.target, &v, sz);
            std::string nm = db->nameAt(n.target);
            if (isFloatReg(a.reg)) {
                double d;
                if (sz == 4) { float f; memcpy(&f, &v, 4); d = f; }
                else memcpy(&d, &v, 8);
                char b[40];
                snprintf(b, 40, "%.17g", d);
                emitAssign(a.reg, b, ind, out);
                return;
            }
            if (!nm.empty() || (v & 0xFFFFFFFF00000000ULL)) {
                RS &s = rs[a.reg];
                varName(a.reg);
                s.w = true; s.hasP = true; s.pAddr = v;
                s.pName = nm.empty() ? ptrName(v) : nm;
                s.hasC = false; s.txt = "";
                out.push_back(pad(ind) + vars[s.vn].name + " = (__int64)&" + s.pName + ";");
                return;
            }
            RS &s = rs[a.reg];
            s.w = true; s.hasC = true; s.cv = (long long)v; s.hasP = false; s.txt = "";
            return;
        }

        // adrp page + add/ldr/str pair (decoder marked the resolving insn)
        if (n.kind == K_ADDR && n.hasTarget) {
            std::string nm = db->nameAt(n.target);
            if (nm.empty()) nm = ptrName(n.target);
            if (m == "ADD") {
                Opd a = parseOpd(t[0]);
                if (a.reg < 0) return;
                RS &s = rs[a.reg];
                varName(a.reg);
                s.w = true; s.hasP = true; s.pAddr = n.target; s.pName = nm;
                s.hasC = false; s.txt = "";
                out.push_back(pad(ind) + vars[s.vn].name + " = (__int64)&" + nm + ";");
                return;
            }
            bool st = isStoreMnemonic(m);
            int vr = parseReg(t[0]);
            std::string g = glyph(m, vr);
            if (st) {
                out.push_back(pad(ind) + "*(" + g + " *)&" + nm + " = " + regText(vr) + ";");
                markUsed(rs[vr].vn);
            } else {
                if (vr < 0) return;
                RS &s = rs[vr];
                varName(vr);
                s.w = true; s.hasC = false; s.hasP = false; s.txt = vars[s.vn].name;
                out.push_back(pad(ind) + vars[s.vn].name + " = *(" + g + " *)&" + nm + ";");
            }
            return;
        }

        // calls
        if (n.kind == K_CALL) { emitCall(ii, n, t, ind, out, false); return; }
        if (n.kind == K_ICALL) { emitCall(ii, n, t, ind, out, true); return; }

        // address formation
        if (m == "ADRP" || m == "ADR") {
            Opd a = parseOpd(t[0]);
            if (a.reg < 0) return;
            RS &s = rs[a.reg];
            varName(a.reg);
            s.w = true; s.hasP = true; s.pAddr = n.target;
            s.pName = db->nameAt(n.target);
            if (s.pName.empty()) s.pName = ptrName(n.target);
            s.hasC = false; s.txt = "";
            return;
        }

        if (m == "MOV") {
            if (t.size() < 2) { out.push_back(asmLine(ind, n)); return; }
            Opd a = parseOpd(t[0]);
            Opd b = parseOpd(t[1]);
            if (a.reg < 0 || a.reg == 29 || a.reg == 31) return;
            if (b.isImm) {
                RS &s = rs[a.reg];
                s.w = true; s.hasC = true; s.cv = b.imm; s.hasP = false; s.txt = "";
                return;
            }
            if (b.reg == -1) {
                RS &s = rs[a.reg];
                s.w = true; s.hasC = true; s.cv = 0; s.hasP = false; s.txt = "";
                return;
            }
            if (b.reg >= 0) {
                RS &sd = rs[b.reg];
                bool wide = anyX[b.reg];
                if (isFloatReg(a.reg)) { rs[a.reg] = sd; rs[a.reg].w = true; return; }
                if (wide && !anyX[a.reg]) {
                    std::string src = regText(b.reg);
                    emitAssign(a.reg, "(unsigned int)" + src, ind, out);
                    return;
                }
                if (!wide && anyX[a.reg]) {
                    std::string src = regText(b.reg);
                    emitAssign(a.reg, "(unsigned int)" + src, ind, out);
                    return;
                }
                rs[a.reg] = sd;
                rs[a.reg].w = true;
                return;
            }
            out.push_back(asmLine(ind, n));
            return;
        }

        if (m == "MOVK") {
            Opd a = parseOpd(t[0]);
            Opd b = parseOpd(t[1]);
            if (a.reg < 0) return;
            long long sh = 0;
            if (t.size() > 2) {
                size_t p = t[2].find("LSL #");
                if (p != std::string::npos) sh = atoll(t[2].c_str() + p + 5);
            }
            if (rs[a.reg].hasC) {
                rs[a.reg].cv |= (long long)(unsigned long long)(b.imm & 0xFFFF) << sh;
                if (!anyX[a.reg]) rs[a.reg].cv &= 0xFFFFFFFFLL;
                rs[a.reg].w = true;
                return;
            }
            if (a.reg >= 0 && !rs[a.reg].txt.empty()) {
                unsigned long long maskN = ~((0xFFFFULL << sh) & (anyX[a.reg] ? ~0ULL : 0xFFFFFFFFULL));
                char mb[40];
                snprintf(mb, 40, "0x%llXULL", maskN);
                std::string expr = "(" + vars[rs[a.reg].vn].name + " & " + mb + ") | " + constOfs(b.imm << sh);
                emitAssign(a.reg, expr, ind, out);
                return;
            }
            out.push_back(asmLine(ind, n));
            return;
        }

        if (m == "MVN") {
            Opd a = parseOpd(t[0]);
            Opd b = parseOpd(t[1]);
            if (a.reg < 0 || b.reg < 0) { out.push_back(asmLine(ind, n)); return; }
            std::string x = regText(b.reg);
            if (t.size() > 2) x = shTxt(t, 2, x, b.reg);
            emitAssign(a.reg, "~(" + x + ")", ind, out);
            return;
        }

        if (m == "MRS") {
            Opd a = parseOpd(t[0]);
            if (a.reg < 0 || t.size() < 2) { out.push_back(asmLine(ind, n)); return; }
            emitAssign(a.reg, std::string("_ReadStatusReg( ") + t[1] + " )", ind, out);
            return;
        }

        if (m == "MSR") {
            if (t.size() < 2) { out.push_back(asmLine(ind, n)); return; }
            int r = parseReg(t[1]);
            out.push_back(pad(ind) + " _WriteStatusReg( " + t[0] + ", " + (r >= 0 ? regText(r) : valOf(t[1])) + " );");
            return;
        }

        if (isLoadMnemonic(m) || isStoreMnemonic(m)) { emitMem(n, t, m, ind, out); return; }

        // ---- arithmetic / logic ----
        if (t.size() >= 2) {
            Opd a = parseOpd(t[0]);
            if (a.reg < 0 || a.reg == 29 || a.reg == 31) return;
            Opd b = t.size() > 1 ? parseOpd(t[1]) : Opd();
            Opd c = t.size() > 2 ? parseOpd(t[2]) : Opd();
            bool setF = (m == "ADDS" || m == "SUBS" || m == "ANDS" || m == "BICS");

            // const folding: dst == src1 and const state and imm operand, no shift
            if ((m == "ADD" || m == "ADDS" || m == "SUB" || m == "SUBS" || m == "AND" || m == "ANDS" ||
                 m == "ORR" || m == "EOR" || m == "BIC" || m == "BICS" || m == "ORN" || m == "EON") &&
                b.reg == a.reg && rs[a.reg].hasC && c.isImm && t.size() <= 3) {
                long long d = c.imm;
                bool ok = true;
                if (m == "ADD" || m == "ADDS") rs[a.reg].cv += d;
                else if (m == "SUB" || m == "SUBS") rs[a.reg].cv -= d;
                else if (m == "AND" || m == "ANDS") rs[a.reg].cv &= d;
                else if (m == "ORR") rs[a.reg].cv |= d;
                else if (m == "EOR") rs[a.reg].cv ^= d;
                else if (m == "BIC" || m == "BICS") rs[a.reg].cv &= ~d;
                else if (m == "ORN") rs[a.reg].cv |= ~d;
                else if (m == "EON") rs[a.reg].cv ^= ~d;
                else ok = false;
                if (ok) {
                    rs[a.reg].w = true;
                    if (setF) condAfter(constOfs(rs[a.reg].cv));
                    return;
                }
            }

            // adrp page + plain add (pair mark lost): rebase the pointer
            if (m == "ADD" && b.reg == a.reg && rs[a.reg].hasP && c.isImm && c.imm >= 0 && c.imm < 4096 && t.size() <= 3) {
                RS &s = rs[a.reg];
                s.pAddr += (unsigned long long)c.imm;
                std::string nm = db->nameAt(s.pAddr);
                if (nm.empty()) nm = ptrName(s.pAddr);
                s.pName = nm;
                varName(a.reg);
                out.push_back(pad(ind) + vars[s.vn].name + " = (__int64)&" + nm + ";");
                return;
            }

            if (m == "ADD" || m == "ADDS" || m == "SUB" || m == "SUBS" || m == "AND" || m == "ANDS" ||
                m == "ORR" || m == "EOR" || m == "BIC" || m == "BICS" || m == "ORN" || m == "EON" ||
                m == "MUL" || m == "SDIV" || m == "UDIV") {
                std::string L = b.isImm ? constOfs(b.imm) : regText(b.reg);
                std::string R = c.isImm ? constOfs(c.imm) : regText(c.reg);
                if (t.size() > 3) R = shTxt(t, 3, R, c.reg);
                std::string op = " + ";
                if (m == "SUB" || m == "SUBS") op = " - ";
                else if (m == "AND" || m == "ANDS") op = " & ";
                else if (m == "ORR") op = " | ";
                else if (m == "EOR") op = " ^ ";
                else if (m == "BIC" || m == "BICS") op = " & ~(";
                else if (m == "ORN") op = " | ~(";
                else if (m == "EON") op = " ^ ~(";
                else if (m == "MUL") op = " * ";
                else if (m == "SDIV" || m == "UDIV") op = " / ";
                std::string expr = "(" + L + op + R + ((op == " & ~(" || op == " | ~(" || op == " ^ ~(") ? ")" : "") + ")";
                if (m == "UDIV") {
                    std::string u = anyX[a.reg] ? "(unsigned __int64)" : "(unsigned int)";
                    expr = "(" + u + L + " / " + u + R + ")";
                }
                if ((m == "ADD" || m == "ADDS") && L == "0") expr = "(" + R + ")";
                else if ((m == "ADD" || m == "ADDS" || m == "SUB" || m == "SUBS") && R == "0") expr = "(" + L + ")";
                emitAssign(a.reg, expr, ind, out);
                if (setF) {
                    std::string e2 = "(" + L + ((m == "ADD" || m == "ADDS") ? " + " : (m == "SUB" || m == "SUBS") ? " - " : " & ") + R + ")";
                    condAfter(e2);
                }
                return;
            }

            if (m == "MADD" || m == "MSUB") {
                if (t.size() < 4) { out.push_back(asmLine(ind, n)); return; }
                std::string L1 = regText(parseReg(t[1])), L2 = regText(parseReg(t[2])), L3 = regText(parseReg(t[3]));
                std::string expr = "(" + L1 + " * " + L2 + ((m == "MADD") ? " + " : " - ") + L3 + ")";
                emitAssign(a.reg, expr, ind, out);
                return;
            }

            if (m == "SMULL") {
                std::string L = regText(parseReg(t[1])), R = regText(parseReg(t[2]));
                emitAssign(a.reg, "(__int64)" + L + " * " + R, ind, out);
                return;
            }
            if (m == "UMULL") {
                std::string L = regText(parseReg(t[1])), R = regText(parseReg(t[2]));
                emitAssign(a.reg, "(__int64)(unsigned int)" + L + " * (unsigned int)" + R, ind, out);
                return;
            }

            if (m == "LSL" || m == "LSR" || m == "ASR" || m == "ROR") {
                std::string L = regText(b.reg), R = c.isImm ? constOfs(c.imm) : regText(c.reg);
                std::string expr;
                if (m == "LSL") expr = "(" + L + " << " + R + ")";
                else if (m == "LSR" || m == "ASR") expr = "(" + L + " >> " + R + ")";
                else expr = std::string(anyX[a.reg] ? "__ROR8__(" : "__ROR4__(") + L + ", " + R + ")";
                emitAssign(a.reg, expr, ind, out);
                return;
            }

            if (m == "UXTB" || m == "UXTH" || m == "UXTW" || m == "SXTB" || m == "SXTH" || m == "SXTW") {
                const char *cy = m == "UXTB" ? "(unsigned __int8)" : m == "UXTH" ? "(unsigned __int16)" :
                                 m == "UXTW" ? "(unsigned int)" : m == "SXTB" ? "(signed __int8)" :
                                 m == "SXTH" ? "(signed __int16)" : "(signed int)";
                emitAssign(a.reg, std::string(cy) + regText(b.reg), ind, out);
                return;
            }

            if (m == "UBFX" || m == "SBFX") {
                if (t.size() < 4) { out.push_back(asmLine(ind, n)); return; }
                long long lsb = parseImm(t[2]), w = parseImm(t[3]);
                std::string L = regText(b.reg);
                std::string expr = "((" + L + " >> " + constOfs(lsb) + ") & " + constOfs((1LL << w) - 1) + ")";
                emitAssign(a.reg, expr, ind, out);
                return;
            }

            if (m == "NEG") {
                std::string L = regText(b.reg);
                emitAssign(a.reg, "-(" + L + ")", ind, out);
                if (m == "NEGS") condAfter("-(" + L + ")");
                return;
            }

            if (m == "CSET" || m == "CSETM") {
                Cond cnd;
                cnd.kind = 0;
                cnd.ci = (t.size() > 1) ? ccIndex(t[1]) : 14;
                if (lastL.empty()) { cnd.kind = 0; cnd.ci = 14; }
                else { cnd.l = lastL; cnd.r = lastR; }
                std::string e = cnd.text();
                if (m == "CSETM") e = "-(" + e + ")";
                emitAssign(a.reg, e, ind, out);
                return;
            }

            if (m == "CSEL" || m == "CSINC" || m == "CSINV" || m == "CSNEG" || m == "FCSEL" || m == "CINC" || m == "CINV" || m == "CNEG") {
                Cond cnd;
                cnd.kind = 0;
                size_t cxi = (m == "CINC" || m == "CINV" || m == "CNEG") ? 2 : 3;
                cnd.ci = (t.size() > cxi) ? ccIndex(t[cxi]) : 14;
                if (lastL.empty()) cnd.ci = 14;
                else { cnd.l = lastL; cnd.r = lastR; }
                std::string L = regText(parseReg(t[1]));
                std::string R = (m == "CINC" || m == "CINV" || m == "CNEG") ? L : regText(parseReg(t[2]));
                std::string e;
                if (m == "CSEL" || m == "FCSEL") e = cnd.text() + " ? " + L + " : " + R;
                else if (m == "CSINC") e = cnd.text() + " ? " + L + " : (" + R + " + 1)";
                else if (m == "CSINV") e = cnd.text() + " ? " + L + " : ~(" + R + ")";
                else if (m == "CSNEG") e = cnd.text() + " ? " + L + " : -(" + R + ")";
                else if (m == "CINC") e = cnd.text() + " ? (" + L + " + 1) : " + L;
                else if (m == "CINV") e = cnd.text() + " ? ~(" + L + ") : " + L;
                else e = cnd.text() + " ? -(" + L + ") : " + L;
                emitAssign(a.reg, e, ind, out);
                return;
            }

            // float arithmetic
            if (m == "FMOV") {
                if (b.isImm) {
                    RS &s = rs[a.reg];
                    s.w = true; s.hasC = true; s.cv = b.imm; s.hasP = false; s.txt = "";
                    return;
                }
                if (b.reg >= 0) { rs[a.reg] = rs[b.reg]; rs[a.reg].w = true; return; }
                out.push_back(asmLine(ind, n));
                return;
            }
            if (m == "FADD" || m == "FSUB" || m == "FMUL" || m == "FDIV" || m == "FCVT" ||
                m == "FCVTZS" || m == "FCVTZU" || m == "SCVTF" || m == "UCVTF") {
                std::string L = regText(b.reg);
                std::string expr;
                if (m == "FADD") expr = "(" + L + " + " + (c.isImm ? constOfs(c.imm) : regText(c.reg)) + ")";
                else if (m == "FSUB") expr = "(" + L + " - " + (c.isImm ? constOfs(c.imm) : regText(c.reg)) + ")";
                else if (m == "FMUL") expr = "(" + L + " * " + (c.isImm ? constOfs(c.imm) : regText(c.reg)) + ")";
                else if (m == "FDIV") expr = "(" + L + " / " + (c.isImm ? constOfs(c.imm) : regText(c.reg)) + ")";
                else if (m == "FCVT") expr = "(" + std::string(ftype(a.reg)) + ")" + L;
                else if (m == "FCVTZS") expr = "(" + std::string(anyX[a.reg] ? "__int64" : "int") + ")" + L;
                else if (m == "FCVTZU") expr = "(" + std::string(anyX[a.reg] ? "unsigned __int64" : "unsigned int") + ")" + L;
                else expr = "(" + std::string(ftype(a.reg)) + ")" + L;
                emitAssign(a.reg, expr, ind, out);
                return;
            }
        }

        out.push_back(asmLine(ind, n));
    }

    void emitInsns(int b, int e, int ind, std::vector<std::string> &out) {
        for (int k = b; k < e; k++) emitInsn(k, out, ind);
    }

    // --- return text ---
    std::string retTxt() {
        if (!written0) return "";
        return " " + regText(0);
    }

    // build the branch condition of a conditional-jump terminator
    Cond cndOf(const Blk &bl) {
        const Insn &n = ins[bl.tIx];
        std::vector<std::string> t = opsSplit(n.ops);
        Cond cnd;
        if (n.mnem.size() > 2 && n.mnem[0] == 'B' && n.mnem[1] == '.') {
            cnd.kind = 0;
            cnd.ci = ccIndex(n.mnem.c_str() + 2);
            if (lastL.empty()) { cnd.ci = 14; return cnd; }
            cnd.l = lastL;
            cnd.r = lastR;
            return cnd;
        }
        if (n.mnem == "CBZ" || n.mnem == "CBNZ") {
            cnd.kind = 1;
            cnd.v = t.empty() ? "0" : regText(parseReg(t[0]));
            cnd.nz = (n.mnem == "CBNZ");
            return cnd;
        }
        if (n.mnem == "TBZ" || n.mnem == "TBNZ") {
            cnd.kind = 2;
            cnd.v = t.empty() ? "0" : regText(parseReg(t[0]));
            cnd.bv = t.size() > 1 ? parseImm(t[1]) : 0;
            cnd.nz = (n.mnem == "TBNZ");
            return cnd;
        }
        cnd.kind = 0;
        cnd.ci = 14;
        return cnd;
    }

    // snapshot / diff const-pointer states so path-merged state is not carried on
    void snapC(bool *hc, bool *hp, long long *cv, unsigned long long *pa) {
        for (int r = 0; r < 384; r++) {
            hc[r] = rs[r].hasC; hp[r] = rs[r].hasP;
            cv[r] = rs[r].cv; pa[r] = rs[r].pAddr;
        }
    }

    void unsnapC(const bool *hc, const bool *hp, const long long *cv, const unsigned long long *pa) {
        for (int r = 0; r < 384; r++) {
            if (rs[r].hasC != hc[r] || (rs[r].hasC && rs[r].cv != cv[r]) ||
                rs[r].hasP != hp[r] || (rs[r].hasP && rs[r].pAddr != pa[r])) {
                rs[r].hasC = false;
                rs[r].hasP = false;
            }
        }
    }

    // forward-only closure over block indices (merge detection)
    void closure(int k, int limit, std::set<int> &out) {
        std::vector<int> st;
        st.push_back(k);
        while (!st.empty()) {
            int c = st.back();
            st.pop_back();
            if (c < 0 || c >= limit || (int)blocks.size() <= c || out.count(c)) continue;
            if ((int)out.size() > 256) return;
            out.insert(c);
            const Blk &bl = blocks[c];
            int nx = c + 1;
            if (bl.term == K_JUMP) {
                if (bl.tj >= fs && bl.tj < fe) {
                    int t = blkOf(bl.tj);
                    if (t > c) st.push_back(t);
                }
                continue;
            }
            if (bl.term == K_CJUMP) {
                if (bl.tj >= fs && bl.tj < fe) {
                    int t = blkOf(bl.tj);
                    if (t > c) st.push_back(t);
                }
                st.push_back(nx);
                continue;
            }
            if (bl.term == K_RET || bl.term == K_IJUMP) continue;
            st.push_back(nx);
        }
    }

    // minimal forward convergence block of two paths; -1 when none
    int mergeOf(int a, int b) {
        if (a > b) { int t = a; a = b; b = t; }
        int limit = (int)blocks.size();
        if (!loops.empty() && loops.back().brk) {
            for (int i = 0; i < limit; i++)
                if (blocks[i].lo >= loops.back().brk) { limit = i; break; }
        }
        std::set<int> A, B;
        closure(a, limit, A);
        closure(b, limit, B);
        for (std::set<int>::iterator it = A.begin(); it != A.end(); ++it)
            if (*it > a && B.count(*it)) return *it;
        return -1;
    }

    // indirect jump -> switch over a jump table
    void emitSwitch(int k, int ind, std::vector<std::string> &out) {
        const Blk &bl = blocks[k];
        int ldrIx = -1, cmpIx = -1, sw = -2, base = -2;
        long long bound = -1;
        for (int q = bl.tIx - 1; q >= bl.b && q > bl.tIx - 9; q--) {
            const Insn &m = ins[q];
            std::vector<std::string> t = opsSplit(m.ops);
            if (ldrIx < 0 && m.mnem == "LDR" && t.size() >= 2) {
                MemP mp = parseMem(t[1]);
                if (mp.ok && mp.idx >= 0 && mp.scale == 8) { ldrIx = q; sw = parseReg(t[0]); base = mp.base; }
            }
            if (cmpIx < 0 && m.mnem == "CMP" && t.size() == 3 && t[2][0] == '#') { cmpIx = q; bound = parseImm(t[2]); }
            if (ldrIx >= 0 && cmpIx >= 0) break;
        }
        if (ldrIx < 0 || cmpIx < 0 || bound < 0 || bound > 63 || sw < 0 ||
            base < 0 || !rs[base].hasP) {
            out.push_back(asmLine(ind, ins[bl.tIx]));
            return;
        }
        out.push_back(pad(ind) + "switch ( " + regText(sw) + " ) {");
        long long nc = bound + 1;
        for (long long c = 0; c < nc; c++) {
            unsigned long long tgt = 0;
            if (!db->readMem(rs[base].pAddr + 8ULL * (unsigned long long)c, &tgt, 8)) break;
            if (tgt < fs || tgt >= fe) break;
            int ti = blkOf(tgt);
            if (ti < 0) break;
            needLabel.insert(tgt);
            char b[96];
            snprintf(b, 96, "case %lld: goto LABEL_%llu;", c, (unsigned long long)((tgt - fs) / 4 + 1));
            out.push_back(pad(ind + 4) + b);
        }
        out.push_back(pad(ind) + "}");
    }

    // try to fold a forward conditional branch into if / if-else / && / ||
    bool tryFold(int ci, int ind, std::vector<std::string> &out, int &next) {
        const Blk &bl = blocks[ci];
        uint64_t tb = bl.tj;
        int tbi = blkOf(tb);
        if (tbi < 0) return false;

        // short-circuit chain: consecutive empty cjmp blocks sharing the same target
        int chainEnd = ci;
        while (chainEnd + 1 < (int)blocks.size() &&
               blocks[chainEnd + 1].term == K_CJUMP &&
               blocks[chainEnd + 1].tj == tb &&
               blocks[chainEnd + 1].b == blocks[chainEnd + 1].tIx)
            chainEnd++;

        bool hc[384]; bool hp[384];
        long long cv[384]; unsigned long long pa[384];

        // OR-form: chain followed by an unconditional jump (both targets converge)
        if (chainEnd > ci && chainEnd + 1 < (int)blocks.size() && blocks[chainEnd + 1].term == K_JUMP) {
            uint64_t oth = blocks[chainEnd + 1].tj;
            int oi = (oth >= fs && oth < fe) ? blkOf(oth) : -1;
            if (oi < 0) return false;
            std::string cond;
            for (int q = ci; q <= chainEnd; q++) {
                std::string ct = cndOf(blocks[q]).text();
                cond = q == ci ? ct : cond + " || " + ct;
            }
            int M = mergeOf(tbi, oi);
            if (M <= chainEnd + 1) return false;
            snapC(hc, hp, cv, pa);
            out.push_back(pad(ind) + "if ( " + cond + " ) {");
            if (M == oi) walk(tbi, oi, ind + 1, out, 0);
            else {
                walk(tbi, M, ind + 1, out, blocks[M].lo);
                std::vector<std::string> el;
                walk(oi, M, ind + 1, el, blocks[M].lo);
                if (!el.empty() && trim(el[0]).size() > 4 && startsWith(trim(el[0]), "if (")) {
                    out.push_back(pad(ind) + "} else " + trim(el[0]).substr(4));
                    for (size_t z = 1; z < el.size(); z++) out.push_back(el[z]);
                } else {
                    out.push_back(pad(ind) + "} else {");
                    for (size_t z = 0; z < el.size(); z++) out.push_back(el[z]);
                    out.push_back(pad(ind) + "}");
                }
            }
            unsnapC(hc, hp, cv, pa);
            next = M;
            return true;
        }

        // AND-form: chain falls through into the body
        int M = mergeOf(ci, tbi);
        if (M < 0) return false;
        std::string cond;
        for (int q = ci; q <= chainEnd; q++) {
            std::string ct = cndOf(blocks[q]).inv().text();
            cond = q == ci ? ct : cond + " && " + ct;
        }
        if (M == tbi) {
            snapC(hc, hp, cv, pa);
            out.push_back(pad(ind) + "if ( " + cond + " ) {");
            walk(chainEnd + 1, tbi, ind + 1, out, 0);
            out.push_back(pad(ind) + "}");
            unsnapC(hc, hp, cv, pa);
            next = tbi;
            return true;
        }
        if (M > tbi) {
            snapC(hc, hp, cv, pa);
            out.push_back(pad(ind) + "if ( " + cond + " ) {");
            walk(chainEnd + 1, tbi, ind + 1, out, blocks[M].lo);
            std::vector<std::string> el;
            walk(tbi, M, ind + 1, el, blocks[M].lo);
            if (!el.empty() && trim(el[0]).size() > 4 && startsWith(trim(el[0]), "if (")) {
                out.push_back(pad(ind) + "} else " + trim(el[0]).substr(4));
                for (size_t z = 1; z < el.size(); z++) out.push_back(el[z]);
            } else {
                out.push_back(pad(ind) + "} else {");
                for (size_t z = 0; z < el.size(); z++) out.push_back(el[z]);
                out.push_back(pad(ind) + "}");
            }
            unsnapC(hc, hp, cv, pa);
            next = M;
            return true;
        }
        return false;
    }

    // emit blocks [bi, ei); skipT suppresses any terminator branching exactly there
    void walk(int bi, int ei, int ind, std::vector<std::string> &out, uint64_t skipT) {
        if (bi < 0) bi = 0;
        if (depth > 64) return;
        depth++;
        for (int k = bi; k < ei && k < (int)blocks.size(); ) {
            if (k >= 0 && k < (int)reach.size() && !reach[k]) { k++; continue; }
            const Blk &bl = blocks[k];
            if (needLabel.count(bl.lo))
                out.push_back("LABEL_" + std::to_string((bl.lo - fs) / 4 + 1) + ":");
            if (bl.lh && claimed.count(k)) {
                emitInsns(bl.b, bl.tIx, ind, out);
                k++;
                continue;
            }
            if (bl.lh && !loops.empty() && bl.lo == loops.back().cont) {
                emitInsns(bl.b, bl.tIx, ind, out);
                k++;
                continue;
            }
            if (bl.lh) { k = tryLoop(k, ind, out); continue; }
            emitInsns(bl.b, bl.tIx, ind, out);
            if (bl.term == K_IJUMP) { emitSwitch(k, ind, out); k++; continue; }
            if (bl.term == K_RET) {
                out.push_back(pad(ind) + "return" + retTxt() + ";");
                k++;
                continue;
            }
            if (bl.term == K_JUMP) {
                if (skipT && bl.tj == skipT) { k++; continue; }
                if (k + 1 < (int)blocks.size() && bl.tj == blocks[k + 1].lo) { k++; continue; }
                if (!loops.empty()) {
                    if (bl.tj == loops.back().cont) { out.push_back(pad(ind) + "continue;"); k++; continue; }
                    if (loops.back().brk && bl.tj >= loops.back().brk && bl.tj < fe) {
                        out.push_back(pad(ind) + "break;");
                        k++;
                        continue;
                    }
                }
                if (bl.tj < fs) {
                    std::string tn = cxxDemangle(callName(bl.tj));
                    if (tn.empty()) tn = callName(bl.tj);
                    out.push_back(pad(ind) + "return " + tn + "(" + buildArgs() + ");");
                    k++;
                    continue;
                }
                if (bl.tj >= fe) {
                    if (!loops.empty() && loops.back().brk) out.push_back(pad(ind) + "break;");
                    k++;
                    continue;
                }
                needLabel.insert(bl.tj);
                out.push_back(pad(ind) + "goto LABEL_" + std::to_string((bl.tj - fs) / 4 + 1) + ";");
                k++;
                continue;
            }
            if (bl.term == K_CJUMP) {
                if (skipT && bl.tj == skipT) { k++; continue; }
                if (k + 1 < (int)blocks.size() && bl.tj == blocks[k + 1].lo) { k++; continue; }
                if (!loops.empty()) {
                    if (bl.tj == loops.back().cont) {
                        out.push_back(pad(ind) + "if ( " + cndOf(bl).text() + " ) continue;");
                        k++;
                        continue;
                    }
                    if (loops.back().brk && bl.tj >= loops.back().brk && bl.tj < fe) {
                        out.push_back(pad(ind) + "if ( " + cndOf(bl).text() + " ) break;");
                        k++;
                        continue;
                    }
                }
                if (bl.tj < fs) {
                    std::string tn = cxxDemangle(callName(bl.tj));
                    if (tn.empty()) tn = callName(bl.tj);
                    out.push_back(pad(ind) + "if ( " + cndOf(bl).text() + " ) return " +
                                  tn + "(" + buildArgs() + ");");
                    k++;
                    continue;
                }
                if (bl.tj >= fe) {
                    out.push_back(pad(ind) + "if ( " + cndOf(bl).text() + " ) return" + retTxt() + ";");
                    k++;
                    continue;
                }
                if (bl.tj < bl.lo) {
                    needLabel.insert(bl.tj);
                    out.push_back(pad(ind) + "if ( " + cndOf(bl).text() + " ) goto LABEL_" +
                                  std::to_string((bl.tj - fs) / 4 + 1) + ";");
                    k++;
                    continue;
                }
                int nx = -1;
                if (!tryFold(k, ind, out, nx)) {
                    needLabel.insert(bl.tj);
                    out.push_back(pad(ind) + "if ( " + cndOf(bl).text() + " ) goto LABEL_" +
                                  std::to_string((bl.tj - fs) / 4 + 1) + ";");
                    nx = k + 1;
                }
                k = nx;
                continue;
            }
            k++;
        }
    }

    // loop detection and emission at a loop-head block; returns next block index
    int tryLoop(int k, int ind, std::vector<std::string> &out) {
        const Blk &bl = blocks[k];
        uint64_t head = bl.lo;
        int j = -1;
        for (int q = k; q < (int)blocks.size(); q++)
            if (blocks[q].term == K_JUMP && blocks[q].tj == head) { j = q; break; }
        if (j >= 0) {
            int cb = -1;
            for (int q = k; q < j; q++)
                if (blocks[q].term == K_CJUMP && blocks[q].tj >= blocks[j].lo && blocks[q].tj != head) { cb = q; break; }
            int brkIdx;
            if (cb >= 0) {
                brkIdx = blkOf(blocks[cb].tj);
                if (brkIdx < 0 || brkIdx <= k) { j = -1; }
            } else {
                brkIdx = j + 1;
            }
            if (j < 0 || brkIdx < 0) goto dowhile;
            for (int i = k; i < brkIdx; i++)
                if (claimed.count(i)) { j = -1; goto dowhile; }
            {
                uint64_t brk = cb >= 0 ? blocks[cb].tj : (j + 1 < (int)blocks.size() ? blocks[j + 1].lo : fe);
                LoopC lc;
                lc.cont = head;
                lc.brk = brk;
                loops.push_back(lc);
                for (int i = k; i < brkIdx; i++) claimed.insert(i);
                if (cb >= 0) {
                    walk(k, cb, ind, out, 0);
                    emitInsns(blocks[cb].b, blocks[cb].tIx, ind, out);
                    Cond cnd = cndOf(blocks[cb]);
                    out.push_back(pad(ind) + "while ( " + cnd.inv().text() + " ) {");
                    walk(cb + 1, j + 1, ind + 1, out, head);
                    out.push_back(pad(ind) + "}");
                } else {
                    out.push_back(pad(ind) + "while ( 1 ) {");
                    walk(k, j + 1, ind + 1, out, head);
                    out.push_back(pad(ind) + "}");
                }
                loops.pop_back();
                return j + 1;
            }
        }
    dowhile:
        j = -1;
        for (int q = k; q < (int)blocks.size(); q++)
            if (blocks[q].term == K_CJUMP && blocks[q].tj == head) { j = q; break; }
        if (j < 0) return k + 1;
        LoopC lc;
        lc.cont = head;
        lc.brk = j + 1 < (int)blocks.size() ? blocks[j + 1].lo : fe;
        loops.push_back(lc);
        for (int i = k; i <= j; i++) claimed.insert(i);
        out.push_back(pad(ind) + "do {");
        walk(k, j + 1, ind + 1, out, head);
        Cond cnd = cndOf(blocks[j]);
        out.push_back(pad(ind) + "} while ( " + cnd.text() + " );");
        loops.pop_back();
        return j + 1;
    }

    // initial branch-argument register states
    void pass2Init() {
        for (int i = 0; i < nArgs; i++) {
            int r = argRegs[i];
            rs[r].isArg = true;
            rs[r].txt = "a" + std::to_string(i + 1);
            markUsed(rs[r].vn);
        }
    }

    void walkAll() {
        walk(0, (int)blocks.size(), 4, records, 0);
        depth--;
    }

    void assemble() {
        std::string nm = db->nameAt(fs);
        std::string fn;
        if (nm.empty()) {
            char b[40];
            snprintf(b, 40, "sub_%llX", (unsigned long long)fs);
            fn = b;
        } else {
            fn = cxxDemangle(nm);
            if (fn.empty()) {
                char b[40];
                snprintf(b, 40, "sub_%llX", (unsigned long long)fs);
                fn = b;
            }
        }
        const char *rt = "void";
        if (written0) {
            if (fRet == 4) rt = "float";
            else if (fRet == 8) rt = "double";
            else rt = anyX0 ? "__int64" : "int";
        }
        std::string args;
        for (int i = 0; i < nArgs; i++) {
            int r = argRegs[i];
            if (i) args += ", ";
            args += isFloatReg(r) ? std::string(ftype(r)) : std::string(anyX[r] ? "__int64" : "int");
            args += " a" + std::to_string(i + 1);
        }
        records.push_back(std::string("H\1") + rt + " __fastcall " + fn + "(" + args + ")");
        records.push_back("B\1{");
        reach.resize(blocks.size(), false);
        reach[0] = true;
        std::vector<int> stk;
        stk.push_back(0);
        while (!stk.empty()) {
            int i = stk.back();
            stk.pop_back();
            const Blk &bl = blocks[i];
            if (bl.term == K_IJUMP) {
                for (size_t j2 = (size_t)i + 1; j2 < blocks.size(); j2++)
                    if (!reach[j2]) { reach[j2] = true; stk.push_back((int)j2); }
                continue;
            }
            if (bl.term == K_JUMP || bl.term == K_CJUMP) {
                if (bl.tj >= fs && bl.tj < fe) {
                    int t = blkOf(bl.tj);
                    if (t >= 0 && !reach[t]) { reach[t] = true; stk.push_back(t); }
                }
            }
            if (bl.term != K_JUMP && bl.term != K_RET && i + 1 < (int)blocks.size()) {
                if (!reach[i + 1]) { reach[i + 1] = true; stk.push_back(i + 1); }
            }
        }
        walkAll();
        records.push_back("B\1}");
        std::vector<std::string> decls;
        for (size_t i = 0; i < vars.size(); i++) {
            if (!vars[i].used) continue;
            decls.push_back("V\1" + vars[i].type + " " + vars[i].name + ";" +
                            (vars[i].cmt.empty() ? "" : " " + vars[i].cmt));
        }
        records.insert(records.begin() + 1, decls.begin(), decls.end());
    }
};

} // namespace pseudo_ns

std::vector<std::string> Database::pseudo(uint64_t fnAddr) {
    std::vector<std::string> r;
    pseudo_ns::PGen g(this, fnAddr);
    if (g.fe <= g.fs) return r;
    g.decode();
    if (g.ins.empty()) return r;
    g.buildBlocks();
    if (g.blocks.empty()) return r;
    g.pass1();
    g.pass2Init();
    g.assemble();
    return g.records;
}

// ---------- signature maker (SigMaker) ----------

namespace pseudo_ns {

// Position-dependent instruction classes: wild = number of low bytes to wildcard.
// Byte order is little-endian: byte0 = bits 7..0, byte3 = bits 31..24.
static void sigWild(uint32_t w, int &wild) {
    uint32_t op = w >> 24;
    wild = 0;
    if ((op & 0x7C) == 0x14) { wild = 3; return; }                    // B (imm26 bits 25:0)
    if (op >= 0x94 && op <= 0x97) { wild = 3; return; }               // BL
    if (op == 0x34 || op == 0x35 || op == 0xB4 || op == 0xB5) { wild = 3; return; } // CBZ/CBNZ (imm19)
    if (op == 0x54) { wild = 3; return; }                             // B.cond (imm19)
    if (op == 0x36 || op == 0x37 || op == 0xB6 || op == 0xB7) { wild = 3; return; } // TBZ/TBNZ (imm14)
    if ((w & 0x9F000000) == 0x90000000) { wild = 3; return; }         // ADRP (imm21)
    if ((w & 0x9F000000) == 0x10000000) { wild = 3; return; }         // ADR
    if ((w & 0x3B000000) == 0x18000000) { wild = 3; return; }         // LDR literal / LDRSW / PRFM
    if ((w & 0x7F800000) == 0x52800000 || (w & 0x7F800000) == 0x72800000 ||
        (w & 0x7F800000) == 0x7A800000) { wild = 2; return; }         // MOVZ/MOVN/MOVK (imm16, hw)
    if ((w & 0x1F000000) == 0x11000000) { wild = 2; return; }         // ADD/SUB/SUBS imm (imm12, sh)
}

} // namespace pseudo_ns

std::string Database::makeSig(uint64_t fnAddr) {
    uint64_t fs, fe;
    if (!funcContaining(fnAddr, fs, fe)) return "";
    uint32_t words[64];
    uint8_t mask[256];
    int n = 0;
    uint64_t pc = fs;
    while (pc + 4 <= fe && n < 64) {
        uint32_t w;
        if (!readMem(pc, &w, 4)) break;
        words[n] = w;
        int wild = 0;
        pseudo_ns::sigWild(w, wild);
        for (int i = 0; i < 4; i++) {
            uint8_t m = 0;
            if (wild == 3 && i < 3) m = 1;
            if (wild == 2 && i >= 1 && i <= 2) m = 1;
            mask[n * 4 + i] = m;
        }
        n++;
        pc += 4;
    }
    if (n == 0) return "";

    // extend the anchor until the pattern is unique in the whole file
    const std::vector<uint8_t> &f = file;
    int bestN = 0;
    size_t bestMatches = 0;
    for (int len = 1; len <= n; len++) {
        size_t plen = (size_t)len * 4;
        if (plen > f.size()) break;
        size_t firstFixed = (size_t)-1;
        for (size_t i = 0; i < plen; i++)
            if (!mask[i]) { firstFixed = i; break; }
        size_t matches = 0;
        if (firstFixed == (size_t)-1) matches = f.size() - plen + 1;
        else {
            uint8_t fb = (uint8_t)((words[firstFixed / 4] >> (8 * (firstFixed % 4))) & 0xFF);
            for (size_t off = 0; off + plen <= f.size(); off++) {
                if (f[off + firstFixed] != fb) continue;
                bool ok = true;
                for (size_t i = 0; i < plen; i++) {
                    if (mask[i]) continue;
                    if (f[off + i] != (uint8_t)((words[i / 4] >> (8 * (i % 4))) & 0xFF)) { ok = false; break; }
                }
                if (ok) matches++;
            }
        }
        if (matches == 0) break;
        bestN = len;
        bestMatches = matches;
        if (matches == 1) break;
    }
    if (bestN == 0) return "";

    std::string ida, x64, carr, bitm;
    for (int i = 0; i < bestN * 4; i++) {
        char b[8];
        snprintf(b, 8, "%02X", (unsigned)((words[i / 4] >> (8 * (i % 4))) & 0xFF));
        if (i) { ida += " "; x64 += " "; }
        if (mask[i]) { ida += "?"; x64 += "??"; carr += "\\x00"; bitm += "?"; }
        else { ida += b; x64 += b; carr += std::string("\\x") + b; bitm += "x"; }
    }
    char h1[48], h2[64];
    snprintf(h1, 48, "0x%llX", (unsigned long long)fs);
    snprintf(h2, 64, "%d bytes (%d insns)", bestN * 4, bestN);
    std::string r;
    r += "IDA:      " + ida + "\n";
    r += "x64dbg:   " + x64 + "\n";
    r += "C array:  " + carr + "\n";
    r += "Bitmask:  " + bitm + "\n";
    r += "Address:  " + std::string(h1) + "\n";
    r += "Length:   " + std::string(h2) + "\n";
    r += "Matches:  " + std::to_string(bestMatches) + " in file";
    return r;
}
