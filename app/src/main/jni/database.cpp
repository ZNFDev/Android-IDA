#include "ida_core.h"
#pragma once
#include <cstring>
#include <fstream>
#include <iterator>
#include <algorithm>
using std::string;

static uint16_t r16(const uint8_t* p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t r32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t r64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }
static string hex(uint64_t v) { char b[24]; snprintf(b, 24, "%llX", (unsigned long long)v); return b; }
static string cstr(const std::vector<uint8_t>& f, uint64_t off) {
    if (off >= f.size()) return "";
    size_t e = off; while (e < f.size() && f[e]) e++;
    return string((const char*)&f[off], e - off);
}

bool Database::load(const string& p, string& err) {
    path = p;
    std::ifstream in(p, std::ios::binary);
    if (!in) { err = "cannot open file"; return false; }
    file.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (file.size() < 64 || memcmp(file.data(), "\x7f" "ELF", 4)) { err = "not an ELF file"; return false; }
    if (file[4] != 2 || file[5] != 1) { err = "only ELF64 little-endian supported"; return false; }
    machine = r16(&file[18]); entry = r64(&file[24]);
    uint64_t phoff = r64(&file[32]), shoff = r64(&file[40]);
    int phes = r16(&file[54]), phn = r16(&file[56]), shes = r16(&file[58]), shn = r16(&file[60]), shstr = r16(&file[62]);
    for (int i = 0; i < phn; i++) {
        uint64_t o = phoff + (uint64_t)i * phes; if (o + 56 > file.size()) break;
        const uint8_t* h = &file[o];
        if (r32(h) == 1) regions.push_back({r64(h + 16), r64(h + 40), r64(h + 8), r64(h + 32), r32(h + 4)});
    }
    for (int i = 0; i < shn; i++) {
        uint64_t o = shoff + (uint64_t)i * shes; if (o + 64 > file.size()) break;
        const uint8_t* h = &file[o]; Section s;
        s.name = std::to_string(r32(h)); // temp: name offset
        s.type = r32(h + 4); s.flags = r64(h + 8); s.addr = r64(h + 16); s.foff = r64(h + 24); s.size = r64(h + 32);
        s.link = r32(h + 40); s.info = r32(h + 44); s.entsize = r64(h + 56);
        secs.push_back(s);
    }
    if (shstr < (int)secs.size()) {
        uint64_t so = secs[shstr].foff;
        for (auto& s : secs) s.name = cstr(file, so + (uint64_t)atoll(s.name.c_str()));
    }
    // symbols
    std::map<int, std::vector<Symbol>> tabs;
    for (size_t si = 0; si < secs.size(); si++) {
        const Section& s = secs[si];
        if ((s.type != 2 && s.type != 11) || s.link >= secs.size() || s.foff + s.size > file.size()) continue;
        uint64_t stro = secs[s.link].foff;
        for (uint64_t o = 24; o + 24 <= s.size; o += 24) {
            const uint8_t* e = &file[s.foff + o]; Symbol y;
            y.name = cstr(file, stro + r32(e)); y.type = e[4] & 15; y.bind = e[4] >> 4; y.shndx = r16(e + 6);
            y.addr = r64(e + 8); y.size = r64(e + 16); y.dyn = (s.type == 11);
            tabs[(int)si].push_back(y);   // index = o/24 - 1 + ... (we skip sym 0 so index shifted)
            syms.push_back(y);
        }
    }
    // relocations -> GOT names
    for (size_t si = 0; si < secs.size(); si++) {
        const Section& s = secs[si]; if (s.type != 4 || s.foff + s.size > file.size()) continue;
        auto it = tabs.find((int)s.link); if (it == tabs.end()) continue;
        for (uint64_t o = 0; o + 24 <= s.size; o += 24) {
            const uint8_t* e = &file[s.foff + o]; uint64_t info = r64(e + 8);
            uint32_t ty = (uint32_t)info, sym = (uint32_t)(info >> 32);
            if ((ty == 1025 || ty == 1026 || ty == 257) && sym >= 1 && sym - 1 < it->second.size())
                gotNames[r64(e)] = it->second[sym - 1].name;
        }
    }
    return true;
}

bool Database::readMem(uint64_t a, void* dst, size_t n) const {
    uint8_t* d = (uint8_t*)dst; size_t done = 0;
    while (done < n) {
        bool hit = false;
        for (auto& r : regions) {
            if (a + done >= r.addr && a + done < r.addr + r.memsz) {
                uint64_t rel = a + done - r.addr; size_t chunk = (size_t)std::min<uint64_t>(n - done, r.memsz - rel);
                for (size_t k = 0; k < chunk; k++) { uint64_t fo = rel + k; d[done + k] = (fo < r.filesz && r.foff + fo < file.size()) ? file[r.foff + fo] : 0; }
                done += chunk; hit = true; break;
            }
        }
        if (!hit) return false;
    }
    return true;
}
const Section* Database::sectionAt(uint64_t a) const {
    for (auto& s : secs) if (s.alloc() && s.addr && a >= s.addr && a < s.addr + s.size) return &s;
    return nullptr;
}
string Database::nameAt(uint64_t a) const {
    auto it = names.find(a);
    if (it == names.end()) return "0x" + hex(a);
    // display demangled C++ names like IDA does; lookups keep the mangled form
    if (it->second.size() > 3 && it->second[0] == '_' && it->second[1] == 'Z') {
        std::string d = cxxDemangle(it->second);
        if (!d.empty()) return d;
    }
    return it->second;
}
bool Database::funcContaining(uint64_t a, uint64_t& st, uint64_t& en) const {
    auto it = funcs.upper_bound(a); if (it == funcs.begin()) return false; --it; st = *it;
    auto nx = funcs.upper_bound(a); const Section* s = sectionAt(st); if (!s) return false;
    en = s->addr + s->size; if (nx != funcs.end() && *nx < en) en = *nx;
    return a < en;
}
string Database::funcRel(uint64_t a) const {
    uint64_t st, en; if (!funcContaining(a, st, en)) return nameAt(a);
    return a == st ? nameAt(st) : nameAt(st) + "+" + hex(a - st);
}
uint64_t Database::lookup(const string& n) const { for (auto& kv : names) if (kv.second == n) return kv.first; return 0; }
void Database::addXref(uint64_t to, uint64_t from, char t) { xrefs[to].push_back({from, t}); }

static string strName(const string& s) {
    string o = "a"; bool up = true;
    for (char c : s) { if (o.size() >= 24) break; if (isalnum((unsigned char)c)) { o += up ? (char)toupper(c) : c; up = false; } else if (!up) { o += '_'; up = true; } }
    while (o.size() > 1 && o.back() == '_') o.pop_back(); return o;
}

bool Database::regionCovers(uint64_t a, uint64_t n) const {
    uint64_t done = 0;
    while (done < n) {
        bool hit = false;
        for (auto& r : regions) {
            if (a + done >= r.addr && a + done < r.addr + r.memsz) {
                uint64_t rel = a + done - r.addr;
                done += (uint64_t)std::min<uint64_t>(n - done, r.memsz - rel); hit = true; break;
            }
        }
        if (!hit) return false;
    }
    return true;
}

void Database::addName(uint64_t a, const std::string& n) { names[a] = n; takenNames.insert(n); }

// ---- compact Itanium C++ ABI demangler -------------------------------------
// Covers the common subset: _Z[...] nested names, substitutions, template
// args, builtin types, pointers/refs/qualifiers, arrays, functions, enums.
// Anything it cannot parse yields "" and callers keep the mangled form.
namespace {
struct Dem {
    const std::string& s;
    size_t i = 0;
    std::vector<std::string> subs;   // S_ = "std", then recorded entries
    std::string out;
    bool fail = false;
    std::string pending;   // composed prefix / instantiation awaiting its record trigger
    bool stBare = false;   // last takeSub was a bare St ("std" is never a candidate)
    std::string quals;     // method cv/ref qualifiers, printed after the params

    Dem(const std::string& str) : s(str) {}
    int peek() const { return i < s.size() ? s[i] : -1; }
    int take() { return i < s.size() ? (unsigned char)s[i++] : -1; }
    void advance(int n) { i += (size_t)n; if (i > s.size()) fail = true; }
    bool eof() const { return i >= s.size(); }
    bool digit() const { int c = peek(); return c >= '0' && c <= '9'; }
    long number() {
        if (!digit()) { fail = true; return 0; }
        long v = 0;
        while (digit()) v = v * 10 + (take() - '0');
        return v;
    }
    void addSub(const std::string& t) { if (subs.size() < 4096) subs.push_back(t); }

    // two-letter operator codes; consumes the code when it matches, else no-op.
    // Returns "" when the next two chars are not an operator encoding.
    std::string operatorName() {
        int c1 = peek();
        int c2 = i + 1 < s.size() ? s[i + 1] : -1;
        std::string o;
        #define OP(a, b, t) if (c1 == a && c2 == b) { advance(2); o = t; }
        OP('n','w',"new") OP('n','a',"new[]") OP('d','l',"delete") OP('d','a',"delete[]")
        OP('p','s',"operator+") OP('n','g',"operator-") OP('a','d',"operator&") OP('d','e',"operator*")
        OP('c','o',"operator~") OP('p','l',"operator+") OP('m','i',"operator-") OP('m','l',"operator*")
        OP('d','v',"operator/") OP('r','m',"operator%") OP('a','n',"operator&") OP('o','r',"operator|")
        OP('e','o',"operator^") OP('a','S',"operator=") OP('p','L',"operator+=") OP('m','I',"operator-=")
        OP('m','L',"operator*=") OP('d','V',"operator/=") OP('r','M',"operator%=") OP('a','N',"operator&=")
        OP('o','R',"operator|=") OP('e','O',"operator^=") OP('l','s',"operator<<") OP('r','s',"operator>>")
        OP('l','S',"operator<<=") OP('r','S',"operator>>=") OP('e','q',"operator==") OP('n','e',"operator!=")
        OP('l','t',"operator<") OP('g','t',"operator>") OP('l','e',"operator<=") OP('g','e',"operator>=")
        OP('s','s',"operator<=>") OP('n','t',"operator!") OP('a','a',"operator&&") OP('o','o',"operator||")
        OP('p','p',"operator++") OP('m','m',"operator--") OP('c','m',"operator,") OP('p','m',"operator->*")
        OP('p','t',"operator->") OP('c','l',"operator()") OP('i','x',"operator[]") OP('q','u',"operator?")
        OP('s','t',"sizeof") OP('s','z',"sizeof...") OP('a','t',"alignof") OP('a','z',"alignof...")
        OP('n','x',"noexcept")
        #undef OP
        return o;
    }

    // substitution: i is at 'S'. Handles St (std), the standard single-letter
    // abbreviations (Ss/Sa/Sb/...), S_ and indexed entries S0_..
    // Inside a nested name N...E, bare S_ refers to substitution #0;
    // as a type it abbreviates St (std::).
    std::string takeSub(bool nested = false) {
        stBare = false;
        advance(1);   // consume 'S'
        int c = peek();
        if (c == 't') { advance(1); stBare = true; return "std"; }
        if (c == 's') { advance(1); return "std::string"; }
        if (c == 'a') { advance(1); return "std::allocator"; }
        if (c == 'b') { advance(1); return "std::basic_string"; }
        if (c == 'c') { advance(1); return "std::char_traits"; }
        if (c == 'd') { advance(1); return "std::iostream"; }
        if (c == 'i') { advance(1); return "std::istream"; }
        if (c == 'o') { advance(1); return "std::ostream"; }
        if (c == '_') {
            advance(1);
            if (nested) {
                if (subs.empty()) { fail = true; return ""; }
                return subs[0];
            }
            return "std";
        }
        if (!digit()) { fail = true; return ""; }
        long n = number();
        if (fail || take() != '_') { fail = true; return ""; }
        if (n < 0 || n + 1 >= (long)subs.size()) { fail = true; return ""; }
        return subs[(size_t)n + 1];
    }

    // source-name: <positive length> <chars>
    std::string sourceName() {
        long n = number();
        if (fail || n <= 0 || i + (size_t)n > s.size()) { fail = true; return ""; }
        std::string r = s.substr(i, (size_t)n);
        for (char c : r) if ((unsigned char)c < 0x20 || c == 0) { fail = true; return ""; }
        i += (size_t)n;
        return r;
    }

    // builtin type single letters
    const char* builtinChar(int c) {
        switch (c) {
        case 'v': return "void";    case 'w': return "wchar_t"; case 'b': return "bool";
        case 'c': return "char";    case 'a': return "signed char";
        case 'h': return "unsigned char";
        case 's': return "short";   case 't': return "unsigned short";
        case 'i': return "int";     case 'j': return "unsigned int";
        case 'l': return "long";    case 'm': return "unsigned long";
        case 'x': return "long long"; case 'y': return "unsigned long long";
        case 'n': return "__int128"; case 'o': return "unsigned __int128";
        case 'f': return "float";   case 'd': return "double";
        case 'e': return "long double"; case 'g': return "__float128";
        case 'z': return "...";
        case 'D': if (peek() == 'n') { advance(1); return "std::nullptr_t"; } return 0;
        case 'u': return 0;         // vendor extended type: unsupported
        default: return 0;
        }
    }

    // type := builtin | subst | class-name (source-name) | P/R/O/K/V type |
    //         A n _ type | F types E | N ... E (nested) | U vendor ...
    // Peek-based dispatch: each branch consumes exactly what it parses.
    std::string parseType(int depth) {
        if (fail || depth > 64) { fail = true; return ""; }
        int c = peek();
        if (c < 0) { fail = true; return ""; }
        if (c == 'S') {
            std::string t = takeSub(true);
            if (fail) return "";
            // continuation components: St11char_traitsIcE stays one type
            for (;;) {
                int c2 = peek();
                if (c2 == 'I') { t += typeSuffix(depth, t); if (fail) return ""; break; }
                if (digit()) {
                    std::string comp = sourceName();
                    if (fail) return "";
                    t += "::" + comp;
                    addSub(t);
                    continue;
                }
                break;
            }
            std::string suf = typeSuffix(depth, t);
            if (fail) return "";
            if (!suf.empty()) pending = t + suf;   // instantiation stages for later recording
            return t + suf;
        }
        if (c == 'P') {
            advance(1);
            std::string t = parseType(depth + 1);
            if (fail) return "";
            std::string r2 = t + "*";
            if (pending.empty()) addSub(r2);
            return r2;
        }
        if (c == 'R' || c == 'O') {
            advance(1);
            bool wasSub = peek() == 'S';
            std::string t = parseType(depth + 1);
            if (fail) return "";
            std::string r2 = t + (c == 'R' ? "&" : "&&");
            // unlike P, ref-composition over a sub-ref is not a candidate
            if (!wasSub && pending.empty()) addSub(r2);
            return r2;
        }
        if (c == 'K' || c == 'V') {
            advance(1);
            bool wasSub = peek() == 'S';
            std::string t = parseType(depth + 1);
            if (fail) return "";
            std::string r2 = t + (c == 'K' ? " const" : " volatile");
            // cv-composition is a candidate unless over a sub-ref or an instantiation
            if (!wasSub && pending.empty()) addSub(r2);
            return r2;
        }
        if (c == 'A') {
            advance(1);
            long n = number();
            if (fail || take() != '_') { fail = true; return ""; }
            return parseType(depth + 1) + "[" + (n ? std::to_string(n) : "") + "]";
        }
        if (c == 'F') {   // function type: params (last may be void) [ret] E
            advance(1);
            std::string params, ret;
            bool first = true;
            while (peek() != 'E' && !eof()) {
                if (!pending.empty()) { addSub(pending); pending.clear(); }
                std::string t = parseType(depth + 1);
                if (fail) return "";
                if (first) { ret = t == "void" ? "" : t + " "; first = false; }
                else { if (!params.empty()) params += ", "; params += t; }
            }
            if (fail || take() != 'E') { fail = true; return ""; }
            return ret + "(" + params + ")";
        }
        if (c == 'N') {   // nested class as type
            advance(1);
            std::string t = parseNested(depth + 1);
            if (fail) return "";
            std::string q = quals;   // qualifiers on a nested type print as a suffix
            quals.clear();
            return t + q;
        }
        if (c == 'D') {
            advance(1);
            if (peek() == 'p') { advance(1); return parseType(depth + 1) + "..."; }
            if (peek() == 'n') { advance(1); return "std::nullptr_t"; }
            if (peek() == 'i') { advance(1); return "decimal128"; }
            if (peek() == 'f') { advance(1); return "decimal32"; }
            if (peek() == 'h') { advance(1); return "half"; }
            if (peek() == 's') { advance(1); return "char16_t"; }
            if (peek() == 'e') { advance(1); return "char8_t"; }
            if (peek() == 'd') { advance(1); return "char32_t"; }
            fail = true; return "";
        }
        if (c == 'u') { fail = true; return ""; }   // vendor types: bail
        if (digit()) {                              // class-name type
            std::string name = sourceName();
            if (fail) return "";
            std::string suf = typeSuffix(depth, name);
            if (fail) return "";
            addSub(name);          // bare class name in type position is a candidate
            if (!suf.empty()) pending = name + suf;
            return name + suf;
        }
        advance(1);   // builtin single-letter type
        const char* b = builtinChar(c);
        if (b) return b;
        fail = true;
        return "";
    }

    // template args / array suffixes that follow a class-name type; base is the
    // text before the suffix so instantiations can stage their substitution.
    std::string typeSuffix(int depth, const std::string& base) {
        std::string suf;
        while (!fail && peek() == 'I') {
            advance(1);
            std::string args;
            bool first = true;
            while (peek() != 'E' && !eof()) {
                if (!pending.empty()) { addSub(pending); pending.clear(); }
                std::string a = parseType(depth + 1);
                if (fail) return "";
                if (!first) args += ", ";
                args += a; first = false;
            }
            if (fail || take() != 'E') { fail = true; return ""; }
            if (!pending.empty()) { addSub(pending); pending.clear(); }   // the last arg's instantiation is still a candidate
            suf += "<" + args + ">";
            pending = base + suf;   // instantiation awaits the next arg / next use
        }
        if (!fail && peek() == 'A') {  // array-of
            advance(1);
            long n = number();
            if (fail || take() != '_') { fail = true; return ""; }
            suf += "[" + (n ? std::to_string(n) : "") + "]";
            if (!suf.empty()) pending = base + suf;
        }
        return suf;
    }
    // N [quals] component ( :: component )... [I args E] E
    std::string parseNested(int depth) {
        if (depth > 64) { fail = true; return ""; }
        quals.clear();
        for (;;) {
            int c = peek();
            if (c == 'K') { quals = " const" + quals; advance(1); }
            else if (c == 'V') { quals = " volatile" + quals; advance(1); }
            else if (c == 'r') {   // restrict only when a ref-qualifier follows
                int n2 = i + 1 < s.size() ? s[i + 1] : -1;
                if (n2 == 'R' || n2 == 'O') { quals = " __restrict" + quals; advance(1); }
                else break;
            }
            else if (c == 'R') { quals = " &"; advance(1); }
            else if (c == 'O') { quals = " &&"; advance(1); }
            else break;
        }
        std::string r;
        std::string prefix;   // grows: "a::b", ...
        std::string last;     // previous component, for ctor/dtor naming
        bool instPend = false; // pending holds an instantiation (survives E)
        for (;;) {
            int c = peek();
            if (c < 0) { fail = true; return ""; }
            if (c == 'E') { advance(1); if (!instPend) pending.clear(); break; }
            if (!pending.empty()) addSub(pending);
            pending.clear();
            std::string comp;
            bool isCtorDtor = false;
            if (c == 'S') { comp = takeSub(true); }
            else if (digit()) {
                comp = sourceName();
            } else if (c == 'C' || c == 'D') {   // C1..C5 ctor / D0..D5 dtor / Dp pack
                advance(1);
                if (c == 'D' && peek() == 'p') {
                    advance(1);
                    comp = parseType(depth + 1);
                } else if (digit()) {
                    number();
                    comp = (c == 'C' ? last : "~" + last);
                    isCtorDtor = true;
                } else { fail = true; return ""; }
            } else if (c == 'c' && i + 1 < s.size() && s[i + 1] == 'v') {   // conversion op
                advance(2);
                std::string t = parseType(depth + 1);
                if (fail) return "";
                comp = "operator " + t;
            } else if (c == 'I') {   // template args attach to the last component
                if (!pending.empty()) addSub(pending);   // bare prefix still a candidate
                pending.clear();
                std::string suf = typeSuffix(depth, prefix);
                if (fail) return "";
                prefix += suf;
                r += suf;
                instPend = true;
                continue;
            } else if (c == 'L' || c == 'Z') { fail = true; return ""; }
            else {
                std::string o = operatorName();
                if (o.empty()) { fail = true; return ""; }
                comp = o;
            }
            if (fail) return "";
            if (!prefix.empty()) prefix += "::";
            prefix += comp;
            if (!r.empty()) r += "::";
            r += comp;
            last = comp;
            if (!isCtorDtor && !stBare) {
                pending = prefix;   // every component's compound is a candidate
                instPend = false;
            }
            stBare = false;
        }
        // template args may follow the last component
        std::string suf = typeSuffix(depth, prefix);
        if (fail) return "";
        prefix += suf;
        r += suf;
        return r;
    }

    std::string params(int depth) {
        std::string p;
        bool first = true;
        while (!eof()) {
            if (peek() == 'E') { advance(1); break; }
            std::string t = parseType(depth + 1);
            if (fail) return "";
            if (!first) p += ", ";
            p += t; first = false;
        }
        if (fail) return "";
        return p;
    }
};

std::string demangleItanium(const std::string& m) {
    if (m.size() < 4 || m[0] != '_' || m[1] != 'Z') return "";
    Dem d(m);
    d.i = 2;
    std::string r;
    if (d.peek() == 'L') d.advance(1);          // internal-linkage
    if (d.peek() == 'N' || d.peek() == 'S') {   // nested / std::...
        if (d.peek() == 'S') {
            std::string first = d.takeSub();
            if (d.fail) return "";
            std::string r2 = first;
            bool sInst = false;
            for (;;) {
                int c = d.peek();
                if (c < 0) break;
                if (c == 'I') {
                    if (!d.pending.empty()) d.addSub(d.pending);   // the name compound is a candidate
                    d.pending.clear();
                    std::string suf = d.typeSuffix(0, r2); if (d.fail) return ""; r2 += suf;
                    sInst = true;
                    continue;
                }
                std::string comp;
                if (c == 'S') comp = d.takeSub(true);
                else if (c == 'N') { d.advance(1); comp = d.parseNested(1); }
                else if (c == 'c' && d.i + 1 < m.size() && m[d.i + 1] == 'v') {
                    d.advance(2);
                    std::string t = d.parseType(1);
                    if (d.fail) return "";
                    comp = "operator " + t;
                }
                else if (d.digit()) comp = d.sourceName();
                else break;   // function params or end of encoding
                if (d.fail) return "";
                if (!d.pending.empty()) d.addSub(d.pending);
                d.pending.clear();
                r2 += "::" + comp;
                sInst = false;
                d.pending = r2;
            }
            if (d.fail) return "";
            if (!sInst) d.pending.clear();
            std::string p = d.params(0);
            if (d.fail || !d.eof()) return "";
            r2 += "(" + (p == "void" ? std::string() : p) + ")";
            return r2;
        }
        d.advance(1);   // consume 'N'
        r = d.parseNested(0);
        if (d.fail) return "";
        std::string p = d.params(0);
        if (d.fail) return "";
        if (!d.eof()) return "";      // trailing junk
        r += "(" + (p == "void" ? std::string() : p) + ")";
        r += d.quals;
        return r;
    }
    // unscoped: source-name [template args] [params]
    if (!d.digit()) {
        std::string o = d.operatorName();
        if (o.empty() || d.fail) return "";
        d.addSub(o);
        r = o;
    } else {
        std::string src = d.sourceName();
        if (d.fail) return "";
        d.addSub(src);
        std::string suf = d.typeSuffix(0, src);
        if (d.fail) return "";
        r = src + suf;
    }
    if (!d.eof()) {
        std::string p = d.params(0);
        if (d.fail || !d.eof()) return "";
        r += "(" + (p == "void" ? std::string() : p) + ")";
    }
    return r;
}
}   // namespace

std::string cxxDemangle(const std::string& mangled) {
    try { return demangleItanium(mangled); } catch (...) { return ""; }
}

void Database::analyzeStage1() {
    for (auto& s : syms) {
        if (s.name.empty() || s.name[0] == '$' || !s.addr || s.shndx == 0 || s.type == 3 || s.type == 4) continue;
        if (!names.count(s.addr)) addName(s.addr, s.name);
        if (s.type == 2) funcs.insert(s.addr);
        if (s.type == 2 && s.bind != 0 && s.dyn) exports.push_back(s.name);
        if (s.type == 2 && s.shndx == 0) imports.push_back(s.name);
    }
    for (auto& s : syms) if (s.shndx == 0 && s.type == 2 && !s.name.empty()) imports.push_back(s.name);
    std::sort(imports.begin(), imports.end()); imports.erase(std::unique(imports.begin(), imports.end()), imports.end());
    std::sort(exports.begin(), exports.end()); exports.erase(std::unique(exports.begin(), exports.end()), exports.end());
    if (entry) { funcs.insert(entry); if (!names.count(entry)) addName(entry, "start"); }

    for (auto& sec : secs) {   // PLT stubs: ADRP X16 / LDR X17,[X16,#o]
        if (!sec.exec() || sec.name.compare(0, 4, ".plt") != 0) continue;
        for (uint64_t a = sec.addr; a + 8 <= sec.addr + sec.size; a += 4) {
            uint32_t w1 = 0, w2 = 0; readMem(a, &w1, 4); readMem(a + 4, &w2, 4);
            if ((w1 & 0x9F00001F) == 0x90000010 && (w2 & 0xFFC003FF) == 0xF9400211) {
                int64_t imm = (int64_t)((((uint64_t)((w1 >> 5) & 0x7FFFF) << 2) | ((w1 >> 29) & 3)));
                if (imm & 0x100000) imm -= 0x200000;
                uint64_t got = ((a & ~0xFFFULL) + ((uint64_t)imm << 12)) + (uint64_t)(((w2 >> 10) & 0xFFF) * 8);
                auto g = gotNames.find(got);
                if (g != gotNames.end()) { addName(a, g->second); funcs.insert(a); }
            }
        }
    }
    for (auto& sec : secs) {   // init/fini arrays
        if (sec.name != ".init_array" && sec.name != ".fini_array") continue;
        for (uint64_t o = 0; o + 8 <= sec.size; o += 8) {
            uint64_t v = 0; readMem(sec.addr + o, &v, 8); const Section* t = sectionAt(v);
            if (t && t->exec()) { funcs.insert(v); addXref(v, sec.addr + o, 'o'); }
        }
    }
    stage1Done = true;
}

void Database::buildWorklists() {
    sweepList.clear(); strList.clear(); sweepTotalU = 0; strTotalU = 0;
    for (size_t i = 0; i < secs.size(); i++) {
        const Section& s = secs[i];
        if (s.exec() && s.name.compare(0, 4, ".plt") != 0 && s.size && regionCovers(s.addr, s.size)) {
            sweepList.push_back(i); sweepTotalU += s.size / 4;
        } else if (s.alloc() && !s.exec() && !s.write() && s.type == 1 && s.size && regionCovers(s.addr, s.size)) {
            strList.push_back(i); strTotalU += s.size;
        }
    }
}

void Database::processSweepWord(const Section& sec, uint64_t a, uint32_t w) {
    if (hasPend) { resolvePair(pendAddr, pendPage, pendRd, w); hasPend = false; }
    Insn in = a64_decode(a, w);
    if (in.hasTarget) {
        const Section* t = sectionAt(in.target);
        if (in.kind == K_CALL && t && t->exec()) { funcs.insert(in.target); addXref(in.target, a, 'p'); }
        else if ((in.kind == K_JUMP || in.kind == K_CJUMP) && t && t->exec()) { labels.insert(in.target); addXref(in.target, a, 'j'); }
    }
    if (in.mnem == "ADRP" && (a - sec.addr) + 8 <= sec.size) {   // defer ADRP + ADD/LDR/STR pair
        hasPend = true; pendAddr = a; pendPage = in.target; pendRd = w & 31;
    }
}

void Database::resolvePair(uint64_t a, uint64_t page, uint32_t rd, uint32_t w2) {
    uint64_t full = 0; char xt = 'o';
    if ((w2 & 0xFF800000) == 0x91000000 && ((w2 >> 5) & 31) == rd) full = page + (((w2 >> 10) & 0xFFF) << ((w2 >> 22) & 1 ? 12 : 0));
    else if ((w2 & 0x3B000000) == 0x39000000 && ((w2 >> 5) & 31) == rd) {
        int size = (w2 >> 30) & 3, opc = (w2 >> 22) & 3, v = (w2 >> 26) & 1; int sc = (v && size == 0 && opc >= 2) ? 4 : size;
        full = page + (uint64_t)(((w2 >> 10) & 0xFFF) << sc); xt = (opc & 1) ? 'r' : 'w';
        if (!v && opc == 2 && size == 3) full = 0;   // PRFM
    }
    if (full) { pairTarget[a] = full; pairTarget[a + 4] = full; addXref(full, a + 4, xt); }
}

void Database::sweepUnits(int budget) {
    if (sweepSec == (size_t)-1) sweepSec = 0;
    while (budget > 0 && sweepSec < sweepList.size()) {
        const Section& sec = secs[sweepList[sweepSec]];
        uint64_t words = sec.size / 4;
        if (sweepOff >= words) { hasPend = false; sweepSec++; sweepOff = 0; continue; }
        uint64_t take = (uint64_t)std::min<uint64_t>(words - sweepOff, (uint64_t)budget);
        chunkBuf.resize((size_t)take * 4);
        if (!readMem(sec.addr + sweepOff * 4, chunkBuf.data(), (size_t)take * 4)) { hasPend = false; sweepSec++; sweepOff = 0; continue; }
        for (uint64_t k = 0; k < take; k++) {
            uint32_t w = r32(&chunkBuf[(size_t)k * 4]);
            processSweepWord(sec, sec.addr + (sweepOff + k) * 4, w);
        }
        sweepOff += take; sweepDoneU += take; budget -= (int)take;
    }
    if (sweepSec >= sweepList.size()) sweepDone = true;
}

void Database::stringUnits(int budget) {
    if (strSec == (size_t)-1) strSec = 0;
    while (budget > 0 && strSec < strList.size()) {
        const Section& sec = secs[strList[strSec]];
        if (strOff >= sec.size) { strSec++; strOff = 0; strSt = 0; strOk = true; continue; }
        uint64_t take = (uint64_t)std::min<uint64_t>(sec.size - strOff, (uint64_t)budget);
        chunkBuf.resize((size_t)take);
        if (!readMem(sec.addr + strOff, chunkBuf.data(), (size_t)take)) { strSec++; strOff = 0; strSt = 0; strOk = true; continue; }
        for (uint64_t k = 0; k < take; k++) {
            uint8_t c = chunkBuf[(size_t)k]; uint64_t o = strOff + k;
            if (c == 0) {
                if (strOk && o - strSt >= 4) {
                    std::vector<uint8_t> sb((size_t)(o - strSt));
                    if (readMem(sec.addr + strSt, sb.data(), sb.size()))
                        strings[sec.addr + strSt] = string((char*)sb.data(), sb.size());
                }
                strSt = o + 1; strOk = true;
            } else if (!((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r')) strOk = false;
        }
        strOff += take; strDoneU += take; budget -= (int)take;
    }
    if (strSec >= strList.size()) strDone = true;
}

void Database::nameUnits(int budget) {
    // All stages below are idempotent (names.count guards), so they also
    // re-run safely over pre-named snapshots. Resume by address cursor so a
    // step boundary never repeats or skips an item.
    while (budget > 0 && !namedDone) {
        switch (nameStage) {
        case 0: {   // strings, globally address-ordered
            auto it = strings.lower_bound(nameCursor);
            if (it == strings.end()) { nameStage = 1; nameCursor = 0; break; }
            if (!names.count(it->first)) {
                string n = strName(it->second), b = n; int k = 1;
                while (takenNames.count(n)) n = b + "_" + std::to_string(k++);
                addName(it->first, n);
            }
            nameCursor = it->first + 1; budget--;
            break;
        }
        case 1: {   // function starts
            auto it = funcs.lower_bound(nameCursor);
            if (it == funcs.end()) { nameStage = 2; nameCursor = 0; break; }
            if (!names.count(*it)) addName(*it, "sub_" + hex(*it));
            nameCursor = *it + 1; budget--;
            break;
        }
        case 2: {   // loc_ labels
            auto it = labels.lower_bound(nameCursor);
            if (it == labels.end()) { nameStage = 3; nameCursor = 0; break; }
            if (!names.count(*it) && !funcs.count(*it)) addName(*it, "loc_" + hex(*it));
            nameCursor = *it + 1; budget--;
            break;
        }
        case 3: {   // xref data targets
            auto it = xrefs.lower_bound(nameCursor);
            if (it == xrefs.end()) { nameStage = 4; nameCursor = 0; break; }
            if (!names.count(it->first)) {
                const Section* s = sectionAt(it->first);
                if (s && !s->exec()) addName(it->first, (s->name.compare(0, 4, ".got") == 0 ? "off_" : "unk_") + hex(it->first));
            }
            nameCursor = it->first + 1; budget--;
            break;
        }
        case 4: {   // ADRP pair targets
            auto it = pairTarget.lower_bound(nameCursor);
            if (it == pairTarget.end()) { nameStage = 5; nameCursor = 0; break; }
            if (!names.count(it->second) && sectionAt(it->second)) addName(it->second, "unk_" + hex(it->second));
            nameCursor = it->first + 1; budget--;
            break;
        }
        default:    // sort xref sources once, cheap enough for a single step
            for (auto& kv : xrefs)
                std::sort(kv.second.begin(), kv.second.end(), [](const Xref& a, const Xref& b) { return a.from < b.from; });
            namedDone = true;
            break;
        }
    }
}

int Database::analyzeStep(int budget) {
    if (namedDone) return 0;
    if (!stage1Done) { analyzeStage1(); return 1; }
    if (!sweepDone) { sweepUnits(budget); return 1; }
    if (!strDone) { stringUnits(budget); return 1; }
    nameUnits(budget); return 1;
}

void Database::analyze() {
    buildWorklists();
    while (analyzeStep(1 << 30)) {}
}

// ---- snapshots ----
static const uint32_t SNAP_MAGIC = 0x53414449;   // "IDAS"
static const uint32_t SNAP_VER = 2;

static uint64_t fnv1a64(const std::vector<uint8_t>& f) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint8_t c : f) { h ^= c; h *= 0x100000001b3ULL; }
    return h;
}
static uint32_t fnv32(const std::vector<uint8_t>& b, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 16777619u; }
    return h;
}
static void wv(std::vector<uint8_t>& b, const void* p, size_t n) { const uint8_t* s = (const uint8_t*)p; b.insert(b.end(), s, s + n); }
static void wu8(std::vector<uint8_t>& b, uint8_t v) { wv(b, &v, 1); }
static void wu32(std::vector<uint8_t>& b, uint32_t v) { wv(b, &v, 4); }
static void wu64(std::vector<uint8_t>& b, uint64_t v) { wv(b, &v, 8); }
static void wstr(std::vector<uint8_t>& b, const string& s) { wu32(b, (uint32_t)s.size()); wv(b, s.data(), s.size()); }

/** Serialize the database state into a byte blob (fast; call under the engine mutex). */
std::vector<uint8_t> Database::serializeSnapshot() const {
    std::vector<uint8_t> b;
    wu32(b, SNAP_MAGIC); wu32(b, SNAP_VER);
    wu32(b, machine); wu64(b, entry);
    wu64(b, (uint64_t)file.size()); wu64(b, fnv1a64(file));
    wstr(b, path);
    wu8(b, stage1Done ? 1 : 0); wu8(b, sweepDone ? 1 : 0); wu8(b, strDone ? 1 : 0); wu8(b, namedDone ? 1 : 0);
    wu64(b, (uint64_t)sweepSec); wu64(b, sweepOff);
    wu64(b, (uint64_t)strSec); wu64(b, strOff); wu64(b, strSt); wu8(b, (uint8_t)strOk);
    wu8(b, hasPend ? 1 : 0); wu64(b, pendAddr); wu64(b, pendPage); wu32(b, pendRd);
    wu64(b, sweepDoneU); wu64(b, sweepTotalU); wu64(b, strDoneU); wu64(b, strTotalU);
    wu64(b, savedCursor); wu64(b, savedHex);
    wu64(b, funcs.size()); for (uint64_t f : funcs) wu64(b, f);
    wu64(b, labels.size()); for (uint64_t l : labels) wu64(b, l);
    wu64(b, names.size()); for (auto& kv : names) { wu64(b, kv.first); wstr(b, kv.second); }
    wu64(b, strings.size()); for (auto& kv : strings) { wu64(b, kv.first); wstr(b, kv.second); }
    wu64(b, xrefs.size());
    for (auto& kv : xrefs) {
        wu64(b, kv.first); wu32(b, (uint32_t)kv.second.size());
        for (auto& x : kv.second) { wu64(b, x.from); wu8(b, (uint8_t)x.type); }
    }
    wu64(b, pairTarget.size()); for (auto& kv : pairTarget) { wu64(b, kv.first); wu64(b, kv.second); }
    wu64(b, imports.size()); for (auto& s : imports) wstr(b, s);
    wu64(b, exports.size()); for (auto& s : exports) wstr(b, s);
    wu32(b, fnv32(b, b.size()));
    return b;
}

/** Write a serialized blob to disk (slow; never call while holding the engine mutex). */
bool Database::writeSnapshotBlob(const std::vector<uint8_t>& b, const std::string& p, std::string& err) {
    try {
        string tmp = p + ".tmp";
        remove(tmp.c_str());
        {
            std::ofstream out(tmp, std::ios::binary);
            if (!out) { err = "cannot create database file"; return false; }
            out.write((const char*)b.data(), (std::streamsize)b.size());
            if (!out) { err = "database write failed"; out.close(); return false; }
        }
        remove(p.c_str());
        if (rename(tmp.c_str(), p.c_str())) { err = "cannot rename database file"; return false; }
        return true;
    } catch (...) { err = "database save failed"; return false; }
}

bool Database::saveSnapshot(const string& p, string& err) {
    try {
        std::vector<uint8_t> b = serializeSnapshot();
        return writeSnapshotBlob(b, p, err);
    } catch (...) { err = "database save failed"; return false; }
}

bool Database::loadSnapshot(const string& p, string& err) {
    std::vector<uint8_t> b;
    {
        std::ifstream in(p, std::ios::binary);
        if (!in) { err = "cannot open database file"; return false; }
        in.seekg(0, std::ios::end);
        std::streamoff n = in.tellg(); in.seekg(0);
        if (n <= 0) { remove(p.c_str()); err = "empty database file"; return false; }
        b.resize((size_t)n);
        in.read((char*)b.data(), n);
        if (!in || b.size() < 8) { remove(p.c_str()); err = "corrupt database file"; return false; }
    }
    uint32_t chk = fnv32(b, b.size() - 4), stored = 0; memcpy(&stored, &b[b.size() - 4], 4);
    if (chk != stored || r32(&b[0]) != SNAP_MAGIC || r32(&b[4]) != SNAP_VER) { remove(p.c_str()); err = "corrupt database file"; return false; }
    size_t i = 8;
    auto rd = [&](void* d, size_t n) -> bool { if (i + n > b.size() - 4) return false; memcpy(d, &b[i], n); i += n; return true; };
    auto rdu8 = [&](uint8_t& v) { return rd(&v, 1); };
    auto rdu32 = [&](uint32_t& v) { return rd(&v, 4); };
    auto rdu64 = [&](uint64_t& v) { return rd(&v, 8); };
    auto rdstr = [&](string& s) -> bool { uint32_t n2; if (!rdu32(n2) || i + n2 > b.size() - 4) return false; s.assign((char*)&b[i], n2); i += n2; return true; };
    try {
        uint32_t m2 = 0, pr = 0; uint64_t e2 = 0, fsize = 0, fhash = 0, sw2 = 0, swo = 0, st2 = 0, sto = 0, sts = 0, po = 0, pp = 0;
        string snapPath; uint8_t sok = 0, hp = 0;
        if (!rdu32(m2) || !rdu64(e2) || !rdu64(fsize) || !rdu64(fhash) || !rdstr(snapPath)) throw 0;
        uint8_t fl[4] = {0, 0, 0, 0};
        if (!rdu8(fl[0]) || !rdu8(fl[1]) || !rdu8(fl[2]) || !rdu8(fl[3])) throw 0;
        if (m2 != machine || e2 != entry || fsize != file.size() || fhash != fnv1a64(file)) { remove(p.c_str()); err = "database is for a different file"; return false; }
        if (!rdu64(sw2) || !rdu64(swo) || !rdu64(st2) || !rdu64(sto) || !rdu64(sts) || !rdu8(sok) || !rdu8(hp) || !rdu64(po) || !rdu64(pp) || !rdu32(pr)) throw 0;
        uint64_t sd = 0, stt = 0, sdd = 0, stt2 = 0, cur = 0, hxv = 0;
        if (!rdu64(sd) || !rdu64(stt) || !rdu64(sdd) || !rdu64(stt2) || !rdu64(cur) || !rdu64(hxv)) throw 0;
        auto rdset = [&](std::set<uint64_t>& out) -> bool {
            uint64_t n3; if (!rdu64(n3)) return false;
            for (uint64_t k = 0; k < n3; k++) { uint64_t v; if (!rdu64(v)) return false; out.insert(v); }
            return true;
        };
        if (!rdset(funcs) || !rdset(labels)) throw 0;
        auto rdnmap = [&](std::map<uint64_t, string>& out) -> bool {
            uint64_t n3; if (!rdu64(n3)) return false;
            for (uint64_t k = 0; k < n3; k++) { uint64_t a; string s; if (!rdu64(a) || !rdstr(s)) return false; out[a] = s; }
            return true;
        };
        if (!rdnmap(names) || !rdnmap(strings)) throw 0;
        {
            uint64_t n3; if (!rdu64(n3)) throw 0;
            for (uint64_t k = 0; k < n3; k++) {
                uint64_t t; uint32_t c; if (!rdu64(t) || !rdu32(c)) throw 0;
                for (uint32_t j = 0; j < c; j++) { uint64_t f2; uint8_t ty; if (!rdu64(f2) || !rdu8(ty)) throw 0; xrefs[t].push_back({f2, (char)ty}); }
            }
        }
        {
            uint64_t n3; if (!rdu64(n3)) throw 0;
            for (uint64_t k = 0; k < n3; k++) { uint64_t a, t; if (!rdu64(a) || !rdu64(t)) throw 0; pairTarget[a] = t; }
        }
        auto rdlst = [&](std::vector<string>& out) -> bool {
            uint64_t n3; if (!rdu64(n3)) return false;
            for (uint64_t k = 0; k < n3; k++) { string s; if (!rdstr(s)) return false; out.push_back(s); }
            return true;
        };
        if (!rdlst(imports) || !rdlst(exports)) throw 0;
        if (i > b.size() - 4) throw 0;
        stage1Done = fl[0] != 0; sweepDone = fl[1] != 0; strDone = fl[2] != 0; namedDone = fl[3] != 0;
        sweepSec = sw2; sweepOff = swo; strSec = st2; strOff = sto; strSt = sts; strOk = sok;
        hasPend = hp != 0; pendAddr = po; pendPage = pp; pendRd = pr;
        sweepDoneU = sd; sweepTotalU = stt; strDoneU = sdd; strTotalU = stt2;
        savedCursor = cur; savedHex = hxv;
        for (auto& kv : names) takenNames.insert(kv.second);
        snapLoaded = true;
        return true;
    } catch (...) { remove(p.c_str()); err = "corrupt database file"; return false; }
}

string Database::targetName(uint64_t t, const string& mnem) const {
    auto nm = names.find(t);
    if (nm != names.end()) return nm->second;
    bool code = mnem == "B" || mnem == "BL" || mnem.rfind("B.", 0) == 0 ||
                mnem == "CBZ" || mnem == "CBNZ" || mnem == "TBZ" || mnem == "TBNZ";
    if (code && funcs.count(t)) return "sub_" + hex(t);
    if (code && labels.count(t)) return "loc_" + hex(t);
    if (code) return (mnem == "BL") ? ("sub_" + hex(t)) : ("loc_" + hex(t));   // display-only auto labels; BL targets read as functions like the pseudo view
    return nameAt(t);
}

string Database::resolveOps(const Insn& in) const {
    string o = in.ops;
    size_t p = o.find('\x02');
    if (p != string::npos) {
        uint64_t t = in.target; auto pt = pairTarget.find(in.addr);
        if (in.mnem == "ADRP" && pt != pairTarget.end()) t = pt->second;
        o.replace(p, 1, targetName(t, in.mnem));
    }
    return o;
}

string Database::xrefText(uint64_t a, bool code) const {
    auto it = xrefs.find(a); if (it == xrefs.end()) return "";
    string r; int n = 0;
    for (auto& x : it->second) {
        bool isCode = (x.type == 'p' || x.type == 'j');
        if (isCode != code) continue;
        if (n++) r += ", ";
        r += funcRel(x.from) + (x.from < a ? "\xE2\x86\x91" : "\xE2\x86\x93") + x.type;
    }
    return r;
}
std::vector<string> Database::xrefsTo(uint64_t a) const {
    std::vector<string> out; auto it = xrefs.find(a); if (it == xrefs.end()) return out;
    for (auto& x : it->second) { char b[24]; snprintf(b, 24, "%016llX", (unsigned long long)x.from); out.push_back(string(1, x.type) + "\x01" + b + "\x01" + funcRel(x.from)); }
    return out;
}

std::vector<string> Database::disasm(uint64_t addr, int count) const {
    std::vector<string> out; const char S1 = '\x01';
    for (int k = 0; k < count; k++) {
        uint64_t a = addr + 4ULL * k; const Section* sec = sectionAt(a); uint32_t w = 0;
        if (!sec || !readMem(a, &w, 4)) break;
        char ab[24]; snprintf(ab, 24, "%016llX", (unsigned long long)a);
        char bb[16]; const uint8_t* p = (const uint8_t*)&w; snprintf(bb, 16, "%02X %02X %02X %02X", p[0], p[1], p[2], p[3]);
        string mnem, ops, comment, fn, lbl;
        auto nm = names.find(a); if (nm != names.end()) lbl = nm->second;
        if (funcs.count(a)) fn = lbl.empty() ? "sub_" + hex(a) : lbl;
        if (sec->exec()) {
            Insn in = a64_decode(a, w); mnem = in.mnem; ops = resolveOps(in);
            auto pt = pairTarget.find(a + 0);
            if (a >= 4) { auto pp = pairTarget.find(a); if (pp != pairTarget.end() && in.mnem != "ADRP") {   // follow-up insn of ADRP pair
                string nmx = nameAt(pp->second); uint32_t imm = 0;
                if (in.mnem == "ADD") { size_t q = ops.rfind('#'); if (q != string::npos) ops.replace(q, string::npos, "#" + nmx + "@PAGEOFF"); }
                else { size_t q = ops.rfind(",#"); if (q != string::npos) { size_t e = ops.find(']', q); ops.replace(q, e == string::npos ? string::npos : e - q, ",#" + nmx + "@PAGEOFF"); }
                       else { size_t q2 = ops.rfind('['); size_t e = ops.find(']', q2); if (q2 != string::npos && e != string::npos) ops.insert(e, ",#" + nmx + "@PAGEOFF"); } }
                (void)imm; (void)pt; } }
            if (in.hasTarget) { auto s = strings.find(in.target); if (s != strings.end()) comment = "\"" + s->second.substr(0, 60) + "\""; }
            auto pp = pairTarget.find(a);
            if (pp != pairTarget.end() && in.mnem != "ADRP") { auto s = strings.find(pp->second); if (s != strings.end()) comment = "\"" + s->second.substr(0, 60) + "\""; }
        } else { char o[24]; snprintf(o, 24, "0x%08X", w); mnem = "DCD"; ops = o; }
        string rec = sec->name + S1 + ab + S1 + bb + S1 + fn + S1 + lbl + S1 + xrefText(a, true) + S1 + xrefText(a, false) + S1 + mnem + S1 + ops + S1 + comment;
        out.push_back(rec);
    }
    return out;
}
