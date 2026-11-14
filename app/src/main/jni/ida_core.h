#pragma once
// IDA-style AArch64 analysis core. Pure C++17, no third-party deps.
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <set>

#define TG "\x02"   // branch/data target placeholder inside Insn::ops

enum InsnKind { K_NORMAL=0, K_CALL=1, K_JUMP=2, K_CJUMP=3, K_RET=4, K_IJUMP=5, K_ADDR=6, K_LIT=7, K_ICALL=8 };

struct Insn {
    uint64_t addr = 0;
    uint32_t raw = 0;
    std::string mnem, ops;      // ops contains TG where a target name goes
    uint64_t target = 0;
    bool hasTarget = false;
    int kind = K_NORMAL;
};

Insn a64_decode(uint64_t pc, uint32_t w);

// Compact Itanium demangler; "" when the name is not demanglable.
std::string cxxDemangle(const std::string& mangled);

struct Section {
    std::string name;
    uint64_t addr = 0, size = 0, foff = 0, flags = 0;
    uint32_t type = 0, link = 0, info = 0;
    uint64_t entsize = 0;
    bool exec()  const { return flags & 4; }
    bool write() const { return flags & 1; }
    bool alloc() const { return flags & 2; }
};
struct Region { uint64_t addr, memsz, foff, filesz; uint32_t flags; };
struct Symbol { std::string name; uint64_t addr = 0, size = 0; int type = 0, bind = 0, shndx = 0; bool dyn = false; };
struct Xref   { uint64_t from; char type; bool operator==(const Xref& o) const { return from == o.from && type == o.type; } };   // p=call j=jump o=offset r=read w=write

class Database {
public:
    std::string path;
    std::vector<uint8_t> file;
    uint16_t machine = 0;
    uint64_t entry = 0;
    std::vector<Section> secs;
    std::vector<Region> regions;
    std::vector<Symbol> syms;
    std::map<uint64_t, std::string> names;       // every named address
    std::set<uint64_t> funcs;                    // function starts
    std::set<uint64_t> labels;                   // loc_ targets
    std::map<uint64_t, std::vector<Xref>> xrefs; // target -> sources
    std::map<uint64_t, std::string> strings;     // addr -> text
    std::map<uint64_t, uint64_t> pairTarget;     // ADRP addr / follow-up addr -> full data target
    std::vector<std::string> imports, exports;

    bool load(const std::string& p, std::string& err);
    void analyze();

    // incremental analysis state (live analysis + snapshots)
    bool stage1Done = false, sweepDone = false, strDone = false, namedDone = false, snapLoaded = false;
    size_t sweepSec = (size_t)-1, strSec = (size_t)-1;
    uint64_t sweepOff = 0, strOff = 0, strSt = 0, strOk = 1;
    // incremental naming stage: 0=strings 1=funcs 2=labels 3=xref-targets 4=pair-targets 5=xref-sort
    int nameStage = 0;
    uint64_t nameCursor = 0;                     // resume key (addr) within the current stage
    uint64_t sweepDoneU = 0, sweepTotalU = 0, strDoneU = 0, strTotalU = 0;
    bool hasPend = false; uint64_t pendAddr = 0, pendPage = 0; uint32_t pendRd = 0;
    std::set<std::string> takenNames;
    std::vector<size_t> sweepList, strList;
    std::vector<uint8_t> chunkBuf;
    uint64_t savedCursor = 0, savedHex = 0;

    void buildWorklists();
    void analyzeStage1();
    int analyzeStep(int budget);                 // 1 = more work, 0 = done
    bool analysisDone() const { return namedDone; }
    bool saveSnapshot(const std::string& p, std::string& err);
    bool loadSnapshot(const std::string& p, std::string& err);

    bool readMem(uint64_t addr, void* dst, size_t n) const;
    const Section* sectionAt(uint64_t a) const;
    std::string nameAt(uint64_t a) const;        // name or 0xHEX
    std::string funcRel(uint64_t a) const;       // sub_1000+C
    bool funcContaining(uint64_t a, uint64_t& start, uint64_t& end) const;
    uint64_t lookup(const std::string& name) const; // 0 if not found
    std::vector<std::string> pseudo(uint64_t fnAddr);
    std::string makeSig(uint64_t fnAddr);

    // records: sec \1 addr \1 bytes \1 funcName \1 label \1 codeXref \1 dataXref \1 mnem \1 ops \1 comment
    std::vector<std::string> disasm(uint64_t addr, int count) const;
    std::vector<std::string> xrefsTo(uint64_t addr) const;
private:
    std::string targetName(uint64_t t, const std::string& mnem) const;
    std::string resolveOps(const Insn& in) const;
    std::string xrefText(uint64_t a, bool code) const;
    std::map<uint64_t, std::string> gotNames;
    void addXref(uint64_t to, uint64_t from, char t);
    bool regionCovers(uint64_t a, uint64_t n) const;
    void sweepUnits(int budget);
    void stringUnits(int budget);
    void nameUnits(int budget);
    void processSweepWord(const Section& sec, uint64_t a, uint32_t w);
    void resolvePair(uint64_t a, uint64_t page, uint32_t rd, uint32_t w2);
    void addName(uint64_t a, const std::string& n);
};
