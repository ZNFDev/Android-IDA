// Host equivalence test: chunked incremental analysis + snapshots must produce
// exactly the same final Database state as the monolithic analyze().
#include "ida_core.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
using std::string;

static int g_fail = 0;
static void eq(bool ok, const char* what) {
    if (!ok) { printf("FAIL: %s\n", what); g_fail++; }
    else printf("ok: %s\n", what);
}

static string stateDump(const Database& d) {
    string r;
    char b[64];
    snprintf(b, sizeof b, "F%zu", d.funcs.size()); r += b;
    snprintf(b, sizeof b, "L%zu", d.labels.size()); r += b;
    snprintf(b, sizeof b, "N%zu", d.names.size()); r += b;
    snprintf(b, sizeof b, "S%zu", d.strings.size()); r += b;
    snprintf(b, sizeof b, "X%zu", d.xrefs.size()); r += b;
    snprintf(b, sizeof b, "P%zu", d.pairTarget.size()); r += b;
    snprintf(b, sizeof b, "I%zu", d.imports.size()); r += b;
    snprintf(b, sizeof b, "E%zu", d.exports.size()); r += b;
    return r;
}

static bool stateEqual(const Database& a, const Database& b, string& why) {
    if (a.funcs != b.funcs) { why = "funcs"; return false; }
    if (a.labels != b.labels) { why = "labels"; return false; }
    if (a.names != b.names) { why = "names"; return false; }
    if (a.strings != b.strings) { why = "strings"; return false; }
    if (a.pairTarget != b.pairTarget) { why = "pairTarget"; return false; }
    if (a.imports != b.imports) { why = "imports"; return false; }
    if (a.exports != b.exports) { why = "exports"; return false; }
    if (a.xrefs.size() != b.xrefs.size()) { why = "xrefs size"; return false; }
    for (auto& kv : a.xrefs) {
        auto it = b.xrefs.find(kv.first);
        if (it == b.xrefs.end()) { why = "xrefs target missing"; return false; }
        if (kv.second != it->second) { why = "xrefs vector"; return false; }
    }
    return true;
}

static void progressLine(const Database& d, const char* tag) {
    uint64_t tot = d.sweepTotalU + d.strTotalU;
    int pct = tot ? (int)((d.sweepDoneU + d.strDoneU) * 100 / tot) : 0;
    const char* st = !d.sweepDone ? "sweep" : (!d.strDone ? "strings" : (d.namedDone ? "done" : "naming"));
    string sec;
    if (!d.sweepDone && d.sweepSec < d.sweepList.size()) sec = d.secs[d.sweepList[d.sweepSec]].name;
    else if (!d.strDone && d.strSec < d.strList.size()) sec = d.secs[d.strList[d.strSec]].name;
    printf("%s: %3d%% stage=%-7s sec=%-14s funcs=%zu strs=%zu\n", tag, pct, st, sec.c_str(), d.funcs.size(), d.strings.size());
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: live_cli <elf>\n"); return 2; }
    string path = argv[1];

    // reference: monolithic analyze()
    Database ref; string err;
    if (!ref.load(path, err)) { printf("load failed: %s\n", err.c_str()); return 1; }
    ref.analyze();
    printf("reference: %s\n", stateDump(ref).c_str());

    // live: chunked analyzeStep
    Database d;
    if (!d.load(path, err)) { printf("load failed: %s\n", err.c_str()); return 1; }
    d.buildWorklists();
    printf("worklists: sweep=%zu/%llu words, strings=%zu/%llu bytes\n",
           d.sweepList.size(), (unsigned long long)d.sweepTotalU, d.strList.size(), (unsigned long long)d.strTotalU);
    int steps = 0;
    while (d.analyzeStep(997)) { if (++steps % 40 == 0) progressLine(d, "live"); }
    progressLine(d, "live");
    printf("live: %d step calls, %s\n", steps, stateDump(d).c_str());
    string why;
    eq(d.analysisDone(), "analysisDone after steps");
    eq(stateEqual(ref, d, why), string("chunked == monolithic (diff: " + why + ")").c_str());

    // disasm comparison over every function start
    size_t diserr = 0, disn = 0;
    for (uint64_t f : ref.funcs) {
        std::vector<string> r1 = ref.disasm(f, 40), r2 = d.disasm(f, 40);
        disn++;
        if (r1 != r2) { diserr++; if (diserr <= 3) printf("disasm differs at %llX\n", (unsigned long long)f); }
    }
    eq(diserr == 0, string("disasm over " + std::to_string(disn) + " functions").c_str());

    // snapshot: partial analysis -> save -> fresh load -> resume -> finish
    string snap = path + ".idasnap";
    Database p1;
    if (!p1.load(path, err)) { printf("load failed: %s\n", err.c_str()); return 1; }
    p1.buildWorklists();
    p1.analyzeStage1();
    for (int i = 0; i < 7; i++) p1.analyzeStep(997);
    string serr;
    p1.savedCursor = 0x1234; p1.savedHex = 0xABCD;
    eq(p1.saveSnapshot(snap, serr), string("saveSnapshot (" + serr + ")").c_str());
    eq(!p1.analysisDone(), "partial db not done");

    Database r1;
    if (!r1.load(path, err)) { printf("load failed: %s\n", err.c_str()); return 1; }
    r1.buildWorklists();
    eq(r1.loadSnapshot(snap, serr), string("loadSnapshot (" + serr + ")").c_str());
    eq(r1.snapLoaded, "snapLoaded flag");
    eq(r1.savedCursor == 0x1234 && r1.savedHex == 0xABCD, "saved cursor/hex roundtrip");
    int rsteps = 0;
    while (r1.analyzeStep(997)) rsteps++;
    eq(r1.analysisDone(), "resumed db completes");
    eq(stateEqual(ref, r1, why), string("resumed == monolithic (diff: " + why + ")").c_str());
    printf("resume used %d step calls\n", rsteps);

    // already-done snapshot must complete immediately
    eq(r1.saveSnapshot(snap, serr), "save complete db");
    Database r2;
    if (!r2.load(path, err)) { printf("load failed: %s\n", err.c_str()); return 1; }
    r2.buildWorklists();
    eq(r2.loadSnapshot(snap, serr), "load complete db");
    eq(r2.analyzeStep(997) == 0, "done db needs no steps");

    // corrupt snapshot must be rejected and removed
    {
        FILE* fp = fopen(snap.c_str(), "r+b");
        if (fp) { fseek(fp, 40, SEEK_SET); fputc(0xEE, fp); fclose(fp); }
        Database r3;
        if (!r3.load(path, err)) { printf("load failed: %s\n", err.c_str()); return 1; }
        r3.buildWorklists();
        bool ok = r3.loadSnapshot(snap, serr);
        eq(!ok, "corrupt snapshot rejected");
        FILE* ck = fopen(snap.c_str(), "rb");
        eq(ck == nullptr, "corrupt snapshot file removed");
        if (ck) fclose(ck);
    }
    remove(snap.c_str());

    printf(g_fail ? "\n%d FAILURES\n" : "\nALL TESTS PASSED\n", g_fail);
    return g_fail ? 1 : 0;
}
