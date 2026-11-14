#include "ida_core.h"
#include <cstdio>
#include <cstring>
#include <string>
using std::string;

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: dbg_names <elf>\n"); return 2; }
    string path = argv[1], err, snap = path + ".dbg";

    Database ref; ref.load(path, err); ref.analyze();

    Database p1; p1.load(path, err); p1.buildWorklists(); p1.analyzeStage1();
    for (int i = 0; i < 7; i++) p1.analyzeStep(997);
    p1.saveSnapshot(snap, err);

    Database r1; r1.load(path, err); r1.buildWorklists(); r1.loadSnapshot(snap, err);
    printf("after restore: stage1=%d sweep=%d str=%d named=%d sweepSec=%zu/%llu strSec=%zu/%llu strings=%zu\n",
           (int)r1.stage1Done, (int)r1.sweepDone, (int)r1.strDone, (int)r1.namedDone,
           r1.sweepSec, (unsigned long long)r1.sweepOff, r1.strSec, (unsigned long long)r1.strOff, r1.strings.size());
    while (r1.analyzeStep(997)) {}
    printf("after resume: strings=%zu strSec=%zu strOff=%llu strDone=%d\n", r1.strings.size(),
           r1.strSec, (unsigned long long)r1.strOff, (int)r1.strDone);

    auto ai = ref.names.begin(); auto bi = r1.names.begin();
    int shown = 0;
    while (ai != ref.names.end() || bi != r1.names.end()) {
        bool aEnd = ai == ref.names.end(), bEnd = bi == r1.names.end();
        if (!aEnd && !bEnd && ai->first == bi->first) {
            if (ai->second != bi->second) {
                printf("addr %llX ref=%s resumed=%s\n", (unsigned long long)ai->first, ai->second.c_str(), bi->second.c_str());
                if (++shown >= 10) break;
            }
            ++ai; ++bi;
        } else if (aEnd || (!bEnd && bi->first < ai->first)) {
            printf("addr %llX ref=MISSING resumed=%s\n", (unsigned long long)bi->first, bi->second.c_str());
            if (++shown >= 10) break;
            ++bi;
        } else {
            printf("addr %llX ref=%s resumed=MISSING\n", (unsigned long long)ai->first, ai->second.c_str());
            if (++shown >= 10) break;
            ++ai;
        }
    }
    if (!shown) printf("no name differences?! sizes ref=%zu r1=%zu\n", ref.names.size(), r1.names.size());
    auto si = ref.strings.begin(); auto sj = r1.strings.begin();
    int ss = 0;
    while (si != ref.strings.end() && sj != r1.strings.end()) {
        if (si->first != sj->first || si->second != sj->second) {
            printf("string %llX ref=[%s] r1=[%s]\n", (unsigned long long)si->first, si->second.c_str(), sj->second.c_str());
            if (++ss >= 10) break;
        }
        ++si; ++sj;
    }
    if (ref.strings.size() != r1.strings.size()) printf("string count ref=%zu r1=%zu\n", ref.strings.size(), r1.strings.size());
    remove(snap.c_str());
    return 0;
}
