#include <jni.h>
#include "ida_core.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>

// Change this if you rename the Java package/class.
static const char* kClass = "com/znfdev/ida/NativeBridge";
static std::string g_err;
static std::mutex g_mutex;   // worker thread + UI thread share one Database
static std::map<jlong, std::shared_ptr<Database>> g_dbs;
static jlong g_nextHandle = 1;

// Returns a shared copy; stale handles yield null and callers return empty results.
static std::shared_ptr<Database> DB(jlong h) {
    std::map<jlong, std::shared_ptr<Database>>::iterator i = g_dbs.find(h);
    return i == g_dbs.end() ? std::shared_ptr<Database>() : i->second;
}
static jstring js(JNIEnv* e, const std::string& s) { return e->NewStringUTF(s.c_str()); }
static jobjectArray arr(JNIEnv* e, const std::vector<std::string>& v) {
    jobjectArray a = e->NewObjectArray((jsize)v.size(), e->FindClass("java/lang/String"), nullptr);
    for (size_t i = 0; i < v.size(); i++) { jstring s = js(e, v[i]); e->SetObjectArrayElement(a, (jsize)i, s); e->DeleteLocalRef(s); }
    return a;
}
static std::string hx(uint64_t v) { char b[24]; snprintf(b, 24, "%016llX", (unsigned long long)v); return b; }
static std::string cs(JNIEnv* e, jstring s) { const char* c = e->GetStringUTFChars(s, nullptr); std::string r = c; e->ReleaseStringUTFChars(s, c); return r; }

static jlong n_open(JNIEnv* e, jclass, jstring path) {
    std::lock_guard<std::mutex> lk(g_mutex);
    Database* d = new Database(); std::string err;
    if (!d->load(cs(e, path), err)) { g_err = err; delete d; return 0; }
    d->analyze();
    jlong h = g_nextHandle++;
    g_dbs[h] = std::shared_ptr<Database>(d);
    return h;
}
static jstring n_error(JNIEnv* e, jclass) { std::lock_guard<std::mutex> lk(g_mutex); return js(e, g_err); }
static void n_close(JNIEnv*, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_dbs.erase(h);   // in-flight holders keep the object alive until their call returns
}
static jlong n_entry(JNIEnv*, jclass, jlong h) { std::lock_guard<std::mutex> lk(g_mutex); std::shared_ptr<Database> d = DB(h); if (!d) return 0; return (jlong)d->entry; }
static jint n_machine(JNIEnv*, jclass, jlong h) { std::lock_guard<std::mutex> lk(g_mutex); std::shared_ptr<Database> d = DB(h); if (!d) return 0; return d->machine; }

static jobjectArray n_sections(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    std::vector<std::string> v; const char S = '\x01';
    for (auto& s : d->secs) if (!s.name.empty()) v.push_back(s.name + S + hx(s.addr) + S + hx(s.addr + s.size) + S + std::to_string(s.flags) + S + std::to_string(s.foff) + S + std::to_string(s.type));
    return arr(e, v);
}
static jobjectArray n_functions(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    std::vector<std::string> v; const char S = '\x01';
    for (uint64_t f : d->funcs) { uint64_t st, en; if (!d->funcContaining(f, st, en)) continue;
        const Section* sc = d->sectionAt(f); v.push_back(d->nameAt(f) + S + hx(f) + S + hx(en - f) + S + (sc ? sc->name : "")); }
    return arr(e, v);
}
static jobjectArray n_names(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    std::vector<std::string> v; const char S = '\x01';
    for (auto& kv : d->names) { const Section* sc = d->sectionAt(kv.first);
        std::string dem = cxxDemangle(kv.second);
        v.push_back(kv.second + S + hx(kv.first) + S + (sc ? sc->name : "") + S + dem); }
    return arr(e, v);
}
static jobjectArray n_strings(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    std::vector<std::string> v; const char S = '\x01';
    for (auto& kv : d->strings) { const Section* sc = d->sectionAt(kv.first); v.push_back(hx(kv.first) + S + (sc ? sc->name : "") + S + d->nameAt(kv.first) + S + kv.second); }
    return arr(e, v);
}
static jobjectArray n_imports(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    return arr(e, d->imports);
}
static jobjectArray n_exports(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    std::vector<std::string> v; const char S = '\x01';
    for (auto& n : d->exports) { uint64_t a = d->lookup(n); v.push_back(n + S + hx(a) + S + cxxDemangle(n)); } return arr(e, v);
}
static jobjectArray n_disasm(JNIEnv* e, jclass, jlong h, jlong addr, jint count) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    return arr(e, d->disasm((uint64_t)addr, count));
}
static jobjectArray n_xrefs(JNIEnv* e, jclass, jlong h, jlong addr) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    return arr(e, d->xrefsTo((uint64_t)addr));
}
static jobjectArray n_pseudo(JNIEnv* e, jclass, jlong h, jlong addr) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return arr(e, std::vector<std::string>());
    return arr(e, d->pseudo((uint64_t)addr));
}
static jstring n_sig(JNIEnv* e, jclass, jlong h, jlong addr) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return js(e, "");
    return js(e, d->makeSig((uint64_t)addr));
}
static jbyteArray n_read(JNIEnv* e, jclass, jlong h, jlong addr, jint len) {
    std::lock_guard<std::mutex> lk(g_mutex);
    jbyteArray r = e->NewByteArray(len < 0 ? 0 : len);
    if (len <= 0) return r;
    std::shared_ptr<Database> d = DB(h); if (!d) { return r; }
    std::vector<uint8_t> b(len); if (!d->readMem((uint64_t)addr, b.data(), len)) { for (int i = 0; i < len; i++) if (!d->readMem((uint64_t)addr + i, &b[i], 1)) b[i] = 0; }
    e->SetByteArrayRegion(r, 0, len, (const jbyte*)b.data()); return r;
}
static jstring n_nameAt(JNIEnv* e, jclass, jlong h, jlong addr) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return js(e, "");
    return js(e, d->nameAt((uint64_t)addr));
}
static jlong n_lookup(JNIEnv* e, jclass, jlong h, jstring name) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return 0;
    return (jlong)d->lookup(cs(e, name));
}
static jlong n_funcStart(JNIEnv*, jclass, jlong h, jlong addr) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return 0;
    uint64_t s, en; return d->funcContaining((uint64_t)addr, s, en) ? (jlong)s : 0;
}

// live analysis
static jlong n_openLive(JNIEnv* e, jclass, jstring path, jstring snap) {
    std::lock_guard<std::mutex> lk(g_mutex);
    Database* d = new Database(); std::string err;
    if (!d->load(cs(e, path), err)) { g_err = err; delete d; return 0; }
    d->buildWorklists();
    std::string sp = cs(e, snap);
    if (!sp.empty()) { std::string e2; d->loadSnapshot(sp, e2); }   // failure -> fresh analysis
    if (!d->stage1Done) d->analyzeStage1();
    jlong h = g_nextHandle++;
    g_dbs[h] = std::shared_ptr<Database>(d);
    return h;
}
static jboolean n_resumed(JNIEnv*, jclass, jlong h) { std::lock_guard<std::mutex> lk(g_mutex); std::shared_ptr<Database> d = DB(h); if (!d) return JNI_FALSE; return d->snapLoaded ? JNI_TRUE : JNI_FALSE; }
static jint n_step(JNIEnv*, jclass, jlong h, jint budget) { std::lock_guard<std::mutex> lk(g_mutex); std::shared_ptr<Database> d = DB(h); if (!d) return 0; return d->analyzeStep(budget); }
static jstring n_liveState(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h);
    if (!d) return js(e, std::string("1") + '\x01' + '3' + '\x01' + '0' + '\x01' + '0' + '\x01' + '0' + '\x01' + '\x01' + '0');
    bool done = d->analysisDone();
    int stage = done ? 3 : (!d->sweepDone ? 0 : (!d->strDone ? 1 : 2));
    uint64_t tot = d->sweepTotalU + d->strTotalU;
    int pct = tot ? (int)((d->sweepDoneU + d->strDoneU) * 100 / tot) : 0;
    std::string sec; uint64_t off = 0;
    if (!d->sweepDone && d->sweepSec < d->sweepList.size()) { sec = d->secs[d->sweepList[d->sweepSec]].name; off = d->sweepOff; }
    else if (!d->strDone && d->strSec < d->strList.size()) { sec = d->secs[d->strList[d->strSec]].name; off = d->strOff; }
    const char S = '\x01';
    std::string r = std::to_string(done ? 1 : 0) + S + std::to_string(stage) + S + std::to_string(pct) + S +
                    std::to_string(d->funcs.size()) + S + std::to_string(d->strings.size()) + S + sec + S + hx(off);
    return js(e, r);
}
static jstring n_savedPos(JNIEnv* e, jclass, jlong h) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return js(e, "");
    return js(e, hx(d->savedCursor) + "\x01" + hx(d->savedHex));
}
static jstring n_save(JNIEnv* e, jclass, jlong h, jstring p, jlong cur, jlong hxv) {
    std::lock_guard<std::mutex> lk(g_mutex);
    std::shared_ptr<Database> d = DB(h); if (!d) return js(e, "no database");
    d->savedCursor = (uint64_t)cur; d->savedHex = (uint64_t)hxv;
    std::string err;
    if (!d->saveSnapshot(cs(e, p), err)) return js(e, err);
    return js(e, "");
}

jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* e; if (vm->GetEnv((void**)&e, JNI_VERSION_1_6) != JNI_OK) return -1;
    jclass c = e->FindClass(kClass); if (!c) return -1;
    static const JNINativeMethod m[] = {
        {"open", "(Ljava/lang/String;)J", (void*)n_open}, {"lastError", "()Ljava/lang/String;", (void*)n_error},
        {"close", "(J)V", (void*)n_close}, {"entry", "(J)J", (void*)n_entry}, {"machine", "(J)I", (void*)n_machine},
        {"sections", "(J)[Ljava/lang/String;", (void*)n_sections}, {"functions", "(J)[Ljava/lang/String;", (void*)n_functions},
        {"names", "(J)[Ljava/lang/String;", (void*)n_names}, {"strings", "(J)[Ljava/lang/String;", (void*)n_strings},
        {"imports", "(J)[Ljava/lang/String;", (void*)n_imports}, {"exports", "(J)[Ljava/lang/String;", (void*)n_exports},
        {"disasm", "(JJI)[Ljava/lang/String;", (void*)n_disasm}, {"xrefsTo", "(JJ)[Ljava/lang/String;", (void*)n_xrefs},
        {"pseudo", "(JJ)[Ljava/lang/String;", (void*)n_pseudo},
        {"sig", "(JJ)Ljava/lang/String;", (void*)n_sig},
        {"readBytes", "(JJI)[B", (void*)n_read}, {"nameAt", "(JJ)Ljava/lang/String;", (void*)n_nameAt},
        {"lookup", "(JLjava/lang/String;)J", (void*)n_lookup}, {"funcStart", "(JJ)J", (void*)n_funcStart},
        {"openLive", "(Ljava/lang/String;Ljava/lang/String;)J", (void*)n_openLive},
        {"resumed", "(J)Z", (void*)n_resumed}, {"analyzeStep", "(JI)I", (void*)n_step},
        {"liveState", "(J)Ljava/lang/String;", (void*)n_liveState},
        {"saveState", "(JLjava/lang/String;JJ)Ljava/lang/String;", (void*)n_save},
        {"savedPos", "(J)Ljava/lang/String;", (void*)n_savedPos},
    };
    if (e->RegisterNatives(c, m, sizeof(m) / sizeof(m[0])) < 0) return -1;
    return JNI_VERSION_1_6;
}
