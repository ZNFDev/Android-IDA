#include "../jni/ida_core.h"
#include <cstdio>
#include <cstdlib>
int main(int c,char**v){ Database d; std::string e; if(!d.load(v[1],e)){puts(e.c_str());return 1;} d.analyze();
 printf("funcs=%zu names=%zu strings=%zu imports=%zu exports=%zu\n",d.funcs.size(),d.names.size(),d.strings.size(),d.imports.size(),d.exports.size());
 uint64_t a = c>2? strtoull(v[2],0,16): (d.funcs.size()? *d.funcs.begin():0); int n=c>3?atoi(v[3]):40;
 for(auto&r:d.disasm(a,n)){ std::vector<std::string> f; std::string cur; for(char ch:r){ if(ch=='\x01'){f.push_back(cur);cur.clear();} else cur+=ch;} f.push_back(cur);
  if(!f[3].empty()) printf("%s:%s ; ===== S U B R O U T I N E =====\n",f[0].c_str(),f[1].c_str());
  if(!f[4].empty()) printf("%s:%s %-38s%s%s\n",f[0].c_str(),f[1].c_str(),f[4].c_str(),f[5].empty()?"":"; CODE XREF: ",f[5].c_str());
  if(!f[6].empty()) printf("%s:%s %-38s; DATA XREF: %s\n",f[0].c_str(),f[1].c_str(),"",f[6].c_str());
  printf("%s:%s                 %-16s%s%s%s\n",f[0].c_str(),f[1].c_str(),f[7].c_str(),f[8].c_str(),f[9].empty()?"":"   ; ",f[9].c_str()); } }
