#include "../jni/ida_core.h"
#include <cstdio>
int main(){ unsigned w; unsigned long long pc=0x1000; char line[64];
 while(fgets(line,64,stdin)){ sscanf(line,"%x",&w); Insn i=a64_decode(pc,w); std::string o=i.ops; for(auto&c:o) if(c=='\x02') c='@';
  printf("%08x\t%s\t%s\t%d\t%llx\n",w,i.mnem.c_str(),o.c_str(),i.kind,(unsigned long long)i.target); pc+=4; } }
