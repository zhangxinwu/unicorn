#include <stdio.h>
#include <string.h>
#include <cmath>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <utility>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

pair<uint64_t, uint64_t> get_mem_range(int pid, uint64_t ptr) {
    stringstream ss;
    ss << "/proc/" << pid << "/maps";
    fstream sf(ss.str().c_str(), sf.in);
    string line;
    uint64_t st, ed;
    pair<uint64_t, uint64_t> pi(0, 0);
    while(std::getline(sf, line))
    {
        cout << line << endl;
        sscanf(line.c_str(), "%llx-%llx ", &st, &ed);
        cout << hex << st << " " << ed << endl;
        if (st <= ptr && ptr <= ed)
        {
            pi.first = st;
            pi.second = ed;
        }
    }
    cout << hex << ptr << endl;
    return pi;
}
int main() {
    printf("");
    int pid = getpid();
    auto p = get_mem_range(pid, (uint64_t)printf);
    cout << hex << p.first << " " << p.second << endl;
    return 0;
}