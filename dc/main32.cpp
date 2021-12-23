#include "unicorn/unicorn.h"
#include <stdio.h>
#include <string.h>
#include <cmath>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <sstream>
#include <fstream>
#include <utility>
#include <set>
#include "android/log.h"

using namespace std;

// setprop use_libanduni 1
// setprop anduni_method "int com.xtgo.nbtest.MainActivity.stringFromJNI(int, int, int)"
extern "C" int android_jni_call(uint32_t* method, uint32_t* args, uint32_t argsize, void* self, void* result, const char* shorty, int isStatic, const void* func, const char* method_name)
{
    __android_log_print(6, "libanduni", "call method %s", method_name);
    // check func entrypoint and method_name
    if(1 && method_name && func && shorty && args) {
        __android_log_print(6, "libanduni", "call method %s[%p]{%s}", method_name, func, shorty);
    }
    return -1;
}