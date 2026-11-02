#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "yuwheel.h"

int systemf(const char *fmt, ...){

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if( n < 0 ){ return -1; }

    char buf[n+1];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return system(buf);
}

void super_fucking_srand(void){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    srand((unsigned)(time(NULL) ^ ts.tv_nsec ^ (getpid() << 10)));
}

const char *locate(int depth){
    static char exe_real[1024];
    ssize_t n = readlink("/proc/self/exe", exe_real, sizeof(exe_real) - 1);
    if (n <= 0){ return NULL; }
    exe_real[n] = '\0';

    if(depth < 0){ return NULL; }

    for(int i = 0; i < depth; i++){
        char *slash = strrchr(exe_real, '/');
        if(!slash){ return NULL; }
        if(slash == exe_real){ return NULL; }
        *slash = '\0'; 
    }
    return exe_real;
}

const char *timestamp(void){
    static char stp[20];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(stp, 20, "%Y-%m-%d %H:%M:%S", &tmv);   /* 19 bytes + '\0' == 20 bytes */
    return stp;
}

const char *base_name(const char *path){
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

char *trim(char *s){
    while(*s == ' ' || *s == '\n' || *s == '\t' || *s == '\r'){ s++; }
    size_t n = strlen(s);
    while(n > 0){
        char c = s[n - 1];
        if(c != ' ' && c != '\n' && c != '\t' && c != '\r'){ break; }
        s[--n] = '\0';
    }
    return s;
}