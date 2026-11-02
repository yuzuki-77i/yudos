#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "shared.h"

/* const */

const uint8_t broadmac[6] = {0xff, 0xff,0xff, 0xff, 0xff, 0xff};
const uint8_t zeromac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const int hop_2g[13] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
const int hop_5g[9] = {36, 40, 44, 48, 149, 153, 157, 161, 165};
const char *hop_names[4] = {"off", "2g", "5g", "all"};

double getnsec(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

char *mac2str(const uint8_t *mac, char *buf){
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return buf;
}
