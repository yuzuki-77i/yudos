#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>

#define DEAUTH_FRAME_LEN 34
#define CLIENTS_MAX_RECORD 1024
#define APS_MAX_RECORD 256

/* typedef */
typedef struct {
    uint8_t mac[6];
    uint8_t ap_bssid[6];
    char lastseen[20];
} client_t;

typedef struct {
    uint8_t bssid[6];
    int ch;
    char ssid[33];
    char lastseen[20];
} ap_info_t;

typedef enum{VT_STR, VT_INT, VT_MAC, VT_ENUM} vtype;

typedef struct {
    vtype type;
    size_t cap;
    union{
        char *s;
        int *i;
        uint8_t *mac;
    } as;
    const char **names;
} value_t;

typedef struct {
    const char *key;
    value_t value;
} pair_t;

typedef int (*run_fn)(void);
typedef struct {
    const char *path;
    const char *desc;
    run_fn run;
    const char * const * reqr;
} module_t;

/* const */
extern const uint8_t broadmac[6];
extern const uint8_t zeromac[6];
extern const int hop_2g[13];
extern const int hop_5g[9];
extern const char *hop_names[4];
extern const char *tipslib[];
extern const int n_tips;
extern const char *version;

enum {HOP_OFF = 0, HOP_2G, HOP_5G, HOP_ALL};

/*global options var*/

extern char phy[32];
extern char mon_iface[64];
extern char module[64];
extern int ch;
extern int hop;
extern uint8_t target[6];
extern uint8_t bssid[6];

/* global storge var */

extern char phy_list[32][32];
extern char driver_list[32][32];
extern ap_info_t ap_list[APS_MAX_RECORD];
extern client_t client_list[CLIENTS_MAX_RECORD];
extern int n_client;
extern int n_ap;
extern volatile sig_atomic_t running;

/* wheel functions */

double getnsec(void);
char *mac2str(const uint8_t *mac, char *buf);
