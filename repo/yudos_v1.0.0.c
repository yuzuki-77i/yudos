#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <json-c/json.h>

#include "../lib/yutheme.h"
#include "../lib/yuwheel.h"
#include "../lib/network.h"
#include "../lib/shared.h"
#include "../lib/modules.h"

#define CONSOLE_MAX_ARGC 32
#define MODULE_REQ(...) ( (const char * const[]){__VA_ARGS__, NULL} )

/* const */
const char *version = "v1.0.0";
const char *tipslib[] = {
    #include "../assets/tipslib.txt"
};
const int n_tips = sizeof(tipslib)/sizeof(tipslib[0]);

/* global options var */

char phy[32];
char mon_iface[64];
char module[64];
int ch = 0;
int hop = HOP_ALL;
uint8_t target[6];
uint8_t bssid[6];

/* global storge var */

int g_argc = 0;
char **g_argv = NULL;

const char *proj_root = NULL;

pair_t options_dict[] = {
    {"phy", { .type = VT_STR, .cap = sizeof(phy), .as.s = phy}},
    {"mon_iface", { .type = VT_STR, .cap = sizeof(mon_iface), .as.s = mon_iface}},
    {"ch", { .type = VT_INT, .as.i = &ch}},
    {"bssid", { .type = VT_MAC, .cap = sizeof(bssid), .as.mac = bssid}},
    {"target", { .type = VT_MAC, .cap = sizeof(target), .as.mac = target}},
    {"hop", { .type = VT_ENUM, .cap = sizeof(hop), .as.i = &hop, .names = hop_names}}
};
#define N_OPTIONS ( sizeof(options_dict)/sizeof(options_dict[0]) )

char phy_list[32][32];
char driver_list[32][32];
ap_info_t ap_list[APS_MAX_RECORD];
client_t client_list[CLIENTS_MAX_RECORD];
int n_client = 0;
int n_ap = 0;
volatile sig_atomic_t running = 0;
volatile sig_atomic_t console_interrupted = 0;
volatile sig_atomic_t prompt_sigint = 0;
volatile sig_atomic_t console_done = 0;

int is_quiet_boot = 0;
char *exe_cmd = NULL;
char *resource_path = NULL;
char *init_phy = NULL;


static module_t modules_list[] = {
    {"probe/ap", "Scan nearby APs and get BSSID, SSID and channel", run_probe_ap, MODULE_REQ("mon_iface")},
    {"probe/client", "Scan clients connected with specific AP and get their MACs", run_probe_client, MODULE_REQ("mon_iface", "ch", "bssid")},
    {"probe/carpet", "Scan everything and fill discovered list", run_probe_carpet, MODULE_REQ("mon_iface")},
    {"attack/deauth/unicast/single", "Send DeAuth once to one client", run_attack_deauth_unicast_single, MODULE_REQ("mon_iface", "bssid", "target", "ch")},
    {"attack/deauth/unicast/flood", "DeAuth flood to one client", run_attack_deauth_unicast_flood, MODULE_REQ("mon_iface", "bssid", "target", "ch")},
    {"attack/deauth/broadcast/single", "Send DeAuth once to all clients of selected AP", run_attack_deauth_broadcast_single, MODULE_REQ("mon_iface", "ch", "bssid")},
    {"attack/deauth/broadcast/flood", "DeAuth flood to all clients of selected AP", run_attack_deauth_broadcast_flood, MODULE_REQ("mon_iface", "ch", "bssid")},
    {"attack/deauth/serial/single", "Unicast DeAuth once to all clients of selected AP at the same time", run_attack_deauth_serial_single, MODULE_REQ("mon_iface", "ch", "bssid")},
    {"attack/deauth/serial/flood", "Unicast DeAuth flood to all clients of selected AP at the same time", run_attack_deauth_serial_flood, MODULE_REQ("mon_iface", "ch", "bssid")},
    {"attack/deauth/roster/single", "Unicast DeAuth once to all clients in discovered list", run_attack_deauth_roster_single, MODULE_REQ("mon_iface")},
    {"attack/deauth/roster/flood", "Unicast DeAuth flood to all clients in discovered list", run_attack_deauth_roster_flood, MODULE_REQ("mon_iface")},
    {"attack/deauth/carpet/single", "Unicast DeAuth once to all clients visible", run_attack_deauth_carpet_single, MODULE_REQ("mon_iface")},
    {"attack/deauth/carpet/flood", "Unicast Deauth flood to all clients visible", run_attack_deauth_carpet_flood, MODULE_REQ("mon_iface")},
};

#define N_MODULES (sizeof(modules_list)/sizeof(modules_list[0]))

static struct option long_options[] = {
    {"resource", required_argument, NULL, 'r'},
    {"version", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {"quiet", no_argument, NULL, 'q'},
    {"execute", required_argument, NULL, 'x'},
    {"init-phy", required_argument, NULL, 'i'},
    {NULL, 0, NULL, 0},

};

static int parse_mac(const char *s, uint8_t *mac){
    unsigned b[6];
    if(sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6){ return -1; }
    for(int i = 0; i < 6; i++){ mac[i] = (uint8_t)b[i]; }
    return 0;
}

static int check_mac(const uint8_t *m){
    for(int i = 0; i < 6; i++){
        if(m[i]){ return 1;}
    }
    return 0;
}

static int check_one(const char *key){
    for(size_t i = 0; i < N_OPTIONS; i++){
        if(strcmp(options_dict[i].key, key) != 0){ continue; }

        int is_set = -2;
        value_t v = options_dict[i].value;
        switch(v.type){
            case VT_INT : is_set = (*v.as.i != 0); break; 
            case VT_STR : is_set = (v.as.s[0] != '\0'); break;
            case VT_MAC : is_set = check_mac(v.as.mac); break;
            case VT_ENUM : is_set = 1; break;
        }
        if(is_set == 0){ return -1; }    /*key exist but no value set*/
        return 0;       /*correctly set*/
    }
    return -2;      /*key not exist*/
}

__attribute__((unused))
static int check_set(const char *first, ...){
    va_list ap;
    va_start(ap, first);
    int rc = 0;

    for(const char *key = first; key != NULL; key = va_arg(ap, const char *)){
        int r = check_one(key);

        if(r == -1){ log_print("err", "Option '%s' not set", key); rc = -1; }
        else if(r == -2){ printf("there is no key called '%s'. if u see this, don't worry, it's caused by the stupid developer.\n", key); rc = -1; }
    }
    va_end(ap);
    return rc;
}

static int check_reqr(const char * const *keys){
    if(!keys){ return 0; }
    int rc = 0;

    for(size_t i = 0 ;keys[i] != NULL; i++){
        int r = check_one(keys[i]);
        if(r == -1){ log_print("err", "Option '%s' not set", keys[i]); rc = -1; }
        else if(r == -2){ printf("there is no key called '%s'. if u see this, don't worry, it's caused by the stupid developer.\n", keys[i]); rc = -1; }
    }
    return rc;
}

static int load_discovered(void){
    int rc = -2;

    if(!proj_root){ return rc; }

    char state_dir[strlen(proj_root) + strlen("/state") + 1];
    snprintf(state_dir, sizeof(state_dir), "%s/state", proj_root);
    if(access(state_dir, F_OK)){ if(mkdir(state_dir, 0755)){ perror("mkdir"); return rc; } }

    char ap_json[strlen(proj_root) + strlen("/state/ap.json") + 1];
    snprintf(ap_json, sizeof(ap_json), "%s/state/ap.json", proj_root);
    char client_json[strlen(proj_root) + strlen("/state/client.json") + 1];
    snprintf(client_json, sizeof(client_json), "%s/state/client.json", proj_root);

    FILE *f_ap = fopen(ap_json, "r");
    if(!f_ap){ log_print("warn", "Cannot open %s", ap_json); }
    else{
        char *line = NULL;
        size_t linecap = 0;
        ssize_t len;

        int invalid = 0;
        while((len = getline(&line, &linecap, f_ap)) != -1){
            if(n_ap >= APS_MAX_RECORD){ log_print("warn", "Too many APs (over %d), list truncated", APS_MAX_RECORD); rc -=1; break; }
            if(len == 0 || strspn(line, " \n\t\r") == (size_t)len){ continue; }
            struct json_object *obj = json_tokener_parse(line);
            if(!obj){ invalid++; continue; }

            struct json_object *bssid, *ch, *ssid, *lastseen;
            if(!json_object_object_get_ex(obj, "bssid", &bssid) || !json_object_object_get_ex(obj, "ch", &ch) || !json_object_object_get_ex(obj, "ssid", &ssid) || !json_object_object_get_ex(obj, "lastseen", &lastseen)){
                json_object_put(obj);
                invalid++;
                continue;
            }
            if(!json_object_is_type(bssid, json_type_string) || !json_object_is_type(ch, json_type_int) || !json_object_is_type(ssid, json_type_string) || !json_object_is_type(lastseen, json_type_string)){
                json_object_put(obj);
                invalid++;
                continue;
            }

            uint8_t b[6];
            if(parse_mac(json_object_get_string(bssid), b) < 0){ json_object_put(obj); invalid++; continue; }
            memcpy(ap_list[n_ap].bssid, b, 6);
            ap_list[n_ap].ch = json_object_get_int(ch);
            snprintf(ap_list[n_ap].ssid, sizeof(ap_list[n_ap].ssid), "%s", json_object_get_string(ssid));
            snprintf(ap_list[n_ap].lastseen, sizeof(ap_list[n_ap].lastseen), "%s", json_object_get_string(lastseen));

            json_object_put(obj);
            n_ap++;
        }

        if(invalid){ log_print("warn", "%d AP data skipped due to invalid JSON", invalid); rc -= 1; }
        free(line);
        fclose(f_ap);
        rc += 1;
    }

    FILE *f_cl = fopen(client_json, "r");
    if(!f_cl){ log_print("warn", "Cannot open %s", client_json); return rc; }
    else{
        char *line = NULL;
        size_t linecap = 0;
        ssize_t len;

        int invalid = 0;
        while((len = getline(&line, &linecap, f_cl)) != -1){
            if(n_client >= CLIENTS_MAX_RECORD){ log_print("warn", "Too many clients (over %d), list truncated", CLIENTS_MAX_RECORD); rc -=1; break; }
            if(len == 0 || strspn(line, " \n\t\r") == (size_t)len){ continue; }
            struct json_object *obj = json_tokener_parse(line);
            if(!obj){ invalid++; continue; }

            struct json_object *mac, *ap_bssid, *lastseen;
            if(!json_object_object_get_ex(obj, "mac", &mac) || !json_object_object_get_ex(obj, "ap_bssid", &ap_bssid) || !json_object_object_get_ex(obj, "lastseen", &lastseen)){
                json_object_put(obj);
                invalid++;
                continue;
            }
            if(!json_object_is_type(mac, json_type_string) || !json_object_is_type(ap_bssid, json_type_string) || !json_object_is_type(lastseen, json_type_string)){
                json_object_put(obj);
                invalid++;
                continue;
            }

            uint8_t b1[6], b2[6];
            if(parse_mac(json_object_get_string(mac), b1) < 0){ json_object_put(obj); invalid++; continue; }
            if(parse_mac(json_object_get_string(ap_bssid), b2) < 0){ json_object_put(obj); invalid++; continue; }
            memcpy(client_list[n_client].mac, b1, 6); memcpy(client_list[n_client].ap_bssid, b2, 6);
            snprintf(client_list[n_client].lastseen, sizeof(client_list[n_client].lastseen), "%s", json_object_get_string(lastseen));

            json_object_put(obj);
            n_client++;
        }

        if(invalid){ log_print("warn", "%d client data skipped due to invalid JSON", invalid); rc -= 1; }
        free(line);
        fclose(f_cl);
        rc += 1;
    }

    return rc;
}

static int archive_discovered(void){
    int rc = -2;
    if(!n_ap && !n_client){ return 0; }
    if(!proj_root){ return rc; }

    char state_dir[strlen(proj_root) + strlen("/state") + 1];
    snprintf(state_dir, sizeof(state_dir), "%s/state", proj_root);
    if(mkdir(state_dir, 0755) && errno != EEXIST){ log_print("warn", "mkdir %s: %s", state_dir, strerror(errno)); return rc; } 

    char ap_json[strlen(proj_root) + strlen("/state/ap.json") + 1];
    snprintf(ap_json, sizeof(ap_json), "%s/state/ap.json", proj_root);
    char client_json[strlen(proj_root) + strlen("/state/client.json") + 1];
    snprintf(client_json, sizeof(client_json), "%s/state/client.json", proj_root);

    char ap_json_tmp[sizeof(state_dir) + strlen("/ap.json.part.XXXXXX")];
    snprintf(ap_json_tmp, sizeof(ap_json_tmp), "%s/ap.json.part.XXXXXX", state_dir);
    char client_json_tmp[sizeof(state_dir) + strlen("/client.json.part.XXXXXX")];
    snprintf(client_json_tmp, sizeof(client_json_tmp), "%s/client.json.part.XXXXXX", state_dir);

        if(n_ap){
            int fd = mkstemp(ap_json_tmp);
            if( fd < 0){ log_print("warn", "mkstemp %s: %s", ap_json_tmp, strerror(errno)); goto client; }

            FILE *f = fdopen(fd, "w");
            if(!f){ log_print("warn", "fdopen %s: %s", ap_json_tmp, strerror(errno)); close(fd); unlink(ap_json_tmp); goto client; }

            for(int i = 0; i < n_ap; i++){
                struct json_object *o = json_object_new_object();
                if(!o){ fclose(f); unlink(ap_json_tmp); goto client; }

                char b[18];
                json_object_object_add(o, "bssid", json_object_new_string(mac2str(ap_list[i].bssid, b)));
                json_object_object_add(o, "ch", json_object_new_int(ap_list[i].ch));
                json_object_object_add(o, "ssid", json_object_new_string(ap_list[i].ssid));
                json_object_object_add(o, "lastseen", json_object_new_string(ap_list[i].lastseen));

                fprintf(f, "%s\n", json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN));
                json_object_put(o);
            }

            int bad = 0;
            if(fflush(f)){ bad = 1; }
            if(!bad && fsync(fileno(f))){ bad = 1; }
            if(fclose(f)){ bad = 1; }
            if(bad){ unlink(ap_json_tmp); goto client; }
            if(rename(ap_json_tmp, ap_json)){ log_print("warn", "rename %s: %s", ap_json_tmp, strerror(errno)); unlink(ap_json_tmp); goto client; }
            rc++;
        }else{ rc++; }
    
    client:
        if(n_client){
            int fd = mkstemp(client_json_tmp);
            if( fd < 0){ log_print("warn", "mkstemp %s: %s", client_json_tmp, strerror(errno)); return rc; }

            FILE *f = fdopen(fd, "w");
            if(!f){ log_print("warn", "fdopen %s: %s", client_json_tmp, strerror(errno)); close(fd); unlink(client_json_tmp); return rc; }

             for(int i = 0; i < n_client; i++){
                struct json_object *o = json_object_new_object();
                if(!o){ fclose(f); unlink(client_json_tmp); return rc; }

                char b1[18], b2[18];
                json_object_object_add(o, "mac", json_object_new_string(mac2str(client_list[i].mac, b1)));
                json_object_object_add(o, "ap_bssid", json_object_new_string(mac2str(client_list[i].ap_bssid, b2)));
                json_object_object_add(o, "lastseen", json_object_new_string(client_list[i].lastseen));

                fprintf(f, "%s\n", json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN));
                json_object_put(o);
            }

            int bad = 0;
            if(fflush(f)){ bad = 1; }
            if(!bad && fsync(fileno(f))){ bad = 1; }
            if(fclose(f)){ bad = 1; }
            if(bad){ unlink(client_json_tmp); return rc; }
            if(rename(client_json_tmp, client_json)){ log_print("warn", "rename %s: %s", client_json_tmp, strerror(errno)); unlink(client_json_tmp); return rc; }
            rc++;
        }else{ rc++; }
        
    return rc;
}

static int free_or_resume_radio(char choice){
    DIR *d = opendir("/sys/class/net");
    if(!d){ log_print("err", "Cannot open /sys/class/net"); return -1; }

    struct dirent *e;
    int found = 0;
    while((e = readdir(d))){
        if(e -> d_name[0] == '.'){ continue; }
        if(strcmp(e -> d_name, mon_iface) == 0){ continue; }

        char path[512];
        snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", e -> d_name);

        char link[512];
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if(n < 0){ continue; }
        link[n] = '\0';

        char *base = strrchr(link, '/');
        if(!base){ continue; }
        if(strcmp((base + 1), phy)){ continue; }

        found++;

        if(choice == 'f'){
            if(systemf("nmcli device set %s managed no >/dev/null 2>&1", e -> d_name) == 0){ log_print("info", "Dismanaged %s from NM", e -> d_name); }
            else{ log_print("warn", "Skipped dismanaging %s from NM", e -> d_name);}

            if(systemf("ip link set %s down", e -> d_name) == 0){ log_print("info", "Took %s DOWN (Shares radio with %s)", e -> d_name, phy); }
            else{ log_print("err", "Cannot take %s down", e -> d_name); closedir(d); return -1; }
        }else if(choice == 'r'){
            if(systemf("nmcli device set %s managed yes >/dev/null 2>&1", e -> d_name) == 0){ log_print("info", "Handed %s back to NM", e -> d_name); }
            else{ log_print("warn", "Skipped handing %s back from NM", e -> d_name);}

            if(systemf("ip link set %s up", e -> d_name) == 0){ log_print("info", "Took %s UP (Shares radio with %s)", e -> d_name, phy); }
            else{ log_print("err", "Cannot take %s up", e -> d_name); closedir(d); return -1; }
        }else{
            printf("the stupid developer is using an undeclared parameter '%c' for function 'free_or_resume_radio', if u see this, don't worry, it's not ur fault.\n", choice);
            closedir(d);
            return -1;
        }
    }
    if(!found){ log_print("warn", "No interface found on %s to be freed or resumed", phy); }
    closedir(d);
    return 0;
}

static int mon_up(void){

    char tmp_iface_name[64];
    snprintf(tmp_iface_name, sizeof(tmp_iface_name), "%smon", phy);

    if(if_nametoindex(tmp_iface_name) != 0){
        log_print("info", "'%s' already exist, reusing", tmp_iface_name);
        snprintf(mon_iface, sizeof(mon_iface), "%s", tmp_iface_name);
        return 0;}

    int r0 = 1, r1 = 1, r2 = 1, r3 = 1;

    for(int i = 0; i < 1; i++){
    r0 = systemf("rfkill unblock all");
    if(r0 == 0){log_print("info", "Unblocked RF-kill");}else{log_print("err", "Failed to unblock RF-kill"); break; }
    
    r1 = free_or_resume_radio('f');
    if(r1 != 0){ break; }

    r2 = systemf("iw phy %s interface add %s type monitor", phy, tmp_iface_name);
    if(r2 == 0){log_print("info", "Created monitor interface: %s", tmp_iface_name);}else{log_print("err", "Failed to create new monitor interface"); break; }

    r3 = systemf("ip link set %s up", tmp_iface_name);
    if(r3 == 0){log_print("info", "%s UP", tmp_iface_name);}else{log_print("err", "Failed to set %s up", tmp_iface_name); systemf("iw dev %s del", tmp_iface_name); break; }
    }

    if(r0 == 0 && r1 == 0 && r2 == 0 && r3 == 0){
        snprintf(mon_iface, sizeof(mon_iface), "%s", tmp_iface_name);
        return 0;
    }else{
        mon_iface[0] = '\0';
        return -1;
    }
}

static int mon_resume(void){
    if(if_nametoindex(mon_iface) == 0){
        log_print("warn", "Interface '%s' does not exist, skipping", mon_iface);
        return -1;}

    int r0 = 1, r1 = 1, r2 = 1;

    for(int i = 0; i < 1; i++){
    r0 = systemf("rfkill unblock all");
    if(r0 == 0){log_print("info", "Unblocked RF-kill");}else{log_print("err", "Failed to unblock RF-kill"); break; }
    
    r1 = free_or_resume_radio('r');
    if(r1 != 0){ break; }

    r2 = systemf("iw dev %s del", mon_iface);
    if(r2 == 0){log_print("info", "Removed monitor interface: %s", mon_iface);}else{log_print("err", "Failed to remove monitor interface '%s'", mon_iface); break; }
    }

    if(r0 == 0 && r1 == 0 && r2 == 0){
        mon_iface[0] = '\0';
        return 0;
    }else{
        return -1;
    }
}

static int get_phy(void){
    DIR *d = opendir("/sys/class/ieee80211");
    if(!d){perror("opendir");return -1;}
    struct dirent *e;

    int i = 0;
    while((e = readdir(d)) != NULL){
        if(e -> d_name[0] == '.'){continue;}
        if(i >= (int)( sizeof(phy_list)/sizeof(phy_list[0]) )){ log_print("warn", "Too many phys (over %d), list truncated", (int)( sizeof(phy_list)/sizeof(phy_list[0]) )); break; }
        snprintf(phy_list[i], sizeof(phy_list[i]), "%.31s", e->d_name);

        char link[512], dri_path[256];
        snprintf(link, sizeof(link), "/sys/class/ieee80211/%s/device/driver", e->d_name);
        ssize_t len = readlink(link, dri_path, sizeof(dri_path) - 1);
        if(len > 0 && len < (ssize_t)sizeof(dri_path)){
            dri_path[len] = '\0';
            snprintf(driver_list[i], sizeof(driver_list[i]), "%.31s", base_name(dri_path));
        }else{
            if(len < 0){ perror("readlink"); }
            snprintf(driver_list[i], sizeof(driver_list[i]), "unknown driver");
        }
        i++;
    }
    closedir(d);
    return i;
}

static const char *lookup_phy_driver(const char *phy){
    for(int i = 0; i < (int)( sizeof(phy_list)/sizeof(phy_list[0]) ); i++){
        if(strcmp(phy_list[i], phy) == 0){ return driver_list[i]; }
    }
    return NULL;
}

static void cmd_exit(void){
    if(mon_resume() == 0){ log_print("info", "Restored radio %s", phy);}
    else{ log_print("warn", "Cannot restored radio %s", phy); }

    if(archive_discovered() < 0){ log_print("warn", "Discovered list archived incompletely"); }
    else{ log_print("info", "Discovered list archived completely"); }

    log_print("info", "Console shutdown");
    exit(0);
}

static void help_for_set(void){
    printf("Usage: set [Options] [Value]\n");
    printf("Options:\n    %-33sChoose physical layer to use\n    %-33sChange monitor/managed mode on current phy\n    %-33sChoose a channel to use\n    %-33sMAC address of AP\n    %-33sMAC address of target\n    %-33s2g/5g/all to choose scope of channel hopping or 'off' to use a stable channel\n", "phy", "mon", "ch", "bssid", "target", "hop");
}

static void help_for_use(void){
        printf("Usage: use [Module]\n");
        printf("Modules:\n");
        for(size_t i = 0; i < N_MODULES; i++){
            printf("    %-33s%s\n", modules_list[i].path, modules_list[i].desc);
        }
}

static void help_for_global(void){
    printf("Usage: yudos [Global options]\n");
    printf("Global options:\n    %-33sLoad specified parameters in resource file\n    %-33sExecute internal command without interactive console (; to split)\n    %-33sChoose a specified phy to init\n    %-33sBoot without banner and tips\n    %-33sEcho current version\n    %-33sShow this help message\n", "-r, --resource FILE", "-x, --execute COMMAND", "-i, --init-phy PHY", "-q, --quiet", "-V, --version", "-h, --help");
}

static void cmd_help(void){
    printf("Usage: [Command] ...\n");
    printf("Commands:\n    %-33sShow all options\n    %-33sSet values for options\n    %-33sChoose a module to use\n    %-33sShow stored discovered list\n    %-33sShutdown console\n    %-33sShow this help\n", "status", "set", "use", "show", "exit", "help");
    printf("To get help detail, try '[Command] help', e.g. set help\n");
}

static int cmd_set(int argc, char *argv[CONSOLE_MAX_ARGC]){
    if(argc < 2){help_for_set(); return 0;}

    else if(strcmp(argv[1], "phy") == 0){
        int n_phy = get_phy();
        if(argc < 3){log_print("err", "Empty value for 'phy'"); return -1;}
        for(int i = 0; i < n_phy; i++){
            if(strcmp(argv[2], phy_list[i]) == 0){
                snprintf(phy, sizeof(phy), "%s", argv[2]);
                log_print("info", "Set phy -> %s (%s)", argv[2], lookup_phy_driver(phy));
                return 0;
            }
        }
        printf(RED"[-]"RESET" Device not found. Available: ");
        for(int i = 0; i < n_phy; i++){
            printf("%s (%s)", phy_list[i], driver_list[i]);
            if(i != (n_phy - 1)){ printf(", "); }
        }
        printf("\n");
        return -1;

    }else if(strcmp(argv[1], "ch") == 0){
        if(argc < 3){log_print("err", "Empty value for 'ch'. Available: 1~196"); return -1;}
        if(atoi(argv[2]) < 1 || atoi(argv[2]) > 196){ log_print("err", "Invalid value for channel, should be 1~196"); return -1; }
        if(if_nametoindex(mon_iface) == 0){ log_print("err", "No monitor interface found, run 'set mon on' first"); return -1; }
        if(netlink_set_channel(mon_iface, atoi(argv[2])) == 0){ ch = atoi(argv[2]); log_print("info", "Set ch -> %d", ch); }
        else{ log_print("err", "Failed to set channel to %d", atoi(argv[2])); return -1; }

    }else if(strcmp(argv[1], "mon") == 0){
        if(argc < 3){log_print("err", "Empty value for 'mon'. Available: on, off"); return -1; }
        if(strcmp(argv[2], "on") != 0 && strcmp(argv[2], "off") != 0){ log_print("warn", "Unknown parameter %s. Available: up, down", argv[2]); return -1; }
        if(strcmp(argv[2], "on") == 0){
            if(mon_up() == 0){log_print("info", "%s enable successfully", mon_iface);}
            else{log_print("err", "Failed to enable %s", mon_iface); return -1;}
            if(ch){
                log_print("info", "'ch' already set to %d, trying to reuse...", ch);
                if(netlink_set_channel(mon_iface, ch) == 0){ log_print("info", "Reused ch %d", ch); }
                else{ log_print("warn", "Cannot reuse ch %d, skipped", ch); }
            }
        }else if(strcmp(argv[2], "off") == 0){
            if(mon_resume() == 0){ log_print("info", "Restored radio %s", phy);}
            else{ log_print("err", "Failed to restored radio %s", phy); return -1; }
        }

    }else if(strcmp(argv[1], "hop") == 0){
        if(argc < 3){log_print("err", "Empty value for 'hop'. Available: off, 2g, 5g, all"); return -1; }
        if(strcmp(argv[2], "2g") != 0 && strcmp(argv[2], "5g") != 0 && strcmp(argv[2], "all") != 0 && strcmp(argv[2], "off") != 0){ log_print("warn", "Unknown parameter %s. Available: off, 2g, 5g, all", argv[2]); return -1; }
        if(strcmp(argv[2], "2g") == 0){ hop = HOP_2G; }
        else if(strcmp(argv[2], "5g") == 0){ hop = HOP_5G; }
        else if(strcmp(argv[2], "all") == 0){ hop = HOP_ALL; }
        else if(strcmp(argv[2], "off") == 0){ hop = HOP_OFF; }
        log_print("info", "Set hop -> %s", hop_names[hop]);

    }else if(strcmp(argv[1], "help") == 0){
        help_for_set();

    }else if(strcmp(argv[1], "bssid") == 0){
        if(argc < 3){ log_print("err", "Empty value for 'bssid'"); return -1; }
        if(parse_mac(argv[2], bssid) == -1){ log_print("warn", "Parser cannot understand this MAC format: %s", argv[2]); return -1; }
        char tmp[18];
        log_print("info", "Set bssid -> %s", mac2str(bssid, tmp));

    }else if(strcmp(argv[1], "target") == 0){
        if(argc < 3){ log_print("err", "Empty value for 'target'"); return -1; }
        if(parse_mac(argv[2], target) == -1){ log_print("warn", "Parser cannot understand this MAC format: %s", argv[2]); return -1; }
        char tmp[18];
        log_print("info", "Set target -> %s", mac2str(target, tmp));
    }

    else{log_print("warn", "Unknown parameter '%s'", argv[1]); return -1; }

    return 0;
}

static int cmd_use(int argc, char *argv[CONSOLE_MAX_ARGC]){
    if(argc < 2){ log_print("err", "Empty value for 'use'"); return -1; }
    if(strcmp(argv[1], "help") == 0){ help_for_use(); return 0; }
    for(size_t i = 0; i < N_MODULES; i++){
        if(strcmp(argv[1], modules_list[i].path) == 0){
            snprintf(module, sizeof(module), "%s", argv[1]);
            log_print("info", "Using module %s", module);
            return 0;
        }
    }
    log_print("err", "No such module: %s", argv[1]);
    return -1;
}

static int cmd_status(void){
    printf("    %-33s%s\n", "Options", "Value");
    for(size_t i = 0; i < sizeof(options_dict)/sizeof(options_dict[0]); i++){
        switch(options_dict[i].value.type){
            case VT_INT : printf("    %-33s%d\n", options_dict[i].key, *options_dict[i].value.as.i); break;
            case VT_STR : {
                if(strcmp(options_dict[i].key, "phy") == 0){ printf("    %-33s%s (%s)\n", options_dict[i].key, options_dict[i].value.as.s, lookup_phy_driver(phy)); break; }
                printf("    %-33s%s\n", options_dict[i].key, options_dict[i].value.as.s); break;
            }
            case VT_MAC : { char tmp[18]; printf("    %-33s%s\n", options_dict[i].key, mac2str(options_dict[i].value.as.mac, tmp)); break; }
            case VT_ENUM : {
                int idx = *options_dict[i].value.as.i;
                const char **nms = options_dict[i].value.names;
                size_t n = sizeof(hop_names)/sizeof(hop_names[0]);
                printf("    %-33s%s\n", options_dict[i].key, (idx >= 0 && (size_t)idx < n) ? nms[idx] : "???");
                break;
            }
        }
    }
    return 0;
}

static int cmd_show(int argc, char *argv[CONSOLE_MAX_ARGC]){
    if(argc < 2){ log_print("err", "Empty value for 'show'. Available: ap, client"); return -1; }

    if(strcmp(argv[1], "help") == 0){
        printf("Usage: show [Options]\n");
        printf("Options:\n    %-33sShow AP discovered list\n    %-33sShow client discovered list\n", "ap", "client");
        return 0;

    }else if(strcmp(argv[1], "ap") == 0){
        if(!n_ap){ log_print("warn", "No AP discovered yet, run probe/ap first"); return -1; }
        printf("    %-22s%-7s%-22s%-23s\n", "BSSID", "CH", "SSID", "Last Seen");
        for(int i = 0; i < n_ap; i++){
            char tmp[18];
            printf("    %-22s%-7d%-22s%-23s\n", mac2str(ap_list[i].bssid, tmp), ap_list[i].ch, ap_list[i].ssid, ap_list[i].lastseen);
        }

    }else if(strcmp(argv[1], "client") == 0){
        if( !n_client ){ log_print("warn", "No client discovered yet, run probe/client first"); return -1; }
        printf("    %-22s%-22s%-23s\n", "MAC Address", "AP's BSSID", "Last Seen");
        for(int i = 0; i < n_client; i++){
            char tmp_1[18], tmp_2[18];
            printf("    %-22s%-22s%-23s\n", mac2str(client_list[i].mac, tmp_1), mac2str(client_list[i].ap_bssid, tmp_2), client_list[i].lastseen);
        }
    }else{
        log_print("warn", "Unknown parameter '%s'. Available: ap, client", argv[1]);
        return -1;
    }
    return 0;
}

static int attack(void){
    if(!module[0]){ log_print("err", "No module is selected"); return -1; }
    for(size_t i = 0; i < N_MODULES; i++){
        if(strcmp(modules_list[i].path, module) == 0){
            if(check_reqr(modules_list[i].reqr) < 0){ log_print("err", "Failed to start module %s due to lack of requirements", module); return -1; }
            log_print("info", "Starting %s", module);
            int r = modules_list[i].run();
            running = 0;
            if(r != 0){ log_print("err", "Failed to start module %s (code=%d)", module, r); return -1; }
            else{ log_print("info", "Module %s terminated", module); return 0; }
        }
    }
    log_print("err", "Module '%s' not found", module);
    return -1;
}


static int resolve_cmd(int argc, char *argv[CONSOLE_MAX_ARGC]){
    if(strcmp(argv[0], "help") == 0){ cmd_help(); return 0; }
    else if(strcmp(argv[0], "set") == 0){ return cmd_set(argc,argv); }
    else if(strcmp(argv[0], "use") == 0){ return cmd_use(argc,argv); }
    else if(strcmp(argv[0], "attack") == 0){ return attack(); }
    else if(strcmp(argv[0], "status") == 0){ return cmd_status(); }
    else if(strcmp(argv[0], "exit") == 0){ cmd_exit(); return 0; }
    else if(strcmp(argv[0], "show") == 0){ return cmd_show(argc, argv); }
    else{log_print("warn", "Unknown command '%s'", argv[0]); return -1; }
}

static int execute_one_line(char *line){
    int argc = 0;
    char *argv[CONSOLE_MAX_ARGC];

    for(char *t = strtok(line, " \t\r\n"); t != NULL; t = strtok(NULL, " \t\r\n")){
        if(argc >= CONSOLE_MAX_ARGC){log_print("warn", "Too many parameters (over %d), line truncated", CONSOLE_MAX_ARGC); break; }
        argv[argc++] = t;
    }

    if(argc > 0){ return resolve_cmd(argc, argv); }
    return -1; 
}

static int execute_multi_lines(char *lines){
    int rc = 0;

    for(char *p = lines; p && *p; ){
        char *semi = strchr(p, ';');
        if(semi){ *semi = '\0'; }

        char *cmd = trim(p);
        if(*cmd != '\0'){
            if(execute_one_line(cmd) < 0){ rc = -1; }
        }
        p = semi ? semi + 1 : NULL;
    }
    return rc;
}

static int load_resource_file(const char *resource_path){
    FILE *f = fopen(resource_path, "r");
    if(!f){ log_print("warn", "Cannot open %s: %s", resource_path, strerror(errno)); return -1; }

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0;
    int rc = 0;

    while((n = getline(&line, &cap, f)) != -1){
        lineno++;
        char *p = trim(line);
        if(*p == '\0' || *p == '#'){ continue; }

        printf("<Resource file: line %d> %s\n", lineno, p);
        if(execute_one_line(p) < 0){ rc = -1; }
    }

    if(ferror(f)){ log_print("warn", "Error occurred reading resource file %s", resource_path); rc = -1; }

    free(line);
    fclose(f);
    return rc;
}

static void resolve_global_flags(void){
    int opt;
    while((opt = getopt_long(g_argc, g_argv, ":r:x:i:hVq", long_options, NULL)) != -1){
        switch(opt){
            case 'h': help_for_global(); exit(0); break;
            case 'V': printf("yuDoS %s\n", version); exit(0); break;
            case 'r': resource_path = optarg; break;
            case 'q': is_quiet_boot = 1; break;
            case 'x': is_quiet_boot = 1; exe_cmd = optarg; break;
            case 'i': init_phy = optarg; break;

            case '?': log_print("warn", "Unknown parameter '%s'", g_argv[optind - 1] ? g_argv[optind - 1] : "(?)"); exit(1); break;
            case ':': log_print("warn", "Option '%s' requires an argument", g_argv[optind - 1] ? g_argv[optind - 1] : "(?)"); exit(1); break;
            default: log_print("err", "Unknown error occurred resolving global flags"); exit(1); break;
        }
    }
}

static int pre_execute_before_console(){
    int rc = 0;
    if(resource_path){
        int r = load_resource_file(resource_path);
        if(r < 0){ log_print("warn", "Resource file finished with error"); }
        else{ log_print("info", "Resource file loaded completely"); }
        rc += r;
    }
    if(exe_cmd){ rc += execute_multi_lines(exe_cmd); cmd_exit(); }
    return rc;
}

static const char *build_ps1(void){
    static char ps1[256];
    if(!module[0]){snprintf(ps1, sizeof(ps1), "yuDoS > "); return ps1; }

    const char *s = strchr(module, '/');
    if(s){
        snprintf(ps1, sizeof(ps1), "yuDoS %.*s(\001%s\002%s\001%s\002) > ", (int)(s - module), module, RED, s+1, RESET);
    }else{
        snprintf(ps1, sizeof(ps1), "yuDoS %s > ", module);
    }
    return ps1;
}

static int rl_swallow(int count, int key){
    (void)count;
    (void)key;
    return 0;
}

static void console_init_keys(void){
    rl_initialize();
    rl_read_init_file(NULL);

    rl_bind_keyseq("\033[5~", rl_swallow);    /*PageUp*/
    rl_bind_keyseq("\033[6~", rl_swallow);    /*PageDown*/

    rl_variable_bind("bell-style", "none");
}

static void console_line_handler(char *line){
    if(!line){ console_done = 1; printf("\n"); log_print("info", "Console closed"); return; }
    if(line[0] != '\0'){ add_history(line); }

    if(console_interrupted){
        console_interrupted = 0; 
    }

    int argc = 0;
    char *argv[CONSOLE_MAX_ARGC];

    for(char *t = strtok(line, " \t\r\n"); t != NULL; t = strtok(NULL, " \t\r\n")){
        if(argc >= CONSOLE_MAX_ARGC){log_print("warn", "Too many parameters (over %d), line truncated", CONSOLE_MAX_ARGC); break; }
        argv[argc++] = t;
    }

    if(argc > 0){ resolve_cmd(argc, argv); }

    free(line);
    rl_set_prompt(build_ps1());
    /* if(!console_done){ rl_callback_handler_install(build_ps1(), console_line_handler); } */
}

static void console(void){
    using_history();
    console_init_keys();

    prompt_sigint = 0;
    console_done = 0;

    rl_callback_handler_install(build_ps1(), console_line_handler);

    while(!console_done){
        if(prompt_sigint){
            prompt_sigint = 0;
            rl_replace_line("", 0);
            rl_crlf();
            rl_on_new_line();
            rl_redisplay();
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        int ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL);
        if(ret < 0){
            if(errno == EINTR){ continue; }
            perror("select");
            break;
        }

        if(FD_ISSET(STDIN_FILENO, &rfds)){ rl_callback_read_char(); }
    }

    rl_callback_handler_remove();
    printf("\n");
}

static void resolve_signal(int sig){
    (void)sig;
    if(sig != SIGINT){ return; }
    
    if(running){ running = 0; write(STDOUT_FILENO, "\n", 1); }
    else{ prompt_sigint = 1; }
}

static void init(void){

    if(getuid() != 0){log_print("err", "Root privilege required. Try 'sudo yudos'"); exit(1);}

    phy[0] = '\0';
    mon_iface[0] = '\0';
    module[0] = '\0';
    ch = 0;
    hop = HOP_ALL;
    memset(bssid, 0,sizeof(bssid));
    memset(target, 0, sizeof(target));

    n_ap = 0;
    n_client = 0;
    running = 0;
    proj_root = locate(2);

    if(!proj_root){ log_print("warn", "Cannot locate project root"); }
    if(load_discovered() < 0){ log_print("warn", "Discovered list loaded incompletely"); }
    else{ log_print("info", "Discovered list loaded completely"); }

    int n_phy = get_phy();
    if(n_phy <= 0){log_print("err", "No wireless device found\n"); exit(1);}
    else if(n_phy == 1){snprintf(phy, sizeof(phy), "%s", phy_list[0]);}
    else if(n_phy > 1){
        log_print("info", "Found %d wireless devices", n_phy);
        if(init_phy){
            for(int i = 0; i < n_phy; i++){
                if(strcmp(init_phy, phy_list[i]) == 0){
                    snprintf(phy, sizeof(phy), "%s", init_phy);
                    log_print("info", "Picked %s to init", init_phy);
                    goto mon_up;
                }
            }
            snprintf(phy, sizeof(phy), "%s", phy_list[0]);
            log_print("warn", "Cannot find device '%s', using default '%s'", init_phy, phy_list[0]);
        }else{
            for(int n = 0 ; n < n_phy; n++){
                printf("%d : %s (%s)\n", n, phy_list[n], driver_list[n]);
            }

            int choice;
            char buf[64];
            while(1){
            printf("Input number to choose: ");
            fflush(stdout);
            if(fgets(buf, sizeof(buf), stdin) == NULL){ printf("\n"); log_print("info", "Input closed"); exit(0); }
            if(sscanf(buf, "%d", &choice) != 1){
                buf[strcspn(buf, "\n")] = '\0';
                if(strcmp(buf, "exit") == 0){
                    exit(0);
                }else{
                    log_print("err", "Invalid number");
                    continue;
                }
            }
            if(choice < 0 || choice >= n_phy){log_print("err", "Invalid number"); continue; }

            snprintf(phy, sizeof(phy), "%s", phy_list[choice]);
            break;
            }
        }
    }
    mon_up:
    if(mon_up() == 0){log_print("info", "Initialization completed");}else{log_print("err", "Initialization failed"); exit((1));}
    
}


int main(int argc, char **argv){
    g_argc = argc;
    g_argv = argv;
    resolve_global_flags();

    super_fucking_srand();

    struct sigaction sa = {0};
    sa.sa_handler = resolve_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    if(is_quiet_boot == 0){ boom("yuDoS", version, NULL, "b", BLUE, tipslib, n_tips); }
    init();
    pre_execute_before_console();
    console();
    cmd_exit();
}