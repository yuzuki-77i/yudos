#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

/* NETLINK / nl80211 */

#ifndef NLA_OK
#define NLA_OK(nla, len)  ((len) >= (int)sizeof(struct nlattr) && (nla)->nla_len >= sizeof(struct nlattr) && (nla)->nla_len <= (len))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, attrlen)  ((attrlen) -= NLA_ALIGN((nla)->nla_len), (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#endif

static void *nla_put(struct nlmsghdr *nlh, size_t maxlen, int type, int len, const void *data){
    struct nlattr *nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    int total = NLA_HDRLEN + len;
    if((size_t)((char *)nla - (char *)nlh) + NLA_ALIGN(total) > maxlen){ return NULL; }
    nla->nla_type = (uint16_t)type;
    nla->nla_len = (uint16_t)total;
    if(data && len > 0){ memcpy((char *)nla + NLA_HDRLEN, data, (size_t)len); }
    nlh->nlmsg_len = (uint32_t)((char *)nla + NLA_ALIGN(total) - (char *)nlh);
    return nla;
}

static void nla_put_u32(struct nlmsghdr *nlh, size_t maxlen, int type, unsigned int v){
    nla_put(nlh, maxlen, type, (int)sizeof v, &v);
}

static void nla_put_str(struct nlmsghdr *nlh, size_t maxlen, int type, const char *s){
    nla_put(nlh, maxlen, type, strlen(s) + 1, s);
}

static int nl_open(void){
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if(fd < 0){ return -1; }
    struct sockaddr_nl local; memset(&local, 0, sizeof local);
    local.nl_family = AF_NETLINK;
    if(bind(fd, (struct sockaddr *)&local, sizeof local) < 0){ close(fd); return -1; }
    return fd;
}

static int nl_send(int fd, struct nlmsghdr *nlh){
    struct sockaddr_nl k; memset(&k, 0, sizeof k);
    k.nl_family = AF_NETLINK;
    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg; memset(&msg, 0, sizeof msg);
    msg.msg_name = &k;
    msg.msg_namelen = sizeof k;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    return sendmsg(fd, &msg, 0) < 0 ? -1 : 0;
}

static ssize_t nl_recv_seq(int fd, char *buf, size_t len, uint32_t seq){
    for(;;){
        ssize_t n = recv(fd, buf, len, 0);
        if(n < 0){ if(errno == EINTR){ return -1; } }
        if(n == 0){ return -1; }

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        size_t rem = (size_t)n;
        for(; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)){
            if(h->nlmsg_seq == seq){
                size_t msg_len = NLMSG_ALIGN(h->nlmsg_len);
                if((char *)h != buf){ memmove(buf, h, msg_len); }
                return (ssize_t)msg_len;
            }
        }
    }
}

static int nl80211_family(int fd){
    static int cached = -1;
    if(cached > 0){ return cached; }

    char buf[512]; memset(&buf, 0, sizeof buf);
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    gh->cmd = CTRL_CMD_GETFAMILY;
    gh->version = 1;
    nla_put_str(nlh, sizeof buf, CTRL_ATTR_FAMILY_NAME, "nl80211");

    if(nl_send(fd, nlh) != 0){ return -1; }

    char rbuf[4096];
    ssize_t n = nl_recv_seq(fd, rbuf, sizeof rbuf, 1);
    if(n < 0){ return -1; }

    struct nlmsghdr *r = (struct nlmsghdr *)rbuf;
    for(; NLMSG_OK(r, (unsigned int)n); r = NLMSG_NEXT(r, n)){
        if(r->nlmsg_type == NLMSG_ERROR){ return -1; }
        struct genlmsghdr *rgh = (struct genlmsghdr *)NLMSG_DATA(r);
        int alen = (int)(NLMSG_PAYLOAD(r, GENL_HDRLEN));
        struct nlattr *a = (struct nlattr *)((char *)rgh + GENL_HDRLEN);
        for(; NLA_OK(a, alen); a = NLA_NEXT(a, alen)){
            if(a->nla_type == CTRL_ATTR_FAMILY_ID){
                cached = *(uint16_t *)((char *)a + NLA_HDRLEN);
                return cached;
            }
        }
    }
    return -1;
}

static int ch2freq(int ch){
    if(ch >= 1 && ch <= 13){ return 2407 + ch * 5; }
    if(ch == 14){ return 2484; }
    if(ch >= 36 && ch <= 165){ return 5000 + ch * 5; }
    return 0;
}

static int nl_set_channel(int fd, int ifindex, int freq){
    int fam = nl80211_family(fd);
    if(fam < 0){ return -1; }

    char buf[512]; memset(buf, 0, sizeof buf);
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = (uint16_t)fam;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 2;
    gh->cmd = NL80211_CMD_SET_CHANNEL;

    nla_put_u32(nlh, sizeof buf, NL80211_ATTR_IFINDEX, (unsigned int)ifindex);
    nla_put_u32(nlh, sizeof buf, NL80211_ATTR_WIPHY_FREQ, (unsigned int)freq);
    nla_put_u32(nlh, sizeof buf, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT);
    nla_put_u32(nlh, sizeof buf, NL80211_ATTR_CENTER_FREQ1, (unsigned int)freq);

    if(nl_send(fd, nlh) != 0){ return -1; }

    char rbuf[512];
    ssize_t n = nl_recv_seq(fd, rbuf, sizeof rbuf, 2);
    if(n < 0){ return -1; }

    struct nlmsghdr *r = (struct nlmsghdr *)rbuf;
    if(r->nlmsg_type == NLMSG_ERROR){
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);
        if(e->error != 0){ errno = -e->error; return -1; }
    }
    return 0;
}

int netlink_set_channel(const char *iface, int channel){
    if(!iface || channel <= 0){ errno = EINVAL; return -1; }
    int freq = ch2freq(channel);
    if(freq <= 0){ errno = EINVAL; return -1; }
    int ifx = (int)if_nametoindex(iface);
    if(ifx == 0){ return -1; }

    static int nfd = -1;
    if(nfd < 0){
        nfd = nl_open();
        if(nfd < 0){ return -1; }
    }
    return nl_set_channel(nfd, ifx, freq);
}