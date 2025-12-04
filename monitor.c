/*
https://www.man7.org/linux/man-pages/man7/netlink.7.html

Netlink messages consist of a byte stream with one or multiple
nlmsghdr headers and associated payload.  The byte stream should
be accessed only with the standard NLMSG_* macros.  See netlink(3)
for further information.
*/

/*
https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html

Netlink expects that the user buffer will be at least 8kB or a page size of
the CPU architecture, whichever is bigger. Particular Netlink families may,
however, require a larger buffer. 32kB buffer is recommended for most efficient
handling of dumps (larger buffer fits more dumped objects and therefore fewer recvmsg()
calls are needed).
*/

/*
https://www.man7.org/linux/man-pages/man3/netlink.3.html

<linux/netlink.h> defines several standard macros to access or
create a netlink datagram.  They are similar in spirit to the
macros defined in cmsg(3) for auxiliary data.  The buffer passed
to and from a netlink socket should be accessed using only these
macros.

Parse and build netlink messages using these macros
*/

/*
https://thelinuxcode.com/c-recv-function-usage/
https://www.linuxjournal.com/article/8498

Some guides on how to listen for netdev events
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <stdlib.h>

#define NL_BUF_SIZE 8192
#define NL_MAX_EVENTS 8
/* removed fixed-size interface limit to allow arbitrary number of interfaces */
/* #define NL_MONITOR_NET_IFACE_MAX_COUNT 20 */
#define NL_IPV4_LEN 4
#define NL_IPV6_LEN 16

#define NL_IPV4_STR_FMT "%u.%u.%u.%u"
#define NL_IPV4_STR_FMT_BYTES(buf) \
    (buf)[0], (buf)[1], (buf)[2], (buf)[3]

#define NL_IPV6_STR_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define NL_IPV6_STR_FMT_BYTES(buf) \
    (buf)[0], (buf)[1], (buf)[2], (buf)[3], (buf)[4], (buf)[5], (buf)[6], (buf)[7], (buf)[8], \
    (buf)[9], (buf)[10], (buf)[11], (buf)[12], (buf)[13], (buf)[14], (buf)[15]

#define NL_MAC_STR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define NL_MAC_STR_FMT_BYTES(buf) \
    (buf)[0], (buf)[1], (buf)[2], (buf)[3], (buf)[4], (buf)[5]

struct net_iface {
    int index;
    char ifname[IFNAMSIZ];
    unsigned flags;
    unsigned change;
    int carrier;
    unsigned mtu;
    unsigned char mac[ETH_ALEN];
    unsigned char ipv4[NL_IPV4_LEN];
    unsigned char ipv6[NL_IPV6_LEN];

    /* linked list pointers for dynamic storage of arbitrary number of ifaces */
    struct net_iface *prev;
    struct net_iface *next;
};

/* manager for linked list of interfaces */
struct net_iface_list {
    struct net_iface *head;
    struct net_iface *tail;
    size_t count;
};

/* initialize a single net_iface structure (reset fields) */
static void net_iface_init_one(struct net_iface *niface)
{
    if (!niface) return;
    memset(niface->ifname, 0, sizeof niface->ifname);
    niface->index = -1;
    niface->flags = -1u;
    niface->change = -1u;
    niface->carrier = -1;
    niface->mtu = -1u;
    memset(niface->mac, 0, sizeof niface->mac);
    memset(niface->ipv4, 0, sizeof niface->ipv4);
    memset(niface->ipv6, 0, sizeof niface->ipv6);
    niface->prev = niface->next = NULL;
}

/* initialize list manager */
static void net_iface_list_init(struct net_iface_list *list)
{
    if (!list) return;
    list->head = list->tail = NULL;
    list->count = 0;
}

/* free all nodes in the list */
static void net_iface_list_free_all(struct net_iface_list *list)
{
    if (!list) return;
    struct net_iface *it = list->head;
    while (it) {
        struct net_iface *next = it->next;
        free(it);
        it = next;
    }
    list->head = list->tail = NULL;
    list->count = 0;
}

/* add node (takes ownership of node pointer) to tail */
static void net_iface_list_add_node(struct net_iface_list *list, struct net_iface *node)
{
    if (!list || !node) return;
    node->prev = list->tail;
    node->next = NULL;
    if (list->tail) list->tail->next = node;
    list->tail = node;
    if (!list->head) list->head = node;
    list->count++;
}

/* find node by index */
static struct net_iface *net_iface_list_find_by_index(struct net_iface_list *list, int index)
{
    if (!list) return NULL;
    struct net_iface *it = list->head;
    while (it) {
        if (it->index == index) return it;
        it = it->next;
    }
    return NULL;
}

/* remove node by index (frees node). return 0 on success, -1 if not found */
static int net_iface_list_remove_by_index(struct net_iface_list *list, int index)
{
    if (!list) return -1;
    struct net_iface *it = list->head;
    while (it) {
        if (it->index == index) {
            if (it->prev) it->prev->next = it->next;
            else list->head = it->next;
            if (it->next) it->next->prev = it->prev;
            else list->tail = it->prev;
            list->count--;
            free(it);
            return 0;
        }
        it = it->next;
    }
    return -1;
}

/* helper: check if buffer empty */
static int net_iface_is_buf_empty(const unsigned char *buf, size_t len)
{
    int i;
    for (i = 0; i < (int)len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int net_iface_is_mac_set(const struct net_iface *niface)
{
    return !net_iface_is_buf_empty(niface->mac, sizeof niface->mac);
}

static int net_iface_is_ipv6_set(const struct net_iface *niface)
{
    return !net_iface_is_buf_empty(niface->ipv6, sizeof niface->ipv6);
}

static int net_iface_is_mac_equal(const struct net_iface *one, const struct net_iface *other)
{
    return !memcmp(one->mac, other->mac, sizeof one->mac);
}

static int net_iface_should_ignore(const struct net_iface *niface, const char *filter)
{
    if (!filter)
        return 0;

    size_t filter_len = strlen(filter);
    if (filter_len > sizeof niface->ifname) {
        filter_len = sizeof niface->ifname;
    }

    int i;
    for (i = 0; i < (int)filter_len; i++) {
        if (filter[i] != niface->ifname[i]) {
            if (filter[i] == '*' && i == (int)filter_len - 1) {
                return 0;
            } else {
                return 1;
            }
        }
    }

    return 0;
}

static int nl_monitor_init(size_t nl_event_mask)
{
    int rc = 0;

    /* Open netlink socket and "bind" to list of events we are interested to monitor */
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd == -1) {
        perror("failed socket()");
        goto err;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof addr);
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = nl_event_mask;

    rc = bind(fd, (const struct sockaddr *)&addr, sizeof addr);
    if (rc == -1) {
        perror("failed bind()");
        close(fd);
        goto err;
    }

    return fd;

err:
    return -1;
}

static void nl_monitor_parse_rtmgrp_link(const struct nlmsghdr *nlh, struct net_iface *niface)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    struct rtattr *rtattr;
    size_t rtattrlen = IFLA_PAYLOAD(nlh);

    niface->index = ifi->ifi_index;
    niface->flags = ifi->ifi_flags;
    niface->change = ifi->ifi_change;

    /* Description of message attributes can be found here
     * https://www.man7.org/linux/man-pages/man7/rtnetlink.7.html
     * uapi/linux/if_link.h
     * https://www.kernel.org/doc/html/next/networking/netlink_spec/rt_link.html#rt-link-attribute-set-link-attrs
     */

    /* Parse link layer attributes */
    for (rtattr = IFLA_RTA(ifi); RTA_OK(rtattr, rtattrlen); rtattr = RTA_NEXT(rtattr, rtattrlen)) {
        switch (rtattr->rta_type) {
        case IFLA_IFNAME:
            memcpy(niface->ifname, RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
            /* ensure null termination */
            if (RTA_PAYLOAD(rtattr) < IFNAMSIZ)
                niface->ifname[RTA_PAYLOAD(rtattr)] = '\0';
            else
                niface->ifname[IFNAMSIZ - 1] = '\0';
            break;
        case IFLA_CARRIER:
            niface->carrier = *((unsigned char *)RTA_DATA(rtattr));
            break;
        case IFLA_MTU:
            niface->mtu = *((unsigned *)RTA_DATA(rtattr));
            break;
        case IFLA_ADDRESS:
            memcpy(niface->mac, (unsigned char *)RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
            break;
        default:
            break;
        }
    }
}

static void nl_monitor_parse_rtmgrp_addr(const struct nlmsghdr *nlh, struct net_iface *niface)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    struct rtattr *rtattr;
    size_t rtattrlen = IFA_PAYLOAD(nlh);

    for (rtattr = IFA_RTA(ifa); RTA_OK(rtattr, rtattrlen); rtattr = RTA_NEXT(rtattr, rtattrlen)) {
        switch (rtattr->rta_type) {
        case IFA_ADDRESS:
            if (RTA_PAYLOAD(rtattr) == NL_IPV6_LEN) {
                memcpy(niface->ipv6, (unsigned char *)RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
            } else {
                memcpy(niface->ipv4, (unsigned char *)RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
            }
            break;
        default:
            break;
        }
    }
}

/* Now handle messages using a dynamically-sized linked list of interfaces */
static void nl_monitor_handle_msg(const struct nlmsghdr *nlh, struct net_iface_list *list,
                                  const char *filter)
{
    /* https://linux.die.net/man/7/rtnetlink */

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);

    int iface_index;
    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
        iface_index = ifa->ifa_index;
    } else {
        iface_index = ifi->ifi_index;
    }

    struct net_iface *old = net_iface_list_find_by_index(list, iface_index);

    /* If we don't have a stored entry, create one (no fixed limit) */
    if (old == NULL) {
        old = calloc(1, sizeof(*old));
        if (!old) {
            fprintf(stderr, "ERROR: memory allocation failed for new interface entry\n");
            return;
        }
        net_iface_init_one(old);
        /* We don't yet know index/name until parsing current; keep index=-1 as marker */
        net_iface_list_add_node(list, old);
    }

    char timestamp[100];
    time_t current_time = time(NULL);
    struct tm *time_struct = localtime(&current_time);

    /* Output timestamp in format YYYY-MM-DD HH:MM:SS */
    strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", time_struct);

    /* Retrieve current information about the interface */
    struct net_iface current;
    net_iface_init_one(&current);

    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
        nl_monitor_parse_rtmgrp_addr(nlh, &current);
    } else {
        nl_monitor_parse_rtmgrp_link(nlh, &current);
    }

    if (current.ifname[0] == 0) {
        if_indextoname(iface_index, current.ifname);
    }

    if (net_iface_should_ignore(&current, filter)) {
        return;
    }

    switch (nlh->nlmsg_type) {
    case RTM_DELLINK:
        printf("[%s] Interface %s removed\n", timestamp, current.ifname);
        /* remove stored entry for this interface */
        (void) net_iface_list_remove_by_index(list, iface_index);
        break;
    case RTM_NEWLINK: {
        unsigned status_changed = current.flags ^ old->flags;
        unsigned carrier_changed = 0;

        if (current.carrier != -1) {
            carrier_changed = current.carrier != old->carrier;
        }

        if (old->index == -1) {
            /* First time reporting status */
            status_changed = 0;
            carrier_changed = 0;
        }

        if ((old->index == -1) || (status_changed & IFF_UP) || carrier_changed) {
            int carrier = current.carrier;
            if (carrier == -1) {
                carrier = old->carrier;
            }

            if (current.change == -1u) {
                /* According to linux kernel when new interface is added change bitmap
                 * is set to max unsigned int. See /net/core/dev.c::register_netdevice
                 */
                printf("[%s] Interface %s added\n", timestamp, current.ifname);
            }

            if (carrier == -1) {
                printf("[%s] Interface %s is %s\n", timestamp, current.ifname,
                       (current.flags & IFF_UP) ? "UP" : "DOWN");
            } else {
                printf("[%s] Interface %s is %s (carrier %s)\n", timestamp, current.ifname,
                       (current.flags & IFF_UP) ? "UP" : "DOWN",
                       carrier ? "ON" : "OFF");
            }
        }

        /* Check if MTU changed */
        if (current.mtu != -1u && current.mtu != old->mtu) {
            if (old->mtu != -1u) {
                printf("[%s] MTU for interface %s changed %u -> %u\n", timestamp, current.ifname,
                       old->mtu, current.mtu);
            } else {
                printf("[%s] MTU for interface %s is set to %u\n", timestamp, current.ifname, current.mtu);
            }
            old->mtu = current.mtu;
        }

        /* Check if mac address changed */
        if (net_iface_is_mac_set(&current) && !net_iface_is_mac_equal(old, &current)) {
            if (!net_iface_is_mac_set(old)) {
                printf("[%s] MAC for interface %s is set to "NL_MAC_STR_FMT"\n", timestamp, current.ifname,
                   NL_MAC_STR_FMT_BYTES(current.mac));
            } else {
                printf("[%s] MAC for interface %s changed "NL_MAC_STR_FMT" -> "NL_MAC_STR_FMT"\n", timestamp, current.ifname,
                       NL_MAC_STR_FMT_BYTES(old->mac), NL_MAC_STR_FMT_BYTES(current.mac));
            }
            memcpy(old->mac, current.mac, sizeof old->mac);
        }

        /* update stored info */
        old->index = current.index;
        old->flags = current.flags;

        if (current.carrier != -1) {
            old->carrier = current.carrier;
        }

        /* ensure name is set (sometimes parsed payload lacks ifname) */
        if (current.ifname[0] != 0 && (old->ifname[0] == 0 || strcmp(old->ifname, current.ifname) != 0)) {
            strncpy(old->ifname, current.ifname, IFNAMSIZ - 1);
            old->ifname[IFNAMSIZ - 1] = '\0';
        }

        break;
    }
    case RTM_DELADDR:
        if (net_iface_is_ipv6_set(&current)) {
            printf("[%s] Removed IPV6 address "NL_IPV6_STR_FMT" from interface %s\n", timestamp,
                   NL_IPV6_STR_FMT_BYTES(current.ipv6), current.ifname);
        } else {
            printf("[%s] Removed IPV4 address "NL_IPV4_STR_FMT" from interface %s\n", timestamp,
                   NL_IPV4_STR_FMT_BYTES(current.ipv4), current.ifname);
        }
        break;
    case RTM_NEWADDR:
        if (net_iface_is_ipv6_set(&current)) {
            printf("[%s] New IPV6 address "NL_IPV6_STR_FMT" set on interface %s\n", timestamp,
                   NL_IPV6_STR_FMT_BYTES(current.ipv6), current.ifname);
        } else {
            printf("[%s] New IPV4 address "NL_IPV4_STR_FMT" set on interface %s\n", timestamp,
                   NL_IPV4_STR_FMT_BYTES(current.ipv4), current.ifname);
        }
        break;
    }
}

static void nl_monitor_start(int socket_fd, const char *filter)
{
    int epfd = epoll_create(1);
    if (epfd == -1) {
        perror("failed epoll_create()");
        return;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.data.fd = socket_fd;

    /* Wait for socket to become ready for reading (edge-triggered) */
    ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, socket_fd, &ev) == -1) {
        perror("failed epoll_ctl()");
        goto err;
    }

    /* Use dynamic list to store seen interfaces (no fixed limit) */
    struct net_iface_list nifaces;
    net_iface_list_init(&nifaces);

    for (;;) {
        struct epoll_event events[NL_MAX_EVENTS];

        int ready = epoll_wait(epfd, events, (sizeof events) / (sizeof *events), -1);

        /* Continue in case epoll_wait was interrupted by signal */
        if (ready == -1 && errno == EINTR) {
            continue;
        }

        if (ready == -1) {
            perror("failed epoll_wait()");
            goto err;
        }

        for (int i = 0; i < ready; i++) {
            if (events[i].events & EPOLLIN) {
                struct msghdr msg;
                struct iovec iov[1];
                char buf[NL_BUF_SIZE];

                memset(&msg, 0, sizeof msg);
                iov[0].iov_base = buf;
                iov[0].iov_len = sizeof buf;
                msg.msg_iov = iov;
                msg.msg_iovlen = 1;

                for (;;) {

                    ssize_t read = recvmsg(events[i].data.fd, &msg, MSG_DONTWAIT);

                    if (read == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            /* Now its safe to invoke edge-triggered epoll_wait */
                            break;
                        } else if (errno == EINTR) {
                            continue;
                        } else {
                            perror("failed recv()");
                            goto err;
                        }
                    } else {
                        /* Check if buffer was to small for message */
                        if (msg.msg_flags & MSG_TRUNC) {
                            fprintf(stderr, "WARNING: received netlink message was truncated\n");
                        }

                        /* Process netlink messages */
                        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                        for (; NLMSG_OK(nlh, read); nlh = NLMSG_NEXT(nlh, read)) {
                            nl_monitor_handle_msg(nlh, &nifaces, filter);
                        }
                    }
                }
            }
        }
    }

err:
    /* cleanup list */
    net_iface_list_free_all(&nifaces);
    close(epfd);
}

int main(int argc, char **argv)
{
    const char *filter = NULL;

    if (argc == 2) {
        filter = argv[1];
    }

    size_t event_mask = RTMGRP_LINK;
    event_mask |= RTMGRP_IPV4_IFADDR;
    event_mask |= RTMGRP_IPV6_IFADDR;

    int nl_socket = nl_monitor_init(event_mask);
    if (nl_socket == -1) {
        return -1;
    }

    nl_monitor_start(nl_socket, filter);

    close(nl_socket);

    return 0;
}