/*
monitor.c (refactor)
- Replaced fixed-size array of monitored interfaces with a dynamic linked list.
- Added unique per-interface IPv4/IPv6 address lists to deduplicate multiple
  RTM_NEWADDR notifications for the same address.
- Introduced a generic linked-list node (llnode) and a generic list manager
  (net_iface_list) that stores head/tail/count. Each llnode contains a fixed
  sized data[] buffer to avoid many small allocations; data_size indicates the
  actual payload size stored in the node.
- Added signal handler (SIGINT/SIGTERM) and graceful shutdown to ensure all
  dynamically allocated llnodes are freed before process exit (fixes valgrind
  "still reachable" blocks).
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
#include <stdint.h>
#include <signal.h>

#define NL_BUF_SIZE 8192
#define NL_MAX_EVENTS 8
/* removed fixed-size interface limit to allow arbitrary number of interfaces */
/* #define NL_MONITOR_NET_IFACE_MAX_COUNT 20 */
#define NL_IPV4_LEN 4
#define NL_IPV6_LEN 16

/* LLNODE_DATA_MAX_SIZE must fit struct net_iface (without prev/next) and IPv6 addr */
#define LLNODE_DATA_MAX_SIZE 256

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

/* Stop flag set by signal handler to request graceful shutdown */
static volatile sig_atomic_t g_stop = 0;

static void handle_sigint(int signum)
{
    (void)signum;
    g_stop = 1;
}

/* Generic linked-list node with embedded fixed-size data buffer */
struct llnode {
    struct llnode *prev;
    struct llnode *next;
    size_t data_size;
    unsigned char data[LLNODE_DATA_MAX_SIZE];
};

/* Generic list manager; name preserved as net_iface_list per guidelines */
struct net_iface_list {
    struct llnode *head;
    struct llnode *tail;
    size_t count;
};

/* Per-interface state (payload stored inside an llnode when used in a list) */
struct net_iface {
    int index;
    char ifname[IFNAMSIZ];
    unsigned flags;
    unsigned change;
    int carrier;
    unsigned mtu;
    unsigned char mac[ETH_ALEN];

    /* ipv4 and ipv6 address lists (each element holds raw address bytes) */
    struct net_iface_list ipv4_addrs; /* nodes hold 4-byte payloads */
    struct net_iface_list ipv6_addrs; /* nodes hold 16-byte payloads */
};

/* ---------- Generic llnode/list helpers ---------- */

static void llist_init(struct net_iface_list *list)
{
    if (!list) return;
    list->head = list->tail = NULL;
    list->count = 0;
}

static void llist_free_all(struct net_iface_list *list)
{
    if (!list) return;
    struct llnode *it = list->head;
    while (it) {
        struct llnode *next = it->next;
        free(it);
        it = next;
    }
    list->head = list->tail = NULL;
    list->count = 0;
}

/* Add raw data into a new llnode at tail; data is copied into node->data.
 * Returns pointer to created llnode or NULL on error.
 */
static struct llnode *llist_add_raw(struct net_iface_list *list, const void *data, size_t data_size)
{
    if (!list || !data || data_size == 0 || data_size > LLNODE_DATA_MAX_SIZE) return NULL;
    struct llnode *n = malloc(sizeof(*n));
    if (!n) return NULL;
    n->prev = list->tail;
    n->next = NULL;
    n->data_size = data_size;
    memcpy(n->data, data, data_size);
    if (list->tail) list->tail->next = n;
    list->tail = n;
    if (!list->head) list->head = n;
    list->count++;
    return n;
}

/* Find node by exact data match (size+memcmp). Returns node pointer or NULL */
static struct llnode *llist_find_node_by_data(struct net_iface_list *list, const void *data, size_t data_size)
{
    if (!list || !data || data_size == 0) return NULL;
    struct llnode *it = list->head;
    while (it) {
        if (it->data_size == data_size && memcmp(it->data, data, data_size) == 0) {
            return it;
        }
        it = it->next;
    }
    return NULL;
}

/* Remove given node (unlink and free) */
static void llist_remove_node(struct net_iface_list *list, struct llnode *node)
{
    if (!list || !node) return;
    if (node->prev) node->prev->next = node->next;
    else list->head = node->next;
    if (node->next) node->next->prev = node->prev;
    else list->tail = node->prev;
    list->count--;
    free(node);
}

/* Add unique data: if data exists, return 0; if added successfully return 1; on error -1 */
static int llist_add_unique(struct net_iface_list *list, const void *data, size_t data_size)
{
    if (!list || !data || data_size == 0) return -1;
    if (llist_find_node_by_data(list, data, data_size)) return 0;
    struct llnode *n = llist_add_raw(list, data, data_size);
    return n ? 1 : -1;
}

/* Remove by data; returns 1 if removed, 0 if not found, -1 on error */
static int llist_remove_by_data(struct net_iface_list *list, const void *data, size_t data_size)
{
    if (!list || !data || data_size == 0) return -1;
    struct llnode *n = llist_find_node_by_data(list, data, data_size);
    if (!n) return 0;
    llist_remove_node(list, n);
    return 1;
}

/* ---------- net_iface-specific list API (keeps old naming) ---------- */

/* initialize a single net_iface payload (reset fields) */
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
    llist_init(&niface->ipv4_addrs);
    llist_init(&niface->ipv6_addrs);
}

/* net_iface_list is used as a generic list manager that stores llnodes whose
 * payload is a struct net_iface. Keep API names as before but operate on
 * llnodes underneath.
 */
static void net_iface_list_init(struct net_iface_list *list)
{
    llist_init(list);
}

/* Free all llnodes; used on top-level list (will free stored net_iface payloads
 * but must also free nested addr lists first — handled in removal helper).
 */
static void net_iface_list_free_all(struct net_iface_list *list)
{
    if (!list) return;
    /* For net_iface list we must clean up nested address lists for each stored iface */
    struct llnode *it = list->head;
    while (it) {
        /* access stored net_iface payload */
        if (it->data_size >= sizeof(struct net_iface)) {
            struct net_iface *stored = (struct net_iface *)it->data;
            llist_free_all(&stored->ipv4_addrs);
            llist_free_all(&stored->ipv6_addrs);
        }
        it = it->next;
    }
    /* Now free all nodes themselves */
    llist_free_all(list);
}

/* Add an empty net_iface entry and return pointer to the stored struct net_iface (or NULL) */
static struct net_iface *net_iface_list_add_empty(struct net_iface_list *list)
{
    if (!list) return NULL;
    /* create zeroed payload of size struct net_iface */
    unsigned char tmp[sizeof(struct net_iface)];
    memset(tmp, 0, sizeof tmp);
    struct llnode *n = llist_add_raw(list, tmp, sizeof(struct net_iface));
    if (!n) return NULL;
    struct net_iface *stored = (struct net_iface *)n->data;
    net_iface_init_one(stored);
    return stored;
}

/* Find by index: return pointer to stored struct net_iface or NULL */
static struct net_iface *net_iface_list_find_by_index(struct net_iface_list *list, int index)
{
    if (!list) return NULL;
    struct llnode *it = list->head;
    while (it) {
        if (it->data_size >= sizeof(struct net_iface)) {
            struct net_iface *stored = (struct net_iface *)it->data;
            if (stored->index == index) return stored;
        }
        it = it->next;
    }
    return NULL;
}

/* Remove a net_iface by index; frees nested addr lists and the node */
static int net_iface_list_remove_by_index(struct net_iface_list *list, int index)
{
    if (!list) return -1;
    struct llnode *it = list->head;
    while (it) {
        if (it->data_size >= sizeof(struct net_iface)) {
            struct net_iface *stored = (struct net_iface *)it->data;
            if (stored->index == index) {
                /* free nested address lists first */
                llist_free_all(&stored->ipv4_addrs);
                llist_free_all(&stored->ipv6_addrs);
                /* now remove this node */
                llist_remove_node(list, it);
                return 0;
            }
        }
        it = it->next;
    }
    return -1;
}

/* Helper to add unique address to per-interface addr list.
 * addr_len must be 4 (IPv4) or 16 (IPv6). Returns:
 *  1 = added (unique)
 *  0 = already present (duplicate)
 * -1 = error
 */
static int net_iface_address_add_unique(struct net_iface_list *addr_list, const unsigned char *addr, size_t addr_len)
{
    return llist_add_unique(addr_list, addr, addr_len);
}

/* Helper to remove address from per-interface addr list.
 * Returns 1 if removed, 0 if not found, -1 on error.
 */
static int net_iface_address_remove(struct net_iface_list *addr_list, const unsigned char *addr, size_t addr_len)
{
    return llist_remove_by_data(addr_list, addr, addr_len);
}

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

/* ---------- netlink socket / parsing (mostly unchanged) ---------- */

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

/* Parsing helpers identical to previous behavior, but note: temporary 'current'
 * we use here keeps ipv4/ipv6 buffers local so that we can add/remove them to
 * per-interface lists.
 */
static void nl_monitor_parse_rtmgrp_link(const struct nlmsghdr *nlh, struct net_iface *niface, unsigned char *tmp_ipv4, unsigned char *tmp_ipv6)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    struct rtattr *rtattr;
    size_t rtattrlen = IFLA_PAYLOAD(nlh);

    niface->index = ifi->ifi_index;
    niface->flags = ifi->ifi_flags;
    niface->change = ifi->ifi_change;

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
            memset(niface->mac, 0, sizeof niface->mac);
            memcpy(niface->mac, (unsigned char *)RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
            break;
        default:
            break;
        }
    }
    /* tmp ipv4/ipv6 not used in link parsing */
    (void)tmp_ipv4;
    (void)tmp_ipv6;
}

static void nl_monitor_parse_rtmgrp_addr(const struct nlmsghdr *nlh, unsigned char *tmp_ipv4, unsigned char *tmp_ipv6, int *is_ipv6)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    struct rtattr *rtattr;
    size_t rtattrlen = IFA_PAYLOAD(nlh);

    /* initialize flags */
    *is_ipv6 = 0;
    memset(tmp_ipv4, 0, NL_IPV4_LEN);
    memset(tmp_ipv6, 0, NL_IPV6_LEN);

    for (rtattr = IFA_RTA(ifa); RTA_OK(rtattr, rtattrlen); rtattr = RTA_NEXT(rtattr, rtattrlen)) {
        switch (rtattr->rta_type) {
        case IFA_ADDRESS:
            if (RTA_PAYLOAD(rtattr) == NL_IPV6_LEN) {
                memcpy(tmp_ipv6, (unsigned char *)RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
                *is_ipv6 = 1;
            } else {
                memcpy(tmp_ipv4, (unsigned char *)RTA_DATA(rtattr), RTA_PAYLOAD(rtattr));
                *is_ipv6 = 0;
            }
            break;
        default:
            break;
        }
    }
}

/* Now handle messages using dynamically-sized lists and per-interface address lists */
static void nl_monitor_handle_msg(const struct nlmsghdr *nlh, struct net_iface_list *list,
                                  const char *filter)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);

    int iface_index;
    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
        iface_index = ifa->ifa_index;
    } else {
        iface_index = ifi->ifi_index;
    }

    /* Try to find stored iface by index */
    struct net_iface *old = net_iface_list_find_by_index(list, iface_index);

    /* If we don't have a stored entry, create one (no fixed limit) */
    if (old == NULL) {
        old = net_iface_list_add_empty(list);
        if (!old) {
            fprintf(stderr, "ERROR: memory allocation failed for new interface entry\n");
            return;
        }
        /* index will be filled by parsing */
        old->index = -1;
    }

    char timestamp[100];
    time_t current_time = time(NULL);
    struct tm *time_struct = localtime(&current_time);

    /* Output timestamp in format YYYY-MM-DD HH:MM:SS */
    strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", time_struct);

    /* Temporary current info and tmp addr buffers */
    struct net_iface current_tmp;
    net_iface_init_one(&current_tmp); /* initializes nested lists but they won't be used for temp */
    unsigned char tmp_ipv4[NL_IPV4_LEN];
    unsigned char tmp_ipv6[NL_IPV6_LEN];
    int tmp_is_ipv6 = 0;

    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
        nl_monitor_parse_rtmgrp_addr(nlh, tmp_ipv4, tmp_ipv6, &tmp_is_ipv6);
    } else {
        nl_monitor_parse_rtmgrp_link(nlh, &current_tmp, tmp_ipv4, tmp_ipv6);
    }

    if (current_tmp.ifname[0] == 0) {
        if_indextoname(iface_index, current_tmp.ifname);
    }

    if (net_iface_should_ignore(&current_tmp, filter)) {
        return;
    }

    switch (nlh->nlmsg_type) {
    case RTM_DELLINK:
        printf("[%s] Interface %s removed\n", timestamp, current_tmp.ifname);
        /* remove stored entry for this interface (frees nested addr lists) */
        (void) net_iface_list_remove_by_index(list, iface_index);
        break;
    case RTM_NEWLINK: {
        /* When handling links, old points to stored payload (may have index -1) */
        unsigned status_changed = current_tmp.flags ^ old->flags;
        unsigned carrier_changed = 0;

        if (current_tmp.carrier != -1) {
            carrier_changed = current_tmp.carrier != old->carrier;
        }

        if (old->index == -1) {
            /* First time reporting status */
            status_changed = 0;
            carrier_changed = 0;
        }

        if ((old->index == -1) || (status_changed & IFF_UP) || carrier_changed) {
            int carrier = current_tmp.carrier;
            if (carrier == -1) {
                carrier = old->carrier;
            }

            if (current_tmp.change == -1u) {
                /* According to linux kernel when new interface is added change bitmap
                 * is set to max unsigned int. See /net/core/dev.c::register_netdevice
                 */
                printf("[%s] Interface %s added\n", timestamp, current_tmp.ifname);
            }

            if (carrier == -1) {
                printf("[%s] Interface %s is %s\n", timestamp, current_tmp.ifname,
                       (current_tmp.flags & IFF_UP) ? "UP" : "DOWN");
            } else {
                printf("[%s] Interface %s is %s (carrier %s)\n", timestamp, current_tmp.ifname,
                       (current_tmp.flags & IFF_UP) ? "UP" : "DOWN",
                       carrier ? "ON" : "OFF");
            }
        }

        /* Check if MTU changed */
        if (current_tmp.mtu != -1u && current_tmp.mtu != old->mtu) {
            if (old->mtu != -1u) {
                printf("[%s] MTU for interface %s changed %u -> %u\n", timestamp, current_tmp.ifname,
                       old->mtu, current_tmp.mtu);
            } else {
                printf("[%s] MTU for interface %s is set to %u\n", timestamp, current_tmp.ifname, current_tmp.mtu);
            }
            old->mtu = current_tmp.mtu;
        }

        /* Check if mac address changed */
        if (net_iface_is_mac_set(&current_tmp) && !net_iface_is_mac_equal(old, &current_tmp)) {
            if (!net_iface_is_mac_set(old)) {
                printf("[%s] MAC for interface %s is set to "NL_MAC_STR_FMT"\n", timestamp, current_tmp.ifname,
                   NL_MAC_STR_FMT_BYTES(current_tmp.mac));
            } else {
                printf("[%s] MAC for interface %s changed "NL_MAC_STR_FMT" -> "NL_MAC_STR_FMT"\n", timestamp, current_tmp.ifname,
                       NL_MAC_STR_FMT_BYTES(old->mac), NL_MAC_STR_FMT_BYTES(current_tmp.mac));
            }
            memcpy(old->mac, current_tmp.mac, sizeof old->mac);
        }

        /* update stored info */
        old->index = current_tmp.index;
        old->flags = current_tmp.flags;

        if (current_tmp.carrier != -1) {
            old->carrier = current_tmp.carrier;
        }

        /* ensure name is set (sometimes parsed payload lacks ifname) */
        if (current_tmp.ifname[0] != 0 && (old->ifname[0] == 0 || strcmp(old->ifname, current_tmp.ifname) != 0)) {
            strncpy(old->ifname, current_tmp.ifname, IFNAMSIZ - 1);
            old->ifname[IFNAMSIZ - 1] = '\0';
        }

        break;
    }
    case RTM_DELADDR: {
        /* tmp_is_ipv6 indicates which buffer is filled */
        if (tmp_is_ipv6) {
            int removed = net_iface_address_remove(&old->ipv6_addrs, tmp_ipv6, NL_IPV6_LEN);
            if (removed == 1) {
                printf("[%s] Removed IPV6 address "NL_IPV6_STR_FMT" from interface %s\n", timestamp,
                       NL_IPV6_STR_FMT_BYTES(tmp_ipv6), current_tmp.ifname);
            } else {
                /* ignore duplicate del notifications for unknown address */
            }
        } else {
            int removed = net_iface_address_remove(&old->ipv4_addrs, tmp_ipv4, NL_IPV4_LEN);
            if (removed == 1) {
                printf("[%s] Removed IPV4 address "NL_IPV4_STR_FMT" from interface %s\n", timestamp,
                       NL_IPV4_STR_FMT_BYTES(tmp_ipv4), current_tmp.ifname);
            } else {
                /* ignore duplicate del notifications for unknown address */
            }
        }
        break;
    }
    case RTM_NEWADDR: {
        if (tmp_is_ipv6) {
            int added = net_iface_address_add_unique(&old->ipv6_addrs, tmp_ipv6, NL_IPV6_LEN);
            if (added == 1) {
                printf("[%s] New IPV6 address "NL_IPV6_STR_FMT" set on interface %s\n", timestamp,
                       NL_IPV6_STR_FMT_BYTES(tmp_ipv6), current_tmp.ifname);
            } else {
                /* duplicate newaddr notification -> ignore */
            }
        } else {
            int added = net_iface_address_add_unique(&old->ipv4_addrs, tmp_ipv4, NL_IPV4_LEN);
            if (added == 1) {
                printf("[%s] New IPV4 address "NL_IPV4_STR_FMT" set on interface %s\n", timestamp,
                       NL_IPV4_STR_FMT_BYTES(tmp_ipv4), current_tmp.ifname);
            } else {
                /* duplicate newaddr notification -> ignore */
            }
        }
        break;
    }
    }
}

/* Modified to support graceful shutdown via g_stop flag set by SIGINT/SIGTERM.
 * The function returns after cleanup (so main can close socket_fd).
 */
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

    while (!g_stop) {
        struct epoll_event events[NL_MAX_EVENTS];

        int ready = epoll_wait(epfd, events, (sizeof events) / (sizeof *events), -1);

        /* If interrupted by signal, check stop flag and break if requested */
        if (ready == -1) {
            if (errno == EINTR) {
                if (g_stop) break;
                else continue;
            }
            perror("failed epoll_wait()");
            goto err_cleanup;
        }

        for (int i = 0; i < ready && !g_stop; i++) {
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
                    if (g_stop) break;

                    ssize_t read_len = recvmsg(events[i].data.fd, &msg, MSG_DONTWAIT);

                    if (read_len == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            /* Now its safe to invoke edge-triggered epoll_wait */
                            break;
                        } else if (errno == EINTR) {
                            if (g_stop) break;
                            else continue;
                        } else {
                            perror("failed recv()");
                            goto err_cleanup;
                        }
                    } else {
                        /* Check if buffer was too small for message */
                        if (msg.msg_flags & MSG_TRUNC) {
                            fprintf(stderr, "WARNING: received netlink message was truncated\n");
                        }

                        /* Process netlink messages */
                        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                        for (; NLMSG_OK(nlh, read_len) && !g_stop; nlh = NLMSG_NEXT(nlh, read_len)) {
                            nl_monitor_handle_msg(nlh, &nifaces, filter);
                        }
                    }
                }
            }
        }
    }

err_cleanup:
    /* cleanup list (frees nested addr lists too) */
    net_iface_list_free_all(&nifaces);
    close(epfd);
    return;

err:
    /* If we reached an unrecoverable error path, still cleanup */
    net_iface_list_free_all(&nifaces);
    close(epfd);
    return;
}

int main(int argc, char **argv)
{
    /* Install signal handler for graceful shutdown so we free allocated memory */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

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