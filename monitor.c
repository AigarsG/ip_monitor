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
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>

#define NL_BUF_SIZE 8192
#define NL_MAX_EVENTS 8
#define NL_MONITOR_NET_IFACE_MAX_COUNT 20

struct net_iface {
    int index;
    unsigned flags;
    int carrier;
};

static void net_iface_init(struct net_iface *nifaces, size_t count)
{
    int i;
    for (i = 0; i < count; i++) {
        nifaces[i].index = -1;
        nifaces[i].flags = -1u;
        nifaces[i].carrier = -1;
    }
}

static struct net_iface *net_iface_find_by_index(int index, struct net_iface *nifaces, size_t count)
{
    int i;
    for (i = 0; i < count; i++) {
        if (index == nifaces[i].index) {
            return &nifaces[i];
        }
    }
    return NULL;
}

static struct net_iface *net_iface_next_empty(struct net_iface *nifaces, size_t count)
{
    int i;
    for (i = 0; i < count; i++) {
        if (nifaces[i].index == -1) {
            return &nifaces[i];
        }
    }
    return NULL;
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

static void nl_monitor_handle_msg(const struct nlmsghdr *nlh, struct net_iface *nifaces, size_t count)
{
    /* https://linux.die.net/man/7/rtnetlink */

    /* Description of message attributes can be found here
     * https://www.man7.org/linux/man-pages/man7/rtnetlink.7.html
     */
    struct rtattr *rta;
    char ifname[IFNAMSIZ];
    int carrier = -1;

    /* Length of attributes */
    size_t rtl = IFLA_PAYLOAD(nlh);

    if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {

        struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
        struct net_iface *niface = net_iface_find_by_index(ifi->ifi_index, nifaces, count);
        if (niface == NULL) {
            niface = net_iface_next_empty(nifaces, count);
        }

        /* See uapi/linux/if_link.h */
        /* In order to decode attrs, see
         * https://www.kernel.org/doc/html/next/networking/netlink_spec/rt_link.html#rt-link-attribute-set-link-attrs
         */

        /* Parse attributes */
        for (rta = IFLA_RTA(ifi); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
            switch (rta->rta_type) {
            case IFLA_IFNAME:
                memset(ifname, 0, sizeof ifname);
                memcpy(ifname, RTA_DATA(rta), RTA_PAYLOAD(rta));
                break;
            case IFLA_CARRIER:
                carrier = !!(*((unsigned char *)RTA_DATA(rta)));
                break;
            default:
                break;
            }
        }

        char timestamp[100];
        time_t current_time = time(NULL);
        struct tm *time_struct = localtime(&current_time);

        /* Output timestamp in format YYYY-MM-DD HH:MM:SS */
        strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", time_struct);

        if (nlh->nlmsg_type == RTM_DELLINK) {
            printf("[%s] Interface %s removed\n", timestamp, ifname);
            if (niface) {
                net_iface_init(niface, 1);
            }
        } else {
            /* According to linux kernel when new interface is added change bitmap
             * is set to max unsigned int. See /net/core/dev.c::register_netdevice
             */
            if (ifi->ifi_change == -1u) {
                printf("[%s] Interface %s added\n", timestamp, ifname);
                if (niface) {
                    niface->index = ifi->ifi_index;
                    niface->flags = ifi->ifi_flags;
                    niface->carrier = carrier;
                }
            } else {

                if (niface) {
                    if (niface->index == -1) {
                        /* Report first-time status */
                        printf("[%s] Interface %s is %s (carrier %s)\n", timestamp, ifname,
                               (ifi->ifi_flags & IFF_UP) ? "UP" : "DOWN", carrier ? "ON" : "OFF");
                    } else {
                        unsigned flag_changes = niface->flags ^ ifi->ifi_flags;
                        unsigned carrier_changes = 0;

                        if (carrier != -1) {
                            carrier_changes = niface->carrier != carrier;
                        }

                        if ((flag_changes & IFF_UP) || carrier_changes) {
                            printf("[%s] Interface %s is %s (carrier %s)\n", timestamp, ifname,
                               (ifi->ifi_flags & IFF_UP) ? "UP" : "DOWN", carrier ? "ON" : "OFF");
                        }
                    }
                    niface->index = ifi->ifi_index;
                    niface->flags = ifi->ifi_flags;
                    niface->carrier = carrier;
                } else {
                    /* No place to cache info, try unreliable ifi_change mask */
                    if (ifi->ifi_change & IFF_UP) {
                        printf("[%s] Interface %s is %s (carrier %s)\n", timestamp,
                               ifname, (ifi->ifi_flags & IFF_UP) ? "UP" : "DOWN",
                               carrier ? "ON" : "OFF");
                    }
                }
            }
        }

    }
}

static void nl_monitor_start(int socket_fd)
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

    /* Unfortunatelly we need to cache some data to determine interface changes. For now track
     * up to NL_MONITOR_NET_IFACE_MAX_COUNT interfaces
     */
    int i;
    struct net_iface nifaces[NL_MONITOR_NET_IFACE_MAX_COUNT];
    net_iface_init(nifaces, NL_MONITOR_NET_IFACE_MAX_COUNT);

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

        for (i = 0; i < ready; i++) {
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
                            nl_monitor_handle_msg(nlh, nifaces, NL_MONITOR_NET_IFACE_MAX_COUNT);
                        }
                    }
                }
            }
        }
    }

err:
    close(epfd);
}

int main(int argc, char **argv)
{
    int nl_socket = nl_monitor_init(RTMGRP_LINK);
    if (nl_socket == -1) {
        return -1;
    }

    nl_monitor_start(nl_socket);

    close(nl_socket);

    return 0;
}