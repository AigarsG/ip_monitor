## About
Simple network interface monitoring program based on netlink which captures link layer and IPv4/IPv6 address changes.

## Approach
1) Netlink socket is opened
2) epoll instance is used to wait for the netlink socket to become readable
3) Once readable, the program reads and parses netlink messages, caching per-interface state in a dynamically sized linked list. Reading continues until recvmsg() returns EAGAIN or EWOULDBLOCK, indicating there is no more data to read.
4) Either the current interface state is output or the detected changes (compared to the cached state) are output.
5) Back to step 2

## Build
`cd ip_monitor && make`

## Execute and check
On one terminal monitor changes on all interfaces by running:
```
[term1] ./monitor
```
or monitor a particular interface:
```
[term1] ./monitor enp1s0
```
or monitor a set of interfaces starting with a prefix:
```
[term1] ./monitor enp*
```

On another terminal verify changes are monitored:
```
[term2] sudo ip link add eth99 type dummy
```
```
[term1] [2025-12-03 22:04:10] Interface eth99 added
[term1] [2025-12-03 22:04:10] Interface eth99 is DOWN (carrier ON)
[term1] [2025-12-03 22:04:10] MTU for interface eth99 is set to 1500
[term1] [2025-12-03 22:04:10] MAC for interface eth99 is set to e6:ad:cf:a9:fd:4f
```
```
[term2] sudo ip link set dev eth99 up
```
```
[term1] [2025-12-03 22:06:36] Interface eth99 is UP (carrier ON)
[term1] [2025-12-03 22:06:36] New IPV6 address fe80:0000:0000:0000:e4ad:cfff:fea9:fd4f set on interface eth99
```
```
[term2] sudo ip link set dev eth99 down
```
```
[term1] [2025-12-03 22:07:19] Interface eth99 is DOWN (carrier ON)
[term1] [2025-12-03 22:07:19] Removed IPV6 address fe80:0000:0000:0000:e4ad:cfff:fea9:fd4f from interface eth99
```
```
[term2] sudo ip link set dev eth99 mtu 2000
```
```
[term1] [2025-12-03 22:07:55] MTU for interface eth99 changed 1500 -> 2000
```
```
[term2] sudo ip link set dev eth99 address e6:ad:cf:a9:fd:fd
```
```
[term1] [2025-12-03 22:08:44] MAC for interface eth99 changed e6:ad:cf:a9:fd:4f -> e6:ad:cf:a9:fd:fd
```
```
[term2] sudo ip addr add 192.168.69.69/25 dev eth99
```
```
[term1] [2025-12-03 22:10:11] New IPV4 address 192.168.69.69 set on interface eth99
```
```
[term2] sudo ip addr del 192.168.69.69/25 dev eth99
```
```
[term1] [2025-12-03 22:10:40] Removed IPV4 address 192.168.69.69 from interface eth99
```