#!/bin/sh
echo nameserver 127.0.0.1 > /etc/resolv.conf && \
iptables -t nat -A OUTPUT -d 127.255.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040 && \
service tor start && \
service pdns-recursor start && \
service apache2 start && \
/onionproxy;