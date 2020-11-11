FROM golang AS proxy
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
COPY main.go ./
RUN go build -o onionproxy


FROM debian:10
ENV DEBIAN_FRONTEND=noninteractive
EXPOSE 80 443

RUN \
		apt-get update && \
		apt-get install -y --no-install-recommends \
		apache2 ssl-cert iptables tor torsocks pdns-recursor \
		&& \
		rm -rf /var/lib/apt/lists/*

RUN a2dissite 000-default default-ssl
RUN a2enmod proxy_http rewrite


RUN rm /etc/powerdns/recursor.conf
RUN rm /etc/tor/*

COPY --from=proxy /usr/src/app/onionproxy /
COPY entrypoint.sh /
COPY recursor.conf /etc/powerdns
COPY proxy.conf /etc/apache2/sites-enabled
COPY torrc /etc/tor
COPY torsocks.conf /etc/tor

ENTRYPOINT ["/entrypoint.sh"]
