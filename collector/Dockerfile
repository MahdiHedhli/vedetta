FROM fluent/fluent-bit:5.0

COPY config/fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY config/parsers.conf /fluent-bit/etc/parsers.conf
COPY config/pihole_transform.lua /fluent-bit/etc/pihole_transform.lua
COPY config/unifi_transform.lua /fluent-bit/etc/unifi_transform.lua

EXPOSE 5140/udp
