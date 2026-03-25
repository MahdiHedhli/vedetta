FROM fluent/fluent-bit:3.0

COPY config/fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY config/parsers.conf /fluent-bit/etc/parsers.conf

EXPOSE 5140/udp
