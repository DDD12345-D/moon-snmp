# A stock net-snmp agent and notification receiver, used by the end-to-end
# harnesses in this directory.
#
#   docker build -t moon-snmp-e2e e2e/docker
#
# The base image is an argument so the same file works in CI (plain
# docker hub, no proxy needed) and behind a network that needs a mirror:
#
#   docker build --build-arg BASE=<mirror>/library/alpine:latest \
#     -t moon-snmp-e2e e2e/docker
#
# One image, two roles: the default command is the agent, and the CI runs
# it again with `snmptrapd` as the command to get the notification
# receiver.
ARG BASE=alpine:latest

FROM ${BASE}

# net-snmp is the daemon and the library; net-snmp-tools is snmpwalk,
# snmpget and snmptrap, which the harnesses use as an independent second
# implementation to check ours against.
RUN apk add --no-cache net-snmp net-snmp-tools

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY snmptrapd.conf /etc/snmp/snmptrapd.conf

EXPOSE 161/udp
EXPOSE 162/udp

CMD ["snmpd", "-f", "-Lo", "-c", "/etc/snmp/snmpd.conf"]
