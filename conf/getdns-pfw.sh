#! /bin/sh
set +e
logger -i "flushing port forwarding for getdns error pages"
iptables -t nat -D OUTPUT -p tcp --dst 127.127.127.128,127.127.127.127 --dport 80 -j REDIRECT --to-ports 8080
logger -i "[`date`] : activating port forwarding[getdns-errors.localhost:80->8080] for getdns error pages"
logger -i "Activation command: iptables -t nat -A OUTPUT -p tcp --dst 127.127.127.128,127.127.127.127 --dport 80 -j REDIRECT --to-ports 8080"
iptables -t nat -A OUTPUT -p tcp --dst 127.127.127.128,127.127.127.127 --dport 80 -j REDIRECT --to-ports 8080
logger -i "Exit code: `echo $?`"
