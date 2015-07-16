#!/bin/bash
os="$(uname -s)"
case $os in
*BSD*)
	REDIRECTION_RULE_SET="natd -redirect_port tcp getdns-config.localhost:8080 getdns-config.localhost:http; 
	natd -redirect_port tcp getdns-errors.localhost:8080 getdns-errors.localhost:http"
	REDIRECTION_RULE_UNSET=""
	;;
*Linux*)
	REDIRECTION_RULE_SET="iptables -o lo -t nat -A OUTPUT -p tcp --dst getdns-config.localhost,getdns-errors.localhost --dport 80 -j REDIRECT --to-ports 8080"
	REDIRECTION_RULE_UNSET="iptables -o lo -t nat -D OUTPUT -p tcp --dst getdns-config.localhost,getdns-errors.localhost --dport 80 -j REDIRECT --to-ports 8080"
	;;
esac
if [ -n "$1" ]           
then
	if [ "$1" = "--reverse" ]
	then
		echo "$REDIRECTION_RULE_UNSET"
		eval "$REDIRECTION_RULE_UNSET"
	else
		echo "Unknown option: $1"
		exit 1
	fi
else
	echo "$REDIRECTION_RULE_UNSET"
	eval "$REDIRECTION_RULE_UNSET"
	echo "$REDIRECTION_RULE_SET"
	eval "$REDIRECTION_RULE_SET"
fi 
