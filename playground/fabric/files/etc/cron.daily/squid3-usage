#!/bin/bash

SQUIDLOG="/var/log/squid3/access.log.1"
USAGELOG="/var/log/squid3-usage.log"

(   
    echo -n "`date '+%Y-%m-%d'`:"
    cat $SQUIDLOG | awk '{print $8 }' | sort | grep -v "^-$" | uniq -c | awk '{printf " " $2 "=" $1}'
    echo "" 
) >> $USAGELOG
