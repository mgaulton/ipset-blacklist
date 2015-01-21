#!/bin/bash

#!/bin/sh
if [[ -f /tmp/fwup.running ]] ; then
    exit
fi
touch /tmp/fwup.running

IP_TMP=/tmp/ip.tmp
IP_BLACKLIST=/etc/ip-blacklist.conf
IP_BLACKLIST_TMP=/tmp/ip-blacklist.tmp
IP_BLACKLIST_CUSTOM=/etc/ip-blacklist-custom.conf # optional
BLACKLISTS=(
"http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1" # Project Honey Pot Directory of Dictionary Attacker IPs
"http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"  # TOR Exit Nodes
"https://www.maxmind.com/en/anonymous_proxies" # MaxMind GeoIP Anonymous Proxies
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php" # BruteForceBlocker IP List
"http://www.spamhaus.org/drop/drop.lasso" # Spamhaus Don't Route Or Peer List (DROP)
"http://cinsscore.com/list/ci-badguys.txt" # C.I. Army Malicious IP List
"http://www.openbl.org/lists/base.txt"  # OpenBL.org 30 day List
"http://www.autoshun.org/files/shunlist.csv" # Autoshun Shun List
"http://lists.blocklist.de/lists/all.txt" # blocklist.de attackers
"http://www.stopforumspam.com/downloads/toxic_ip_cidr.txt" # StopForumSpam
"http://feeds.dshield.org/block.txt"
"http://core.nerdtools.co.uk/badbot/latest.txt"
)
for i in "${BLACKLISTS[@]}"
do
    HTTP_RC=`curl -o $IP_TMP -s -w "%{http_code}" "$i"`
    if [ $HTTP_RC -eq 200 -o $HTTP_RC -eq 302 ]; then
        grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $IP_TMP >> $IP_BLACKLIST_TMP
    else
        echo "Error: curl returned HTTP response code $HTTP_RC for URL $i"
    fi
done
sort $IP_BLACKLIST_TMP -n | uniq > $IP_BLACKLIST
rm $IP_BLACKLIST_TMP
wc -l $IP_BLACKLIST


ipset -L blacklist  >/dev/null 2>&1
if [ $? -ne 0 ]; then
	ipset create blacklist hash:net
fi

ipset -L blacklist_tmp  >/dev/null 2>&1
if [ $? -ne 0 ]; then
	ipset create blacklist_tmp hash:net
fi

egrep -v "^#|^$" $IP_BLACKLIST | while IFS= read -r ip
do
        ipset  -exist add blacklist_tmp $ip
done

if [ -f $IP_BLACKLIST_CUSTOM ]; then
        egrep -v "^#|^$" $IP_BLACKLIST_CUSTOM | while IFS= read -r ip
        do
                ipset add blacklist_tmp $ip
        done
fi
python rulecheck.py blacklist
ipset swap blacklist blacklist_tmp
ipset destroy blacklist_tmp
rm -f /tmp/fwup.running
