#!/bin/bash
IP_BLACKLIST_DIR=/etc/ipset-blacklist
IPSET_BLACKLIST_NAME=blacklist # change it if it collides with a pre-existing ipset list
IPSET_TMP_BLACKLIST_NAME=${IPSET_BLACKLIST_NAME}-tmp
IP_BLACKLIST_RESTORE=${IP_BLACKLIST_DIR}/ip-blacklist.restore
IP_BLACKLIST=${IP_BLACKLIST_DIR}/ip-blacklist.list
IP_BLACKLIST_CUSTOM=${IP_BLACKLIST_DIR}/ip-blacklist-custom.list # optional, for your personal nemeses (no typo, plural)
HASHSIZE=128 # the initial hash size for the set. Don't touch unless you know what you're doing.
MAXELEM=1048575 # the maximal number of elements which can be stored in the set

# List of URLs for IP blacklists. Currently, only IPv4 is supported in this script, everything else will be filtered.
BLACKLISTS=(
"http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1" # Project Honey Pot Directory of Dictionary Attacker IPs
"http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"  # TOR Exit Nodes
"https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list" # MaxMind GeoIP Anonymous Proxies
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php" # BruteForceBlocker IP List
"http://www.spamhaus.org/drop/drop.lasso" # Spamhaus Don't Route Or Peer List (DROP)
"http://cinsscore.com/list/ci-badguys.txt" # C.I. Army Malicious IP List
"http://www.openbl.org/lists/base.txt"  # OpenBL.org 30 day List
"http://www.autoshun.org/files/shunlist.csv" # Autoshun Shun List
"http://lists.blocklist.de/lists/all.txt" # blocklist.de attackers
"http://www.stopforumspam.com/downloads/toxic_ip_cidr.txt" # StopForumSpam
#
"http://feeds.dshield.org/block.txt"
"http://core.nerdtools.co.uk/badbot/latest.txt"
"http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
"https://zeustracker.abuse.ch/blocklist.php?download=badips"
"https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist"
"http://malc0de.com/bl/IP_Blacklist.txt"
#"http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
#"http://www.ipdeny.com/ipblocks/data/countries/ca.zone"
#"http://www.ipdeny.com/ipblocks/data/countries/us.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ad.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ae.zone"
"http://www.ipdeny.com/ipblocks/data/countries/af.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ag.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ai.zone"
"http://www.ipdeny.com/ipblocks/data/countries/al.zone"
"http://www.ipdeny.com/ipblocks/data/countries/am.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ao.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ap.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ar.zone"
"http://www.ipdeny.com/ipblocks/data/countries/as.zone"
"http://www.ipdeny.com/ipblocks/data/countries/at.zone"
"http://www.ipdeny.com/ipblocks/data/countries/au.zone"
"http://www.ipdeny.com/ipblocks/data/countries/aw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/az.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ba.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bb.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bd.zone"
"http://www.ipdeny.com/ipblocks/data/countries/be.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bh.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bi.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bj.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bo.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bq.zone"
"http://www.ipdeny.com/ipblocks/data/countries/br.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bs.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/by.zone"
"http://www.ipdeny.com/ipblocks/data/countries/bz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cd.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ch.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ci.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ck.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cl.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/co.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cv.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cy.zone"
"http://www.ipdeny.com/ipblocks/data/countries/cz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/de.zone"
"http://www.ipdeny.com/ipblocks/data/countries/dj.zone"
"http://www.ipdeny.com/ipblocks/data/countries/dk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/dm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/do.zone"
"http://www.ipdeny.com/ipblocks/data/countries/dz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ec.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ee.zone"
"http://www.ipdeny.com/ipblocks/data/countries/eg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/er.zone"
"http://www.ipdeny.com/ipblocks/data/countries/es.zone"
"http://www.ipdeny.com/ipblocks/data/countries/et.zone"
"http://www.ipdeny.com/ipblocks/data/countries/eu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/fi.zone"
"http://www.ipdeny.com/ipblocks/data/countries/fj.zone"
"http://www.ipdeny.com/ipblocks/data/countries/fm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/fo.zone"
"http://www.ipdeny.com/ipblocks/data/countries/fr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ga.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gb.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gd.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ge.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gh.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gi.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gl.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gp.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gq.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/gy.zone"
"http://www.ipdeny.com/ipblocks/data/countries/hk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/hn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/hr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ht.zone"
"http://www.ipdeny.com/ipblocks/data/countries/hu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/id.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ie.zone"
"http://www.ipdeny.com/ipblocks/data/countries/il.zone"
"http://www.ipdeny.com/ipblocks/data/countries/im.zone"
"http://www.ipdeny.com/ipblocks/data/countries/in.zone"
"http://www.ipdeny.com/ipblocks/data/countries/io.zone"
"http://www.ipdeny.com/ipblocks/data/countries/iq.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ir.zone"
"http://www.ipdeny.com/ipblocks/data/countries/is.zone"
"http://www.ipdeny.com/ipblocks/data/countries/it.zone"
"http://www.ipdeny.com/ipblocks/data/countries/je.zone"
"http://www.ipdeny.com/ipblocks/data/countries/jm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/jo.zone"
"http://www.ipdeny.com/ipblocks/data/countries/jp.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ke.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kh.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ki.zone"
"http://www.ipdeny.com/ipblocks/data/countries/km.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kp.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ky.zone"
"http://www.ipdeny.com/ipblocks/data/countries/kz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/la.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lb.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lc.zone"
"http://www.ipdeny.com/ipblocks/data/countries/li.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ls.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/lv.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ly.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ma.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mc.zone"
"http://www.ipdeny.com/ipblocks/data/countries/md.zone"
"http://www.ipdeny.com/ipblocks/data/countries/me.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mh.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ml.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mo.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mp.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mq.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ms.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mv.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mx.zone"
"http://www.ipdeny.com/ipblocks/data/countries/my.zone"
"http://www.ipdeny.com/ipblocks/data/countries/mz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/na.zone"
"http://www.ipdeny.com/ipblocks/data/countries/nc.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ne.zone"
"http://www.ipdeny.com/ipblocks/data/countries/nf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ng.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ni.zone"
"http://www.ipdeny.com/ipblocks/data/countries/nl.zone"
"http://www.ipdeny.com/ipblocks/data/countries/no.zone"
"http://www.ipdeny.com/ipblocks/data/countries/np.zone"
"http://www.ipdeny.com/ipblocks/data/countries/nr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/nu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/nz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/om.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pa.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pe.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ph.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pl.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ps.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/pw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/py.zone"
"http://www.ipdeny.com/ipblocks/data/countries/qa.zone"
"http://www.ipdeny.com/ipblocks/data/countries/re.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ro.zone"
"http://www.ipdeny.com/ipblocks/data/countries/rs.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ru.zone"
"http://www.ipdeny.com/ipblocks/data/countries/rw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sa.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sb.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sc.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sd.zone"
"http://www.ipdeny.com/ipblocks/data/countries/se.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/si.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sl.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/so.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ss.zone"
"http://www.ipdeny.com/ipblocks/data/countries/st.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sv.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sx.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sy.zone"
"http://www.ipdeny.com/ipblocks/data/countries/sz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tc.zone"
"http://www.ipdeny.com/ipblocks/data/countries/td.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/th.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tj.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tk.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tl.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/to.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tr.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tv.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tw.zone"
"http://www.ipdeny.com/ipblocks/data/countries/tz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ua.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ug.zone"
"http://www.ipdeny.com/ipblocks/data/countries/uy.zone"
"http://www.ipdeny.com/ipblocks/data/countries/uz.zone"
"http://www.ipdeny.com/ipblocks/data/countries/va.zone"
"http://www.ipdeny.com/ipblocks/data/countries/vc.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ve.zone"
"http://www.ipdeny.com/ipblocks/data/countries/vg.zone"
"http://www.ipdeny.com/ipblocks/data/countries/vi.zone"
"http://www.ipdeny.com/ipblocks/data/countries/vn.zone"
"http://www.ipdeny.com/ipblocks/data/countries/vu.zone"
"http://www.ipdeny.com/ipblocks/data/countries/wf.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ws.zone"
"http://www.ipdeny.com/ipblocks/data/countries/ye.zone"
"http://www.ipdeny.com/ipblocks/data/countries/yt.zone"
"http://www.ipdeny.com/ipblocks/data/countries/za.zone"
"http://www.ipdeny.com/ipblocks/data/countries/zm.zone"
"http://www.ipdeny.com/ipblocks/data/countries/zw.zone"
)

for command in ipset iptables egrep grep curl sort uniq wc
do
    if ! which $command > /dev/null; then
        echo "Error: please install $command"
        exit 1
    fi
done

if [ ! -d $IP_BLACKLIST_DIR ]; then
    echo "Error: please create $IP_BLACKLIST_DIR directory"
    exit 1
fi

if [ -f /etc/ip-blacklist.conf ]; then
    echo "Error: please remove /etc/ip-blacklist.conf"
    exit 1
fi

if [ -f /etc/ip-blacklist-custom.conf ]; then
    echo "Error: please move /etc/ip-blacklist-custom.conf to the $IP_BLACKLIST_DIR directory and rename it to $IP_BLACKLIST_CUSTOM"
    exit 1
fi

IP_BLACKLIST_TMP=$(mktemp)
for i in "${BLACKLISTS[@]}"
do
    IP_TMP=$(mktemp)
    HTTP_RC=`curl --connect-timeout 10 --max-time 10 -o $IP_TMP -s -w "%{http_code}" "$i"`
    if [ $HTTP_RC -eq 200 -o $HTTP_RC -eq 302 ]; then
        grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $IP_TMP >> $IP_BLACKLIST_TMP
	echo -n "."
    else
        echo -e "\nWarning: curl returned HTTP response code $HTTP_RC for URL $i"
    fi
    rm $IP_TMP
done
echo
sort $IP_BLACKLIST_TMP -n | uniq | sed -e '/^127.0.0.0\|127.0.0.1\|0.0.0.0/d'  > $IP_BLACKLIST
rm $IP_BLACKLIST_TMP
echo "Number of blacklisted IP/networks found: `wc -l $IP_BLACKLIST | cut -d' ' -f1`"
echo "create $IPSET_TMP_BLACKLIST_NAME -exist hash:net family inet  hashsize $HASHSIZE maxelem $MAXELEM" > $IP_BLACKLIST_RESTORE
echo "create $IPSET_BLACKLIST_NAME -exist hash:net family inet hashsize $HASHSIZE maxelem $MAXELEM" >> $IP_BLACKLIST_RESTORE

egrep -v "^#|^$" $IP_BLACKLIST | while IFS= read -r ip
do
    echo "add $IPSET_TMP_BLACKLIST_NAME $ip" >> $IP_BLACKLIST_RESTORE
done

if [ -f $IP_BLACKLIST_CUSTOM ]; then
    egrep -v "^#|^$" $IP_BLACKLIST_CUSTOM | while IFS= read -r ip
    do
        echo "add $IPSET_TMP_BLACKLIST_NAME $ip" >> $IP_BLACKLIST_RESTORE
    done
    echo "Number of IP/networks in custom blacklist: `wc -l $IP_BLACKLIST_CUSTOM | cut -d' ' -f1`"
fi

echo "swap $IPSET_BLACKLIST_NAME $IPSET_TMP_BLACKLIST_NAME" >> $IP_BLACKLIST_RESTORE
echo "destroy $IPSET_TMP_BLACKLIST_NAME" >> $IP_BLACKLIST_RESTORE
ipset restore < $IP_BLACKLIST_RESTORE
python /opt/rulecheck.py blacklist
