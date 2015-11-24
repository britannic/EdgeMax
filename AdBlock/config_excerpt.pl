blacklist {
    disabled false
    dns-redirect-ip 0.0.0.0
    domains {
        exclude adobedtm.com
        exclude apple.com
        exclude coremetrics.com
        exclude doubleclick.net
        exclude google.com
        exclude googleadservices.com
        exclude googleapis.com
        exclude hulu.com
        exclude msdn.com
        exclude paypal.com
        exclude storage.googleapis.com
        include adsrvr.org
        include adtechus.net
        include advertising.com
        include beap.gemini.yahoo.com
        include centade.com
        include doubleclick.net
        include free-counter.co.uk
        include kiosked.com
        source hpHosts {
            compress true
            description "hpHosts optimized in hosts format"
            prefix "127.0.0.1 "
            url http://hosts-file.net/download/HOSTS-Optimized.txt
        }
        source malc0de.com {
            compress false
            description "List of zones serving malicious executables observed by malc0de.com/database/"
            prefix "zone "
            url http://malc0de.com/bl/ZONES
        }
    }
    hosts {
        exclude appleglobal.112.2o7.net
        exclude autolinkmaker.itunes.apple.com
        exclude cdn.visiblemeasures.com
        exclude freedns.afraid.org
        exclude hb.disney.go.com
        exclude static.chartbeat.com
        exclude survey.112.2o7.net
        include beap.gemini.yahoo.com
        source openphish.com {
            description "OpenPhish automatic phishing detection"
            prefix http
            url https://openphish.com/feed.txt
        }
        source someonewhocares.org {
            description "Zero based host and domain list"
            prefix 0.0.0.0
            url http://someonewhocares.org/hosts/zero/
        }
        source volkerschatz.com {
            description "Ad server blacklists"
            prefix http
            url http://www.volkerschatz.com/net/adpaths
        }
        source winhelp2002.mvps.org {
            description "Zero based host and domain list"
            prefix "0.0.0.0 "
            url http://winhelp2002.mvps.org/hosts.txt
        }
        source www.malwaredomainlist.com {
            description "127.0.0.1 based host and domain list"
            prefix "127.0.0.1 "
            url http://www.malwaredomainlist.com/hostslist/hosts.txt
        }
        source yoyo.org {
            description "Fully Qualified Domain Names only - no prefix to strip"
            prefix ""
            url http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext
        }
    }
}
