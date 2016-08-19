# UBNT EdgeMax dnsmasq Blacklist and Adware Blocking
[community.ubnt.com](https://community.ubnt.com/t5/EdgeMAX/Self-Installer-to-configure-Ad-Server-and-Blacklist-Blocking/td-p/1337892)

NOTE: THIS IS NOT OFFICIAL UBIQUITI SOFTWARE AND THEREFORE NOT SUPPORTED OR ENDORSED BY Ubiquiti Networks®

## Overview
EdgeMax dnsmasq Blacklist and Adware Blocking is derived from the received wisdom found at (https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)

## Licenses
* GNU General Public License, version 3
* GNU Lesser General Public License, version 3

## Features
* Generates configuration files used directly by dnsmasq to redirect dns lookups
* Integrated with the EdgeMax OS CLI
* Any FQDN in the blacklist will force dnsmasq to return the configured dns redirect IP address

## Compatibility
* update-dnsmasq.pl has been tested on the EdgeRouter Lite family of routers, version v1.6.0-v1.9.0.
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script could be adapted to work on VyOS and Vyatta derived ports

## Versions
* v3.6: Enhancements
    - Ability to add a source that uses a local file instead of HTTP

            set service dns forwarding blacklist hosts source myhosts description 'Blacklist file source'
            set service dns forwarding blacklist hosts source myhosts dns-redirect-ip 10.10.10.1
            set service dns forwarding blacklist hosts source myhosts file /config/user-data/blist.hosts.src

    - file contents example for /config/user-data/blist.hosts.src:

            gsmtop.net
            click.buzzcity.net
            ads.admoda.com
            stats.pflexads.com
            a.glcdn.co
            wwww.adleads.com
            ad.madvertise.de
            apps.buzzcity.net
            ads.mobgold.com
            android.bcfads.com
            req.appads.com
            show.buzzcity.net
            api.analytics.omgpop.com
            r.edge.inmobicdn.net
            www.mmnetwork.mobi
            img.ads.huntmad.com
            creative1cdn.mobfox.com
            admicro2.vcmedia.vn
            admicro1.vcmedia.vn

- Each source can now have its own dns-redirect-ip for granular control
        set service dns forwarding blacklist hosts source openphish dns-redirect-ip 172.16.10.1

- Revised source list
    - Redundant sources removed:
            delete service dns forwarding blacklist hosts source adaway # description 'Blocking mobile ad providers and some analytics providers'
            delete service dns forwarding blacklist hosts source malwaredomainlist # description '127.0.0.1 based host and domain list'
            delete service dns forwarding blacklist hosts source someonewhocares # description 'Zero based host and domain list'
            delete service dns forwarding blacklist hosts source winhelp2002 # description 'Zero based host and domain list'

    - Retained sources:
            set service dns forwarding blacklist domains source malc0de description 'List of zones serving malicious executables observed by malc0de.com/database/'
            set service dns forwarding blacklist domains source malc0de prefix 'zone '
            set service dns forwarding blacklist domains source malc0de url 'http://malc0de.com/bl/ZONES'
            set service dns forwarding blacklist hosts source openphish description 'OpenPhish automatic phishing detection'
            set service dns forwarding blacklist hosts source openphish prefix http
            set service dns forwarding blacklist hosts source openphish url 'https://openphish.com/feed.txt'
            set service dns forwarding blacklist hosts source volkerschatz description 'Ad server blacklists'
            set service dns forwarding blacklist hosts source volkerschatz prefix http
            set service dns forwarding blacklist hosts source volkerschatz url 'http://www.volkerschatz.com/net/adpaths'
            set service dns forwarding blacklist hosts source yoyo description 'Fully Qualified Domain Names only - no prefix to strip'
            set service dns forwarding blacklist hosts source yoyo prefix ''
            set service dns forwarding blacklist hosts source yoyo url 'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext'

    - Added sources:
        - Domains:
                set service dns forwarding blacklist domains source simple_tracking description 'Basic tracking list by Disconnect'
                set service dns forwarding blacklist domains source simple_tracking prefix ''
                set service dns forwarding blacklist domains source simple_tracking url 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt'
                set service dns forwarding blacklist domains source zeus description 'abuse.ch ZeuS domain blocklist'
                set service dns forwarding blacklist domains source zeus prefix ''
                set service dns forwarding blacklist domains source zeus url 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
        - Hosts:
                set service dns forwarding blacklist hosts source raw.github.com description 'This hosts file is a merged collection of hosts from reputable sources'
                set service dns forwarding blacklist hosts source raw.github.com prefix '0.0.0.0 '
                set service dns forwarding blacklist hosts source raw.github.com url 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
                set service dns forwarding blacklist hosts source sysctl.org description 'This hosts file is a merged collection of hosts from cameleon'
                set service dns forwarding blacklist hosts source sysctl.org prefix '127.0.0.1	 '
                set service dns forwarding blacklist hosts source sysctl.org url 'http://sysctl.org/cameleon/hosts'

- Additional excludes added to blacklist configuration list

- To install:
    * upload install_dnsmasq_blklist.v3.6-beta.2.tgz to your router (ensure you modify the command if you want to install an older version)
        - curl -o /tmp/install_dnsmasq_blklist.v3.6-beta.2.tgz http://community.ubnt.com/ubnt/attachments/ubnt/EdgeMAX/78132/53/install_dnsmasq_blklist.v3.6-beta.2.tgz
        - cd /tmp
        - sudo tar zxvf ./install_dnsmasq_blklist.v3.6-beta.2.tgz
        - bash ./install_dnsmasq_blklist.v3.6-beta.2
        - select menu option #1 if installing for the first time
        - select menu option #2 to completely remove blacklisting if you have a previous version, then run install again using option #1

* v3.5.5: Updates/fixes include:
- Added clarifying explanation for failed IP tests; advises user to ignore if router resolves upstream DNS and not locally
- Fixed minor bug with command shell redirection
- Additional excludes added to blacklist configuration list

- v3.5.3: Updates/fixes include:
- Added code to fix 'set' failures if /opt/vyatta/active/service/dns/forwarding/ group ownership isn't writable for the operator
- Additional excludes added based on user feedback
- Minor optimizations and additional tests added
- Setup commands now include PURGE to clean up stale config sessions:

| # | Option  |                         Function                          |
|---|---------|-----------------------------------------------------------|
| 1 | INSTALL |Install dnsmasq blacklist CLI configuration functionality|
| 2 | REMOVE  |Remove dnsmasq blacklist CLI configuration functionality|
| 3 | TEST    |Validate dnsmasq blacklist CLI configuration functionality|
| 4 | BACKUP  |Save blacklist configuration to /config/user-data/blacklist.cmds|
| 5 | PURGE   |Clean up stale config sessions|
| 5 | QUIT    |Exit the installer|

* v3.5: Updates/fixes include:
    - Global exclude is now available ([set service dns forwarding blacklist exclude ...])
    - Removed --debug option from update-dnsmasq.pl
    - New validator script (/configure/scripts/blacklist.t) runs a battery of tests on the blacklist configuration to ensure it is working correctly or checks it is removed correctly
    - Setup/Remove scripts rewritten in Perl
    - Fixed issue with install that prevented admin user configuration
    - Installer now runs under admin and only uses sudo where absolutely necessary
    - Installer checks to see if service dns forwarding is configured and bails it if not with warning/example configuration
    - Installer includes these new options:
    - Non-essential functions have been pruned, command line switches reduced to:

            /config/scripts/update-dnsmasq.pl -h
            usage: update-dnsmasq.pl <options>
            options:
                -f <file>   # load a configuration file
                --help      # show help and usage text
                -v          # verbose output
                --version   # show program version number

| # | Option  |                         Function                          |
|---|---------|-----------------------------------------------------------|
| 1 | INSTALL |Install dnsmasq blacklist CLI configuration functionality|
| 2 | REMOVE  |Remove dnsmasq blacklist CLI configuration functionality|
| 3 | TEST    |Validate dnsmasq blacklist CLI configuration functionality|
| 4 | BACKUP  |Save blacklist configuration to /config/user-data/blacklist.cmds|
| 5 | QUIT    |Exit the installer|

---
* v3.3.2: What is new:
    - Non-essential functions have been pruned, command line switches reduced to:

            /config/scripts/update-dnsmasq.pl -h
            usage: update-dnsmasq.pl <options>
            options:
                --debug     # enable debug output
                -f <file>   # load a configuration file
                --help      # show help and usage text
                -v          # verbose output
                --version   # show program version number

    - Improved exclusion list rejection
    - Ability to create a domain list from a source that has FQDNs using the new 'compress' switch (note, use with caution, since you may find legit domains getting completely blocked - especially cloud services like amazonaws, in that case you will need to add specific excludes):

            set service dns forwarding blacklist domains source FQDNs_Source compress true

    - Install/remove scripts rewritten in Perl for better error checking
    - Install/remove logs will be written to /var/log for diagnostics
    - Flagged domain list with optional include commands written to /var/log/update-dnsmasq_flagged_domains.cmds
    - Each source will be written to its own file:

            root@ubnt:/etc/dnsmasq.d# ls
            README
            domains.malc0de.com.blacklist.conf
            domains.pre-configured.blacklist.conf
            hosts.adaway.blacklist.conf
            hosts.hpHosts.blacklist.conf
            hosts.pre-configured.blacklist.conf
            hosts.someonewhocares.org.blacklist.conf
            hosts.winhelp2002.mvps.org.blacklist.conf
            hosts.www.malwaredomainlist.com.blacklist.conf
            hosts.yoyo.org.blacklist.conf

    - Log file (/var/log/update-dnsmasq.pl) now flags frequently blacklisted domains, so you can optionally decide to add them as an include under domains:

            root@ubnt:/etc/dnsmasq.d# tail -n 30 /var/log/update-dnsmasq.log
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain loniricarena.ru 4 times
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain starwave.com 5 times
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain axf8.net 41 times
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain com-swd.net 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain jaimiehonoria.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain your-drug-blog.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain wileenallix.ru 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain com-5ny.net 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain bb.13900139000.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain in.th 6 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain adhese.com 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain gueneveredeane.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain xn--c1aqdux1a.xn 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain kathlingertrud.com 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain peqi.healthhuman.net 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain jessamineelvira.ru 9 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain xn--c1abhkul5co5f.xn 7 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain com-0to.net 6 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain 9458.302br.net 19 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain xn--80aasb3bf1bvw.xn 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain web.id 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain ap.org 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain webjump.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain blueseek.com 11 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain j595j4.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain axeynlzljpld.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain jemieandrea.com 59 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain llnwd.net 24 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain thomasadot.com 4 times
            Nov 29 09:45:52 2015: INFO: Reloading dnsmasq configuration...

    - Improved memory usage for threads has been implemented
    - Uses HTTP::Tiny for smaller memory footprint with threads
    - Optional -f config.boot parser has been completely rewritten, so that the XorpConfigParser.pm module is no longer required (saves on memory overhead and compilation time)
    - Over 70% of the code has been rewritten or updated

* Version History:
---
* v3.24d: Updates include:
    - 'hosts' exclusions now incorporates 'domains' exclusions and blacklists
    - Additional 'good hosts' excluded from blacklisting in the supplied install configuration
    - Fixes excluded FQDNs by using precise matching instead of fuzzy (i.e. 1.domain.tld won't also exclude b1.domain.tld)
    - Entire blacklist can be disabled using 'set service dns forwarding blacklist disabled true'
    - Ability to add domain sources, which compile to domain.blacklist.conf allowing for domain wildcards, so that all hosts in a domain will now be blocked
    - Exclude and include lists have been moved and now apply to their parent area, e.g. 'hosts' or 'domains'
    - New --disable switch enables ADBlock by setting [set service dns forwarding blacklist enabled false]
    - New --enable switch enables ADBlock by setting [set service dns forwarding blacklist enabled true]
    - Now uses multi-threading for simultaneous blacklist downloads
    - Revamped stream processor, now has ability to extract multiple FQDNs from each line or input
    - Useragent: HTTP get requests now include browser agent information to prevent website robot rejection
    - Useragent: HTTP/HTTPS handling uses useragent for improved error/timeout control
    - Uses own node.def to maintain configuration changes. This also forces the script to run the dnsmasq configuration update after DNS is up during boot time
---
* 3.22rc1: Updates include:
    - Fixes excluded FQDNs by using precise matching instead of fuzzy (i.e. 1.domain.tld won't also exclude b1.domain.tld)
    - New --disable switch enables ADBlock by setting [set service dns forwarding blacklist enabled false]
    - New --doc switch prints out condensed man page
    - New --enable switch enables ADBlock by setting [set service dns forwarding blacklist enabled true]
    - Now uses multi-threading for simultaneous blacklist downloads
    - Revamped stream processor, now has ability to extract multiple FQDNs from each line or input
    - Useragent: HTTP get requests now include browser agent information to prevent website robot rejection
    - Useragent: HTTP/HTTPS handling uses useragent for improved error/timeout control
    - Uses own node.def to maintain configuration changes. This also forces the script to run the dnsmasq configuration update after DNS is up during boot time
    - Uses own node.def to maintain configuration changes. This also forces the script to run the dnsmasq configuration update after DNS is up during router boot time
---
* 3.15: Added features include:
    - Logging to /var/log/update-blacklists-dnsmasq.log
    - --debug option: prints status messages
    - Additional download sources added to the default lists
    - Added retry logic for download sources that time out (inspired by @mseeEngineer﻿)
    - Task scheduler update interval is now every 6 hours, as some of the sources change hourly (configure interval using "set system task-scheduler task update_blacklists interval"
    - Status line retains previous downloads for more detail
---
* Version 3.12: Fixed bug reported by @soehest﻿ where certain FQDNs were being rejected by the stream processor.
---
* Version 3.10: Now supports https:// source URLs and improved regex handling in the stream processing engine.
---
* Version 3.00: No longer requires regex strings, just the line prefix/preamble before the hostname in the download. If a version of ADBlock was installed previously, you will need to select option 2 to remove it and then install this version. This is necessary to ensure the configure paths are correctly set up for the new prefix option which replaces the regex string.
---
## Installation

To install:

* upload install_adblock.v3.24a.tgz to your router (ensure you modify the command if you want to install an older version)
    - curl -o /tmp/install_adblock.v3.24a.tgz http://community.ubnt.com/ubnt/attachments/ubnt/EdgeMAX/78132/34/install_adblock.v3.24a.tgz
    - sudo tar zxvf ./install_adblock.v3.24a.tgz
    - sudo bash ./install_adblock.v3.24a.tgz
    - select menu option #1 if installing for the first time
    - select menu option #2 to completely remove ADBlock if you have a previous version, then run install again using option #1

* Now run configure and make certain your DHCP services don't give out public nameservers, otherwise they will defeat the dnsmasq redirects:

        delete service dhcp-server shared-network-name <YOUR DHCP SERVICE NAME> subnet <YOUR SUBNET> dns-server <PUBLIC NAME SERVER i.e. 8.8.8.8>

* Now make sure EACH of your DHCP services (for the subnets you want to block adverts and malware servers) gives out the router as the only nameserver (LAN1 and the subnet should be replaced with your own system values):

        set service dhcp-server shared-network-name LAN1 subnet 192.168.1.0/24 dns-server 192.168.1.1

* The script has a menu to either add or remove (if previously installed) AdBlock. It will set up the system task scheduler (cron) via the CLI to run "/config/scripts/update-blacklists-dnsmasq.pl" at mindnight local time.

## Post Installation
Here is the scheduler configuration after running install_adblock:

```python
    show system task-scheduler
     task update_blacklists {
         executable {
             path /config/scripts/update-blacklists-dnsmasq.pl
         }
         interval 6h
     }
```
The script will also install a default blacklist setup, here is the stanza (show service dns forwarding):

```python
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
            include centade.com
            include doubleclick.net
            include free-counter.co.uk
            include kiosked.com
            source malc0de.com {
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
            exclude ads.hulu.com
            exclude ads-a-darwin.hulu.com
            exclude ads-v-darwin.hulu.com
            exclude track.hulu.com
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
```
CLI commands to configure the ADBlock Blacklist:

    set service dns forwarding blacklist dns-redirect-ip 0.0.0.0
    set service dns forwarding blacklist disabled false
    set service dns forwarding blacklist domains exclude adobedtm.com
    set service dns forwarding blacklist domains exclude apple.com
    set service dns forwarding blacklist domains exclude coremetrics.com
    set service dns forwarding blacklist domains exclude doubleclick.net
    set service dns forwarding blacklist domains exclude google.com
    set service dns forwarding blacklist domains exclude googleadservices.com
    set service dns forwarding blacklist domains exclude googleapis.com
    set service dns forwarding blacklist domains exclude hulu.com
    set service dns forwarding blacklist domains exclude msdn.com
    set service dns forwarding blacklist domains exclude paypal.com
    set service dns forwarding blacklist domains exclude storage.googleapis.com
    set service dns forwarding blacklist domains include adsrvr.org
    set service dns forwarding blacklist domains include adtechus.net
    set service dns forwarding blacklist domains include advertising.com
    set service dns forwarding blacklist domains include centade.com
    set service dns forwarding blacklist domains include doubleclick.net
    set service dns forwarding blacklist domains include free-counter.co.uk
    set service dns forwarding blacklist domains include kiosked.com
    set service dns forwarding blacklist domains source malc0de.com description 'List of zones serving malicious executables observed by malc0de.com/database/'
    set service dns forwarding blacklist domains source malc0de.com prefix 'zone '
    set service dns forwarding blacklist domains source malc0de.com url 'http://malc0de.com/bl/ZONES'
    set service dns forwarding blacklist hosts exclude appleglobal.112.2o7.net
    set service dns forwarding blacklist hosts exclude autolinkmaker.itunes.apple.com
    set service dns forwarding blacklist hosts exclude cdn.visiblemeasures.com
    set service dns forwarding blacklist hosts exclude freedns.afraid.org
    set service dns forwarding blacklist hosts exclude hb.disney.go.com
    set service dns forwarding blacklist hosts exclude ads.hulu.com
    set service dns forwarding blacklist hosts exclude ads-a-darwin.hulu.com
    set service dns forwarding blacklist hosts exclude ads-v-darwin.hulu.com
    set service dns forwarding blacklist hosts exclude track.hulu.com
    set service dns forwarding blacklist hosts exclude static.chartbeat.com
    set service dns forwarding blacklist hosts exclude survey.112.2o7.net
    set service dns forwarding blacklist hosts include beap.gemini.yahoo.com
    set service dns forwarding blacklist hosts source openphish.com description 'OpenPhish automatic phishing detection'
    set service dns forwarding blacklist hosts source openphish.com prefix http
    set service dns forwarding blacklist hosts source openphish.com url 'https://openphish.com/feed.txt'
    set service dns forwarding blacklist hosts source someonewhocares.org description 'Zero based host and domain list'
    set service dns forwarding blacklist hosts source someonewhocares.org prefix 0.0.0.0
    set service dns forwarding blacklist hosts source someonewhocares.org url 'http://someonewhocares.org/hosts/zero/'
    set service dns forwarding blacklist hosts source volkerschatz.com description 'Ad server blacklists'
    set service dns forwarding blacklist hosts source volkerschatz.com prefix http
    set service dns forwarding blacklist hosts source volkerschatz.com url 'http://www.volkerschatz.com/net/adpaths'
    set service dns forwarding blacklist hosts source winhelp2002.mvps.org description 'Zero based host and domain list'
    set service dns forwarding blacklist hosts source winhelp2002.mvps.org prefix '0.0.0.0 '
    set service dns forwarding blacklist hosts source winhelp2002.mvps.org url 'http://winhelp2002.mvps.org/hosts.txt'
    set service dns forwarding blacklist hosts source www.malwaredomainlist.com description '127.0.0.1 based host and domain list'
    set service dns forwarding blacklist hosts source www.malwaredomainlist.com prefix '127.0.0.1 '
    set service dns forwarding blacklist hosts source www.malwaredomainlist.com url 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
    set service dns forwarding blacklist hosts source yoyo.org description 'Fully Qualified Domain Names only - no prefix to strip'
    set service dns forwarding blacklist hosts source yoyo.org prefix ''
    set service dns forwarding blacklist hosts source yoyo.org url 'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext'
    set system task-scheduler task update_blacklists executable path /config/scripts/update-dnsmasq.pl
    set system task-scheduler task update_blacklists interval 6h

## Notes:
In order to make this work properly, you will need to first ensure that your dnsmasq is correctly set up. An example configuration is posted below:

    show service dns forwarding
     cache-size 2048
     listen-on eth0
     listen-on eth2
     listen-on lo
     name-server 208.67.220.220
     name-server 208.67.222.222
     name-server 2620:0:ccc::2
     name-server 2620:0:ccd::2
     options expand-hosts
     options bogus-priv
     options localise-queries
     options domain=ubnt.home
     options strict-order
     options listen-address=127.0.0.1
     system

## Removal
* sudo bash ./install_adblock.v3.24a
* select option #2
