# UBNT EdgeMax Blacklist and Ad Server Blocking
https://community.ubnt.com/t5/EdgeMAX/Self-Installer-to-configure-Ad-Server-and-Blacklist-Blocking/td-p/1337892

NOTE: THIS IS NOT OFFICIAL UBIQUITI SOFTWARE AND THEREFORE NOT SUPPORTED OR ENDORSED BY Ubiquiti Networks®

## Overview
EdgeMax Blacklist and Ad Server Blocking is derived from the received wisdom found at (https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)

## Licenses
* GNU General Public License, version 3
* GNU Lesser General Public License, version 3

## Features
* Generates a dnsmasq configuration file that can be used directly by dnsmasq
* Integrated with the EdgeMax OS CLI
* Any fqdn in the blacklist will return the configured Blackhole IP address

## Compatibility
* update-blacklists-dnsmasq.pl has been tested on the EdgeRouter Lite family of routers, version v1.6.0-v1.7.0.
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script could easily be adapted for work on VyOS and Vyatta derived ports

## Versions
* 3.15. Added features include:
    - Logging to /var/log/update-blacklists-dnsmasq.log
    - --debug option: prints status messages
    - Additional download sources added to the default lists
    - Added retry logic for download sources that time out (inspired by @mseeEngineer﻿)
    - Task scheduler update interval is now every 6 hours, as some of the sources change hourly (configure interval using "set system task-scheduler task update_blacklists interval"
    - Status line retains previous downloads for more detail
* Version 3.12: Fixed bug reported by @soehest﻿ where certain FQDNs were being rejected by the stream processor.

* Version 3.10: Now supports https:// source URLs and improved regex handling in the stream processing engine.

* Version 3.00: No longer requires regex strings, just the line prefix/preamble before the hostname in the download. If a version of ADBlock was installed previously, you will need to select option 2 to remove it and then install this version. This is necessary to ensure the configure paths are correctly set up for the new prefix option which replaces the regex string.

## Installation

To install:

* upload install_adblock.tgz to your router (e.g. scp <local path>/install_adblock.v3.15.tgz <user>@<erl router>:/tmp/install_adblock.v3.15.tgz)
    - sudo tar zxvf ./install_adblock.v3.15.tgz
    - sudo bash ./install_adblock.v3.15

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
             interval 1d
         }
```
The script will also install a default blacklist setup, here is the stanza (show service dns forwarding):
```python
        forwarding {
            blacklist {
                blackhole 192.168.10.1
                exclude msdn.com
                exclude appleglobal.112.2o7.net
                exclude cdn.visiblemeasures.com
                exclude hb.disney.go.com
                exclude googleadservices.com
                exclude hulu.com
                exclude static.chartbeat.com
                exclude survey.112.2o7.net
                include beap.gemini.yahoo.com
                source openphish.com {
                    description "OpenPhish automatic phishing detection"
                    prefix "htt.*//"
                    url https://openphish.com/feed.txt
                }
                source someonewhocares.org {
                    description "Zero based host and domain list"
                    prefix "0.0.0.0 "
                    url http://someonewhocares.org/hosts/zero/
                }
                source winhelp2002.mvps.org {
                    description "Zero based host and domain list"
                    prefix "0.0.0.0 "
                    url http://winhelp2002.mvps.org/hosts.txt
                }
                source www.malwaredomainlist.com {
                    description "127.0.0.1 based host and domain list"
                    prefix "127.0.0.1  "
                    url http://www.malwaredomainlist.com/hostslist/hosts.txt
                }
                source yoyo.org {
                    description "Fully Qualified Domain Names only - no prefix to strip"
                    prefix ""
                    url http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext
                }
                source zeustracker.abuse.ch/compromised {
                    description "abuse.ch ZeuS compromised URL blacklist"
                    prefix ""
                    url https://zeustracker.abuse.ch/blocklist.php?download=compromised
                }
                source zeustracker.abuse.ch/hostfile {
                    description "abuse.ch ZeuS blocklist host file"
                    prefix 127.0.0.1\s+
                    url https://zeustracker.abuse.ch/blocklist.php?download=hostfile
                }
            }
```
CLI commands to configure the ADBlock Blacklist:

        set service dns forwarding blacklist blackhole 0.0.0.0
        set service dns forwarding blacklist exclude msdn.com
        set service dns forwarding blacklist exclude appleglobal.112.2o7.net
        set service dns forwarding blacklist exclude cdn.visiblemeasures.com
        set service dns forwarding blacklist exclude hb.disney.go.com
        set service dns forwarding blacklist exclude googleadservices.com
        set service dns forwarding blacklist exclude hulu.com
        set service dns forwarding blacklist exclude static.chartbeat.com
        set service dns forwarding blacklist exclude survey.112.2o7.net
        set service dns forwarding blacklist include beap.gemini.yahoo.com
        set service dns forwarding blacklist source openphish.com description 'OpenPhish automatic phishing detection'
        set service dns forwarding blacklist source openphish.com prefix 'htt.*//'
        set service dns forwarding blacklist source openphish.com url 'https://openphish.com/feed.txt'
        set service dns forwarding blacklist source someonewhocares.org description 'Zero based host and domain list'
        set service dns forwarding blacklist source someonewhocares.org prefix '0.0.0.0 '
        set service dns forwarding blacklist source someonewhocares.org url 'http://someonewhocares.org/hosts/zero/'
        set service dns forwarding blacklist source winhelp2002.mvps.org description 'Zero based host and domain list'
        set service dns forwarding blacklist source winhelp2002.mvps.org prefix '0.0.0.0 '
        set service dns forwarding blacklist source winhelp2002.mvps.org url 'http://winhelp2002.mvps.org/hosts.txt'
        set service dns forwarding blacklist source www.malwaredomainlist.com description '127.0.0.1 based host and domain list'
        set service dns forwarding blacklist source www.malwaredomainlist.com prefix '127.0.0.1  '
        set service dns forwarding blacklist source www.malwaredomainlist.com url 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
        set service dns forwarding blacklist source yoyo.org description 'Fully Qualified Domain Names only - no prefix to strip'
        set service dns forwarding blacklist source yoyo.org prefix ''
        set service dns forwarding blacklist source yoyo.org url 'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext'
        set service dns forwarding blacklist source zeustracker.abuse.ch/compromised description 'abuse.ch ZeuS compromised URL blacklist'
        set service dns forwarding blacklist source zeustracker.abuse.ch/compromised prefix ''
        set service dns forwarding blacklist source zeustracker.abuse.ch/compromised url 'https://zeustracker.abuse.ch/blocklist.php?download=compromised'
        set service dns forwarding blacklist source zeustracker.abuse.ch/hostfile description 'abuse.ch ZeuS blocklist host file'
        set service dns forwarding blacklist source zeustracker.abuse.ch/hostfile prefix '127.0.0.1\s+'
        set service dns forwarding blacklist source zeustracker.abuse.ch/hostfile url 'https://zeustracker.abuse.ch/blocklist.php?download=hostfile'
        set system task-scheduler task update_blacklists executable path /config/scripts/update-blacklists-dnsmasq.pl
        set system task-scheduler task update_blacklists interval

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
