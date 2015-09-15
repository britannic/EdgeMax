# UBNT EdgeMax Blacklist and Ad Server Blocking
https://community.ubnt.com/t5/EdgeMAX/Self-Installer-to-configure-Ad-Server-and-Blacklist-Blocking/td-p/1337892
git@empirecreekcircle.com
@britannic

NOTE: THIS IS NOT OFFICIAL UBIQUITI SOFTWARE AND THEREFORE NOT SUPPORTED OR ENDORSED BY Ubiquiti Networks®

## Overview
EdgeMax Blacklist and Ad Server Blocking is derived from the received wisdom found at (https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)

## Licenses
* GNU General Public License, version 3
* GNU Lesser General Public License, version 3

## Features
* Generates a dnsmasq configuration file that can be used directly by dnsmasq
* Any fqdn in the blacklist will return the IP address configured in the update-blacklists-dnsmasq.pl script at line 15
* Integrated with the EdgeMax OS CLI

## Compatibility
* update-blacklists-dnsmasq.pl has been tested on the EdgeRouter Lite family of routers, version v1.6.0-v1.7.0.
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script could easily be adapted for work on VyOS and Vyatta derived ports

## Installation

To install:

* upload install_adblock.tgz to your router (e.g. scp <local path>/ersetup.tgz <user>@<erl router>:/tmp/install_adblock.tgz
* on your router: cd /tmp; sudo tar zxvf /tmp/install_adblock.tgz
* sudo bash /tmp/install_adblock
* The script has a menu to either add or remove (if previously installed) AdBlock. It will set up the system task scheduler (cron) via the CLI to run "/config/scripts/update-blacklists-dnsmasq.pl" at mindnight local time.

## Post Installation
Here is the scheduler configuration after running install_adblock:
'''javascript
show system task-scheduler
 task update_blacklists {
     executable {
         path /config/scripts/update-blacklists-dnsmasq.pl
     }
     interval 1d
 }
'''
The script will also install a default blacklist setup, here is the stanza (show service dns forwarding):

'''javascript
 dns {
        forwarding {
            blacklist {
                blackhole 0.0.0.0
                exclude msdn.com
                exclude appleglobal.112.2o7.net
                exclude cdn.visiblemeasures.com
                exclude hb.disney.go.com
                exclude googleadservices.com
                exclude hulu.com
                exclude static.chartbeat.com
                exclude survey.112.2o7.net
                include beap.evilmalware.com
                source someonewhocares.org {
                    description "Zero based host and domain list"
                    regex "^0.0.0.0\s([-a-z0-9_.]+).*"
                    url http://someonewhocares.org/hosts/zero/
                }
                source winhelp2002.mvps.org {
                    description "Zero based host and domain list"
                    regex "^0.0.0.0\s([-a-z0-9_.]+).*"
                    url http://winhelp2002.mvps.org/hosts.txt
                }
                source www.malwaredomainlist.com {
                    description "127.0.0.1 based host and domain list"
                    regex "^127\.0\.0\.1\s\s\b([-a-z0-9_\.]*)\b[\s]{0,1}"
                    url http://www.malwaredomainlist.com/hostslist/hosts.txt
                }
                source yoyo.org {
                    description "DNSmasq formatted, but with 127.0.0.1 black hole IP"
                    regex "^address=/\b([-a-z0-9_\.]+)\b/127\.0\.0\.1"
                    url http://pgl.yoyo.org/adservers/serverlist.php?hostformat=dnsmasq&showintro=0&mimetype=plaintext
                }
            }
            cache-size 150
            listen-on eth0
            listen-on eth2
            listen-on eth1
            options listen-address=127.0.0.1
            options bogus-priv
            options localise-queries
            options domain=adblock.home
            system
        }
    }
'''
