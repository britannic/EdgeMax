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

## Installation

To install:

* upload install_adblock.tgz to your router (e.g. scp <local path>/ersetup.tgz <user>@<erl router>:/tmp/install_adblock.tgz
* on your router: cd /tmp; sudo tar zxvf /tmp/install_adblock.tgz
* sudo bash /tmp/install_adblock
* The script has a menu to either add or remove (if previously installed) AdBlock. It will set up the system task scheduler (cron) via the CLI to run "/config/scripts/update-blacklists-dnsmasq.pl" at mindnight local time.

## Post Installation
Here is the scheduler configuration after running install_adblock:

```javascript
show system task-scheduler
 task update_blacklists {
     executable {
         path /config/scripts/update-blacklists-dnsmasq.pl
     }
     interval 1d
 }
```
The script will also install a default blacklist setup, here is the stanza (show service dns forwarding):

```javascript
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
                    prefix "0.0.0.0 "
                    url http://someonewhocares.org/hosts/zero/
                }
                source winhelp2002.mvps.org {
                    description "Zero based host and domain list"
                    prefix "0.0.0.0 "
                    url http://winhelp2002.mvps.org/hosts.txt
                }
                source yoyo.org {
                    description "DNSmasq formatted, but with 127.0.0.1 black hole IP"
                    prefix ""
                    url http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext
                source www.malwaredomainlist.com {
                    description "127.0.0.1 based host and domain list"
                    prefix "127.0.0.1  "
                    url http://www.malwaredomainlist.com/hostslist/hosts.txt
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
```

* CLI commands to configure the ADBlock Blacklist:

```javascript
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
    set service dns forwarding blacklist source someonewhocares.org description 'Zero based host and domain list'
    set service dns forwarding blacklist source someonewhocares.org prefix '0.0.0.0 '
    set service dns forwarding blacklist source someonewhocares.org url 'http://someonewhocares.org/hosts/zero/'
    set service dns forwarding blacklist source winhelp2002.mvps.org description 'Zero based host and domain list'
    set service dns forwarding blacklist source winhelp2002.mvps.org prefix '0.0.0.0 '
    set service dns forwarding blacklist source winhelp2002.mvps.org url 'http://winhelp2002.mvps.org/hosts.txt'
    set service dns forwarding blacklist source yoyo.org description 'DNSmasq formatted, but with 127.0.0.1 black hole IP'
    set service dns forwarding blacklist source yoyo.org prefix ''
    set service dns forwarding blacklist source yoyo.org url 'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext'
    set system task-scheduler task update_blacklists executable path /config/scripts/update-blacklists-dnsmasq.pl
    set system task-scheduler task update_blacklists interval 1d
```
