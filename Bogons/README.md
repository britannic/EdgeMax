# UBNT EdgeMax Bogon Emerging Threats Drop List

NOTE: THIS IS NOT OFFICIAL UBIQUITI SOFTWARE AND THEREFORE NOT SUPPORTED OR ENDORSED BY Ubiquiti Networks®

* Script is derived from publicly available sources and ideas

## Overview
In order to use this script, you must first configure an:

* EdgeOS firewall group with the name 'ipv4Bogons'
* Set up a cron job (recent EdgeOS versions have a CLI configurable system task-scheduler)
* A firewall (at least WAN-Local and WAN-Internal) drop rule that uses the group, i.e.:

        network-group ipv4Bogons {
            description "ipv4 BOGON Addresses"
            network 10.0.0.0/8
            network 100.64.0.0/10
            network 127.0.0.0/8
            network 169.254.0.0/16
            network 172.16.0.0/12
            network 192.0.0.0/24
            network 192.0.2.0/24
            network 192.168.0.0/16
            network 198.18.0.0/15
            network 198.51.100.0/24
            network 203.0.113.0/24
            network 224.0.0.0/4
            network 240.0.0.0/4
        }

        rule 3 {
            action drop
            description "Drop IPv4 bogons"
            source {
                group {
                    network-group ipv4Bogons
                }
            }
        }

## Licenses
* GNU General Public License, version 3
* GNU Lesser General Public License, version 3

## Features
*

## Compatibility
* bogon.py has been tested on the EdgeRouter Lite family of routers, versions v1.6.0-v1.9.1.
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script could easily be adapted to work on VyOS and Vyatta derived ports
* It does require the Python netaddr module, which can be installed using apt-get, once you have updated your router package repository configuration

## Installation

First, ensure you have an updated package repository on your routers

`````````javascript
    configure
    set system package repository wheezy components 'main contrib non-free'
    set system package repository wheezy distribution wheezy
    set system package repository wheezy password ''
    set system package repository wheezy url 'http://ftp.us.debian.org/debian/'
    set system package repository wheezy username ''
    set system package repository wheezy-backports components main
    set system package repository wheezy-backports distribution wheezy-backports
    set system package repository wheezy-backports password ''
    set system package repository wheezy-backports url 'http://http.us.debian.org/debian'
    set system package repository wheezy-backports username ''
    set system package repository wheezy-updates components 'main contrib'
    set system package repository wheezy-updates distribution wheezy/updates
    set system package repository wheezy-updates password ''
    set system package repository wheezy-updates url 'http://security.debian.org/'
    set system package repository wheezy-updates username ''
    commit
    save
    end
```
Next, you need to run the apt-get commands:

``````javascript
    apt-get update
    apt-get install python-netaddr
```

Install the script

``````javascript
    install -o root -m 0755 <path to bogon.py> /config/scripts/bogon.py
```

And finally set up a cron job using task scheduler

``````javascript
    set system task-scheduler task update_threats executable path /config/scripts/bogon.py
    set system task-scheduler task update_threats interval 1d
```
