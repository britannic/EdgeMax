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
* Exclusions can be added in line 22

## Compatibility
* update-blacklists-dnsmasq.pl has been tested on the EdgeRouter Lite family of routers, version v1.6.0-v1.7.0.
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script could easily be adapted for work on VyOS and Vyatta derived ports

## Installation


* upload ersetup.tgz to your router (e.g. scp <local path>/ersetup.tgz <user>@<erl router>:/tmp/ersetup.tgz
* on your router: cd /tmp; sudo tar zxvf /tmp/ersetup.tgz
* sudo bash /tmp/ersetup.tgz
* optional: update line 15 of /config/scripts/update-blacklists-dnsmasq.pl wih your pixelserver IP
* optional: update line 22 with any desired exclusion addresses (i.e. ".*googleadservices.com", ".*hulu.com")
* kickstart the blacklist update (cron will run it at midnight local time): /config/scripts/update-blacklists-dnsmasq.pl