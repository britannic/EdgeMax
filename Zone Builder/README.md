# UBNT EdgeMax Zone Rule Set Generator for EdgeOS 1.6.0 and 1.7.0
http://community.ubnt.com/t5/EdgeMAX/Zone-Firewall-Groups-and-Rules-Generator/m-p/1324358#M75380
git@empirecreekcircle.com

NOTE: THIS IS NOT OFFICIAL UBIQUITI SOFTWARE AND THEREFORE NOT SUPPORTED OR ENDORSED BY Ubiquiti Networks®

## Overview
ubnt_fw_zone_gen.py is based on @jfunk's (https://community.ubnt.com/t5/user/viewprofilepage/user-id/152190) excellent vyatta_firewall_builder.py and the work of @mrjester (http://community.ubnt.com/t5/user/viewprofilepage/user-id/131140) aka @UBNT-Bane﻿ (http://community.ubnt.com/t5/user/viewprofilepage/user-id/259529). It provides a quick and easy way to generate groups and rulesets for Zone Policy based firewalls used on Vyos (formerly Vyatta) and EdgeOS based routers.

## Licenses
* GNU General Public License, version 3
* GNU Lesser General Public License, version 3

## Features
* Generates a complete set of firewall commands that can be sourced directly by configure
* Command line switches to update the configuration directly and also disable/enable logging for the default 10000 rule (enable-default-log)

## Compatibility
*  ubnt_fw_zone_gen.py has been tested on the EdgeRouter Lite family of routers, version v1.5.0-v1.7.0.
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script can easily be adapted for work on VyOS and Vyatta derived ports

## Usage

usage: ubnt_fw_zone_gen.py [-h] [-U] [-l] [-v]

Build a zone-based IPv4/IPv6 firewall configuration for Vyatta.

optional arguments:
-h, --help    show this help message and exit
-U, -Update   Directly update firewall configuration, commit and save
config.boot - CAUTION, only use this option if you know your
proposed firewall configuration is correct.
-l, -log      Sets enable-default-log option on built-in rule 10000 for each
rule set. Any dropped packets unmatched by your rule set will
be logged.
-v, -version  Show ubnt_fw_zone_gen.py version and exit.

If [-l/-log] isn't set, enable-default-log will be disabled for all rulesets.
If [-U/-Update] isn't set, ubnt_fw_zone_gen.py prints to STDOUT.
