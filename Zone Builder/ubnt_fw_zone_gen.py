#!/usr/bin/env python
#
# vyatta_firewall_builder.py - Build a zone-based IPv4/IPv6 firewall for Vyatta
#
# -*- coding: utf-8 -*-

version = '1.7.2'

import argparse
import itertools
import re
import subprocess as sp
import sys

# Define zones and which interfaces reside in each. The 'int' and
# 'ext' zones are required
#
# yapf: disable
zones = {
    'adm': {
        'description': 'Admin Zone',
        'interfaces': ('eth0',)
    },
    'dmz': {
        'description': 'DMZ Zone',
        'interfaces': (
                        'eth0.2',
                        'eth0.3',
                        'eth0.4',
                        'eth2',)
    },
    'ext': {'description':  'External Zone',
        'interfaces' :  ('eth1',)
    },
    'gst': {
        'description':      'Guest Zone',
        'interfaces': (
                        'eth0.6',
                        'eth0.7',)
    },
    'int': {
        'description':      'Internal Zone',
        'interfaces' :      (
                        'eth0.5',
                        'peth0',)
    },
    'mdx': {
        'description':      'Media Zone',
        'interfaces' :      (
                        'eth0.555',)
    }
}  # yapf: disable

# Define Groups which can be used in rules
# Note that Comcast distributes ipv6 from 'fe80::/10' - so do not add this to the bogon list
fw_groups = {
    'port_group': {
        'email': {
            'description': 'Email Port Group',
            'ports': (
                        'imap2',
                        'imaps',
                        'smtp',
                        'ssmtp',)
        },
        'ftp': {
            'description': 'FTP Port Group',
            'ports': (
                        'ftp-data',
                        'ftp',
                        'ftps-data',
                        'ftps',
                        'sftp',)
        },
        'print': {
            'description': 'Print Port Group',
            'ports': (
                        '1900',
                        '3702',
                        '5000',
                        '5001',
                        '5222',
                        '5357',
                        '8000',
                        '8610',
                        '8611',
                        '8612',
                        '8613',
                        '9000',
                        '9100',
                        '9200',
                        '9300',
                        '9500',
                        '9600',
                        '9700',
                        'http',
                        'https',
                        'ipp',
                        'netbios-dgm',
                        'netbios-ns',
                        'netbios-ssn',
                        'printer',
                        'snmp-trap',
                        'snmp',)
        },
        'ssdp': {
            'description': 'SSDP Port Group',
            'ports': (
                        '10102',
                        '1900',
                        '5354',
                        'afpovertcp',
                        'http',
                        'https',
                        'mdns',
                        'netbios-ns',)
        },
        'vpn': {
            'description': 'VPN Port Group',
            'ports': (
                        'isakmp',
                        'openvpn',
                        'l2tp',
                        '4500',)
        }
    },
    'address_group': {
        'media': {
            'description': 'Media Address Group',
            'addresses': (
                        '192.168.50.30-192.168.50.60',
                        '192.168.4.255',
                        '192.168.10.30',
                        '192.168.10.35',
                        '224.0.0.251',
                        '239.255.255.250',
                        '255.255.255.255',)
        }
    },
    'ipv4_group': {
        'ipv4Bogons': {
            'description': 'IPv4 BOGON Addresses',
            'addresses': (
                        '10.0.0.0/8',
                        '100.64.0.0/10',
                        '127.0.0.0/8',
                        '169.254.0.0/16',
                        '172.16.0.0/12',
                        '192.0.0.0/24',
                        '192.0.2.0/24',
                        '192.168.0.0/16',
                        '198.18.0.0/15',
                        '198.51.100.0/24',
                        '203.0.113.0/24',
                        '224.0.0.0/4',
                        '240.0.0.0/4',)
        }
    },
    'ipv6_group': {
        'ipv6Bogons': {
            'description': 'IPv6 BOGON Addresses',
            'addresses': (
                        '::/127',
                        '::ffff:0:0/96',
                        '::/96',
                        '100::/64',
                        '2001:10::/28',
                        '2001:db8::/32',
                        'fc00::/7',
                        'fec0::/10',
                        'ff00::/8',
                        '2002::/24',
                        '2002:a00::/24',
                        '2002:7f00::/24',
                        '2002:a9fe::/32',
                        '2002:ac10::/28',
                        '2002:c000::/40',
                        '2002:c000:200::/40',
                        '2002:c0a8::/32',
                        '2002:c612::/31',
                        '2002:c633:6400::/40',
                        '2002:cb00:7100::/40',
                        '2002:e000::/20',
                        '2002:f000::/20',
                        '2002:ffff:ffff::/48',
                        '2001::/40',
                        '2001:0:a00::/40',
                        '2001:0:7f00::/40',
                        '2001:0:a9fe::/48',
                        '2001:0:ac10::/44',
                        '2001:0:c000::/56',
                        '2001:0:c000:200::/56',
                        '2001:0:c0a8::/48',
                        '2001:0:c612::/47',
                        '2001:0:c633:6400::/56',
                        '2001:0:cb00:7100::/56',
                        '2001:0:e000::/36',
                        '2001:0:f000::/36',
                        '2001:0:ffff:ffff::/64',)
        }
    }
}  # yapf: disable

# Build list of all zone names, which can be used in rules
#
all_zones = zones.keys()
all_zones.append('loc')

# Build list of all groups, which can be used in rules
#
all_groups = fw_groups.keys()

# List of rules to create. Each rule is a list of arguments passed to the
# build_rule function. Each rule has the following elements:
#
# (
# source zone or list of source zones,
# dest zone or list of dest zones,
# list of parameters,
# list of ip versions (optional, defaults to [4, 6]),
# rulenum (optional, defaults to natural order)
# )
#

# yapf: disable

rules = (
    # RULE 1 *****************************************************************
    # Allow connections
    (('adm', 'loc'), all_zones, ('description "Allow all connections"', 'action accept', 'state new enable', 'state established enable', 'state related enable'), [4, 6]),
    (('int', 'mdx'), ('int', 'mdx'), ('description "Allow all connections"', 'action accept', 'state new enable', 'state established enable', 'state related enable'), [4, 6]),
    (('dmz', 'gst', 'int', 'mdx'), ('ext'), ('description "Allow all connections"', 'action accept', 'state new enable', 'state established enable', 'state related enable'), [4, 6]),
    (('dmz', 'gst', 'int', 'ext', 'mdx'), ('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('description "Allow established connections"', 'action accept', 'state established enable', 'state related enable'), [4, 6]),
    # RULE 2 ***********************************************************************
    # Drop invalid packets
    (all_zones, all_zones, ('description "Drop invalid packets"', 'action drop', 'state invalid enable'), [4, 6]),
    # RULE 3 ***********************************************************************
    # Drop invalid WAN source IPs
    ('ext', ('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('description "Drop IPv4 bogons"', 'action drop', 'source group network-group ipv4Bogons'), [4]),
    ('ext', ('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('description "Drop IPv6 bogons"', 'action drop', 'source group ipv6-network-group ipv6Bogons'), [6]),
    # RULE 300 *********************************************************************
    # Access 1 pixel HTTP server
    (('dmz', 'gst', 'int', 'mdx'), 'loc', ('description "Permit access to pixel server"', 'action accept', 'protocol tcp', 'destination address 192.168.168.1'), [4], 300),
    # RULE 400 *********************************************************************
    # Allow media address group access
#     (('dmz', 'gst'), ('int', 'mdx'), ('description "Allow media address group access"', 'action accept', 'destination group address-group media'), [4], 400),
    (('int', 'mdx'), ('adm', 'dmz', 'gst', 'loc'), ('description "Allow mdx to offer access to media address group"', 'action accept', 'source group address-group media'), [4], 400),
    # RULE 500 *********************************************************************
    # Allow ICMP/IPV6-ICMP
    ('ext', 'loc', ('description "Block ICMP ping from the Internet"', 'action drop', 'icmp type-name ping', 'protocol icmp'), [4], 500),
    ('ext', 'loc', ('description "Block IPv6-ICMP ping from the Internet"', 'action drop', 'icmpv6 type ping', 'protocol icmpv6'), [6], 500),
    ('ext', 'loc', ('description "Allow ICMP"', 'action accept', 'protocol icmp'), [4], 510),
    ('ext', 'loc', ('description "Allow IPv6-ICMP"', 'action accept', 'protocol icmpv6'), [6], 510),
    (('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('adm', 'dmz', 'ext', 'gst', 'int', 'loc', 'mdx'), ('description "Allow ICMP"', 'action accept', 'protocol icmp'), [4], 510),
    (('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('adm', 'dmz', 'ext', 'gst', 'int', 'loc', 'mdx'), ('description "Allow IPv6-ICMP"', 'action accept', 'protocol icmpv6'), [6], 510),
    # RULE 1000 ********************************************************************
    # Permit access to DNS
    (('dmz', 'gst', 'int', 'mdx'), 'loc', ('description "Permit access to local DNS"', 'action accept', 'protocol tcp_udp', 'destination port domain'), [4, 6], 1000),
    # RULE 1500 ********************************************************************
    # Block MDNS and SSDP access to Internet
    (('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), 'ext', ('description "Block MDNS & SSDP access to Internet"', 'action drop', 'protocol udp', 'destination port mdns'), [4, 6], 1500),
    # RULE 2000-2100 **************************************************************
    # Permit access to SSDP
    (('dmz', 'gst'), ('int', 'mdx'), ('description "Permit MDNS & SSDP access"', 'action accept', 'protocol tcp_udp', 'destination group port-group ssdp'), [4, 6], 2000),
    (('dmz', 'gst'), ('int', 'mdx'), ('description "Permit MDNS & SSDP access"', 'action accept', 'protocol tcp_udp','destination group address-group media'), [4], 2000),
    # Permit access to Print
    (('dmz', 'gst'), 'int', ('description "Permit Printer access"', 'action accept', 'protocol tcp_udp', 'destination group port-group print'), [4, 6], 2100),
    (('dmz', 'gst'), 'int', ('description "Permit Printer access"', 'action accept', 'protocol tcp_udp','destination group address-group media'), [4], 2100),
    # RULES 3000-3100 **************************************************************
    # Drop brute force SSH from Internet
    ('ext', ('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('description "Drop brute force SSH from Internet"', 'action drop', 'protocol tcp', 'destination port ssh', 'recent count 3', 'recent time 30'), [4], 3000),
    # Allow SSH
    (('adm', 'int', 'loc', 'mdx'), ('adm', 'dmz', 'gst', 'int', 'loc', 'mdx'), ('description "Allow SSH"', 'action accept', 'protocol tcp', 'destination port ssh'), [4], 3100),
    ('ext', 'loc', ('description "Allow SSH"', 'action accept', 'protocol tcp', 'destination port ssh'), [4], 3100),
    # RULES 5000-5600 **************************************************************
    # Allow vpn traffic ext/int
    (('ext', 'int'), ('loc', 'dmz'), ('description "Allow vpn traffic"', 'action accept', 'protocol udp', 'destination group port-group vpn'), [4], 5000),
    (('ext', 'int'), ('loc', 'dmz'), ('description "Allow vpn PPTP"', 'action accept', 'protocol tcp', 'destination port 1723'), [4], 5500),
    (('ext', 'int'), ('loc', 'dmz'), ('description "Allow vpn ESP"', 'action accept', 'protocol esp'), [4], 5600),
    # RULE 6000 ********************************************************************
    # Allow ADT Camera streams
    ('int', 'dmz', ('description "Allow ADT Camera streams"', 'action accept', 'protocol tcp_udp', 'destination port 4301-4325', 'log enable'), [4], 6000),
    # RULE 7000 ********************************************************************
    # Allow DHCP/DHCPV6 responses from ISP
    ('ext', 'loc', ('description "Allow DHCPV4 responses from ISP"', 'action accept', 'protocol udp', 'source port bootps', 'destination port bootpc'), [4], 7000),
    ('ext', 'loc', ('description "Allow DHCPV6 responses from ISP"', 'action accept', 'protocol udp', 'source address fe80::/64', 'source port dhcpv6-server', 'destination port dhcpv6-client'), [6], 7000),
    # Allow DHCP/DHCPV6 responses from DMZ, int, mdx and gst to local
    (('dmz', 'gst', 'int', 'mdx'), 'loc', ('description "Allow DHCPV4 responses"', 'action accept', 'protocol udp', 'source port bootpc', 'destination port bootps'), [4], 7000),
    (('dmz', 'gst', 'int', 'mdx'), 'loc', ('description "Allow DHCPV6 responses"', 'action accept', 'protocol udp', 'source port dhcpv6-client', 'destination port dhcpv6-server'), [6], 7000)
    )
# yapf: enable

class switch(object):

    def __init__(self, value):
        self.value                                          = value
        self.fall                                           = False

    def __iter__(self):
        #Return the match method once, then stop
        yield self.match
        raise StopIteration

    def match(self, *args):
        #Indicate whether or not to enter a case suite
        if self.fall or not args:
            return True
        elif self.value in args:  # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False

# Counters to determine rule numbers for rules without explicit rule numbers
#
ruleset_counters = {}

global commands
commands         = []

vyatta_cmd       = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"


# vyatta_cmd                                                = "echo" # Debug


def get_args():
    # Enable default logging (rule 10000)
    # Defaulted to log all non-matching dropped packets
    #
    # global default_log
    # default_log                                           = user_opts.default_log

    # Set this to False unless you want to generate and write to your config.boot file
    #
    # update_config_boot                                    = user_opts.update_config_boot

    parser           = argparse.ArgumentParser(
        description  =
        'Build a zone-based IPv4/IPv6 firewall configuration for Vyatta.',
        epilog       =
        'If [-l/-log] isn\'t set, enable-default-log will be disabled for all rulesets. If [-U/-Update] isn\'t set, %(prog)s prints to STDOUT.')

    parser.add_argument(
        '-U',
        '-Update',
        action       = "store_true",
        default      =False,
        dest         ='update_config_boot',
        help         =
        'Directly update firewall configuration, commit and save config.boot - CAUTION, only use this option if you know your proposed firewall configuration is correct.')

    parser.add_argument(
        '-l',
        '-log',
        action       = "store_true",
        default      =False,
        dest         ='default_log',
        help         =
        'Sets enable-default-log option on built-in rule 10000 for each rule set. Any dropped packets unmatched by your rule set will be logged.')

    parser.add_argument(
        '-v',
        '-version',
        action       = 'version',
        help         ='Show %(prog)s version and exit.',
        version      = '%(prog)s {}'.format(version))

    global user_opts

    user_opts        = parser.parse_args()


def yesno(*args):

    if len(args) > 1:
        default                                             = args[0].strip().lower()
        question                                            = args[1].strip()
    elif len(args) == 1:
        default                                             = args[0].strip().lower()
        question                                            = 'Answer y or n:'
    else:
        default                                             = None
        question                                            = 'Answer y or n:'

    if default == None:
        prompt                                              = " [y/n] "
    elif default == "y":
        prompt                                              = " [Y/n] "
    elif default == "n":
        prompt                                              = " [y/N] "
    else:
        raise ValueError(
            "{} invalid default parameter: \'{}\' - only [y, n] permitted".format(
                __name__, default))

    while 1:
        sys.stdout.write(question + prompt)
        choice                                              = (raw_input().lower().strip() or '')
        if default is not None and choice == '':
            if default == 'y':
                return True
            elif default == 'n':
                return False
        elif default is None:
            if choice == '':
                continue
            elif choice[0] == 'y':
                return True
            elif choice[0] == 'n':
                return False
            else:
                sys.stdout.write("Answer must be either y or n.\n")
        elif choice[0] == 'y':
            return True
        elif choice[0] == 'n':
            return False
        else:
            sys.stdout.write("Answer must be either y or n.\n")

def build_rule(source_zones, dest_zones, params, ipversions = [4, 6], rulenum=None):
    '''
    Build a rule for each applicable zone direction and IP version
    '''
    # If zones are passed as simple strings, convert to tuples
    if isinstance(source_zones, str):
        source_zones                                        = (source_zones,)

    if isinstance(dest_zones, str):
        dest_zones                                          = (dest_zones,)

    if isinstance(params, str):
        raise TypeError("params must be a list or tuple")

    # All combinations of source -> dest
    for source, dest in itertools.product(source_zones, dest_zones):
        if source == dest:
            continue
        ruleset                                             = '%s-%s' % (source, dest)

        # Check/update counter for ruleset if rulenum is omitted
        if rulenum:
            ruleid                                          = rulenum
        else:
            if not ruleset in ruleset_counters:
                ruleset_counters[ruleset]                   = 0
            ruleset_counters[ruleset] += 1
            ruleid                                          = ruleset_counters[ruleset]
        for ipversion in ipversions:
            if ipversion == 4:
                name_param                                  = 'name'
                set_name                                    = ruleset
            else:
                name_param                                  = 'ipv6-name'
                set_name                                    = 'ipv6-' + ruleset
            base_cmd                                        = "set firewall %s %s rule %s" % (name_param, set_name,
                                                       ruleid)
            commands.append(base_cmd)
            for param in params:
                commands.append(base_cmd + " " + param)


if __name__ == '__main__':
    get_args()

    commands.append("delete firewall group")
    commands.append("delete firewall name")
    commands.append("delete firewall ipv6-name")
    commands.append("delete zone-policy")

    for a in all_groups:
        for case in switch(a):
            if case('port_group'):
                dkey                                        = 'ports'
                gtype                                       = 'port-group'
                gtarget                                     = 'port'
                break

            if case('address_group'):
                dkey                                        = 'addresses'
                gtype                                       = 'address-group'
                gtarget                                     = 'address'
                break

            if case('ipv4_group'):
                dkey                                        = 'addresses'
                gtype                                       = 'network-group'
                gtarget                                     = 'network'
                break

            if case('ipv6_group'):
                dkey                                        = 'addresses'
                gtype                                       = 'ipv6-network-group'
                gtarget                                     = 'ipv6-network'
                break

        for b in fw_groups[a].keys():
            commands.append("set firewall group %s %s description '%s'" %
                            (gtype, b, fw_groups[a][b]['description']))

            for c in fw_groups[a][b][dkey]:
                commands.append(
                    "set firewall group %s %s %s %s" % (gtype, b, gtarget, c))

    # Build a ruleset for every direction (eg: 'int-ext', 'ext-dmz', 'ext-loc', etc.)
    rulesets                                                = list(itertools.permutations(all_zones, 2))

    # Create rulesets for all directions
    for src, dest in rulesets:
        for prefix in ('', 'ipv6-'):
            if user_opts.default_log:
                commands.append(
                    "set firewall %sname %s%s-%s enable-default-log" %
                    (prefix, prefix, src, dest))
            commands.append(
                "set firewall %sname %s%s-%s" % (prefix, prefix, src, dest))
            commands.append("set firewall %sname %s%s-%s default-action drop" %
                            (prefix, prefix, src, dest))

    # Add rules
    for rule in rules:
        build_rule(*rule)

    # Create zones
    for zone in all_zones:
        # Create zone
        if not zone == 'loc':
            commands.append("set zone-policy zone %s description '%s'" %
                            (zone, zones[zone]['description']))
            commands.append(
                "set zone-policy zone %s default-action drop" % zone)
            # Add interfaces
            for interface in zones[zone]['interfaces']:
                commands.append(
                    "set zone-policy zone %s interface %s" % (zone, interface))
#       elif zone == 'loc':
        else:
            # Configure local zone
            commands.append(
                "set zone-policy zone %s default-action drop" % zone)
            commands.append("set zone-policy zone %s local-zone" % zone)

        # Set rulesets
        for srczone in all_zones:
            if srczone == zone:
                continue
            for prefix in ('', 'ipv6-'):
                commands.append(
                    "set zone-policy zone %s from %s firewall %sname %s%s-%s" %
                    (zone, srczone, prefix, prefix, srczone, zone))

    # Remove duplicates
    seen = set()
    result = []
    for item in commands:
        if item not in seen:
            seen.add(item)
            result.append(item)
    commands = result

    if user_opts.update_config_boot and yesno(
            'y', 'OK to update your configuration?'):  # Open a pipe to bash and iterate commands

        commands[:0]                                        = ["begin"]
        commands.append("commit")
        commands.append("save")
        commands.append("end")

        vyatta_shell                                        = sp.Popen(
            'bash',
            shell=True,
            stdin                                           = sp.PIPE,
            stdout=sp.PIPE,
            stderr                                          = sp.PIPE)
        for cmd in commands:  # print to stdout
            print cmd
            vyatta_shell.stdin.write('{} {};\n'.format(vyatta_cmd, cmd))

        out, err                                            = vyatta_shell.communicate()

        cfg_error                                           = False
        if out:
            if re.search(r'^Error:.?', out):
                cfg_error                                   = True
            print "configure message:"
            print out
        if err:
            cfg_error                                       = True
            print "Error reported by configure:"
            print err
        if (vyatta_shell.returncode == 0) and not cfg_error:
            print "Zone firewall configuration was successful."
        else:
            print "Zone firewall configuration was NOT successful!"

    else:
        for cmd in commands:
            print "echo %s" % cmd
            print cmd
