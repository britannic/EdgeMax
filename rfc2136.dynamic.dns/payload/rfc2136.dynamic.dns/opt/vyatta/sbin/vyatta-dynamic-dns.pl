#!/usr/bin/perl
#
# Module: vyatta-dynamic-dns.pl
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2008 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Mohit Mehta
# Date: September 2008
# Description: Script to run ddclient per interface as set in Vyatta CLI
#
# **** End License ****
#

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::Misc;
use Getopt::Long;

use strict;
use warnings;
use Switch;

my $ddclient_run_dir = '/var/run/ddclient';
my $ddclient_cache_dir = '/var/cache/ddclient';
my $ddclient_config_dir = '/etc/ddclient';

my @fixed_services = qw(afraid cloudflare dnspark dslreports dyndns easydns
                        namecheap sitelutions zoneedit);

my @web_builtins = qw(dyndns dnspark loopia);

#
# main
#

my %_services_defaults = (
    afraid => {
        protocol => "freedns"
    },
    changeip => {
        protocol => "changeip"
    },
    cloudflare => {
        protocol => "cloudflare"
    },
    dnspark => {
        protocol => "dnspark"
    },
    dslreports => {
        protocol => "dslreports1"
    },
    dyndns => {
        protocol => "dyndns2"
    },
    easydns => {
        protocol => "easydns"
    },
    namecheap => {
        protocol => "namecheap"
    },
    noip => {
        protocol => "noip"
    },
    sitelutions => {
        protocol => "sitelutions"
    },
    zoneedit => {
        protocol => "zoneedit1"
    }
);

my ($update_dynamicdns, $op_mode_update_dynamicdns, $stop_dynamicdns, $interface, $get_services, $get_default_services, $get_protocols, $check_nodes, $check_service, $check_web);

GetOptions(
    "update-dynamicdns!"            => \$update_dynamicdns,
    "stop-dynamicdns!"              => \$stop_dynamicdns,
    "op-mode-update-dynamicdns!"    => \$op_mode_update_dynamicdns,
    "interface=s"                   => \$interface,
    "get-services!"                 => \$get_services,
    "get-default-services!"         => \$get_default_services,
    "get-protocols!"                => \$get_protocols,
    "check-nodes!"                  => \$check_nodes
);

if (defined $update_dynamicdns) {
   my $config;
   $config  = dynamicdns_get_constants();
   $config .= dynamicdns_get_values();
   dynamicdns_write_file($config);
   dynamicdns_restart();
}

if (defined $op_mode_update_dynamicdns) {
    dynamicdns_restart();
}

if (defined $stop_dynamicdns) {
    dynamicdns_stop();
}

if (defined($check_service)) {
    do_check_service();
}

if (defined($check_web)) {
    do_check_web();
}

dynamicdns_get_services() if (defined $get_services);
dynamicdns_get_default_services() if (defined $get_default_services);
dynamicdns_get_protocols() if (defined $get_protocols);
dynamicdns_check_nodes() if (defined $check_nodes);

exit 0;

#
# subroutines
#

sub do_check_service {
    exit 0 if grep(/^$check_service$/, @fixed_services);

    exit 0 if ($check_service =~ m/^custom-\w+$/);

    print "Invalid service name \"$check_service\"\n";
    exit 1;
}

sub do_check_web {
    foreach my $builtin (@web_builtins) {
        exit 0 if ($check_web =~ m/^$builtin$/);
    }
    exit 0 if ($check_web =~ m/\./);

    print "Invalid Web page \"$check_web\"\n";
    exit 1;
}

sub dynamicdns_restart {
    dynamicdns_stop();
    dynamicdns_start();
}

sub dynamicdns_start {

    if(! -d $ddclient_run_dir ){
            system ("mkdir $ddclient_run_dir\;");
    }
    if(! -d $ddclient_cache_dir ){
            system ("mkdir $ddclient_cache_dir\;");
    }

    system("/usr/sbin/ddclient -file $ddclient_config_dir/ddclient_$interface.conf >&/dev/null");

}

sub dynamicdns_stop {
    system("kill -9 `cat $ddclient_run_dir/ddclient_$interface.pid 2>/dev/null` >&/dev/null");
    system("rm -f $ddclient_cache_dir/ddclient_$interface.cache >&/dev/null");
}

sub dynamicdns_check_nodes {
    my $config = new Vyatta::Config;
    $config->setLevel("service dns dynamic interface $interface");

    my @services = $config->listNodes("service");
    foreach my $service (@services) {
        $config->setLevel("service dns dynamic interface $interface service $service");

        # Check if we have a login, a password and host-name(s)
        if(!defined($config->returnValue('login')) or $config->returnValue('login') eq '') {
            print "A login must be set for dynamic dns service $service on interface $interface\n";
            exit 1;
        }
        if(!defined($config->returnValue('password')) or $config->returnValue('password') eq '') {
            print "A password must be set for dynamic dns service $service on interface $interface\n";
            exit 1;
        }
        if(!defined($config->returnValues('host-name')) or $config->returnValues('host-name') eq 0) {
            print "An host-name must be set for dynamic dns service $service on interface $interface\n";
            exit 1;
        }

        # Check if we have a non-default service
        if(!defined($_services_defaults{$service})) {
            if(!defined($config->returnValue('protocol')) or $config->returnValue('protocol') eq '') {
                print "A protocol must be set for custom dynamic dns service $service on interface $interface\n";
                exit 1;
            }
            if(!defined($config->returnValue('server')) or $config->returnValue('server') eq '') {
                print "A server must be set for custom dynamic dns service $service on interface $interface\n";
                exit 1;
            }
        }
    }
    exit 0;
}

# Will return a string with default services only (those which don't need an explicit server or protocol value)
sub dynamicdns_get_default_services {
    print join(' ', keys(%_services_defaults));
    print "\n";
}

# Return a list of supported protocols
sub dynamicdns_get_protocols {
    for my $service (keys %_services_defaults) {
        print " $_services_defaults{$service}{'protocol'}";
    }
    print "\n";
}

# Will return a string with default services and set services, useful for CLI completion
sub dynamicdns_get_services {
    my @o_services = keys %_services_defaults;
    my $output;
    my $config = new Vyatta::Config;
    $config->setLevel("service dns dynamic interface $interface");

    my @services = $config->listNodes("service");
    foreach my $service (@services) {
        push(@o_services, $service);
    }
    my @unique_o_services = do {
        my %seen;
        grep {!$seen{$_}++} @o_services;
    };
    print join(' ', @unique_o_services);
    print "\n";
}

sub dynamicdns_get_constants {
    my $output;

    my $date = `date`;
    chomp $date;
    $output  = "#\n# autogenerated by vyatta-dynamic-dns.pl on $date\n#\n";
    $output .= "daemon=1m\n";
    $output .= "syslog=yes\n";
    $output .= "ssl=yes\n";
    $output .= "pid=$ddclient_run_dir/ddclient_$interface.pid\n";
    $output .= "cache=$ddclient_cache_dir/ddclient_$interface.cache\n";
    return $output;
}

sub dynamicdns_get_values {

	my $output = '';
	my $config = new Vyatta::Config;
	$config->setLevel("service dns dynamic interface $interface");

	my $web = $config->returnValue("web");
	my $wskip = $config->returnValue("web-skip");
	if (defined($web)) {
		my $webskip = '';
		if (defined($wskip)) {
			$webskip = ", web-skip='$wskip'";
		}
		$output .= "use=web, web='$web'$webskip\n\n\n";
	} else {
		$output .= "use=if, if=$interface\n\n\n";
	}

	my @services = $config->listNodes("service");
	foreach my $service (@services) {
		$config->setLevel("service dns dynamic interface $interface service $service");
		switch ($service) {
			case "afraid"		{$service="freedns";}
			case "changeip"		{$service="changeip";}
			case "cloudflare"	{$service="cloudflare";}
			case "dnspark"		{$service="dnspark";}
			case "dslreports"	{$service="dslreports1";}
			case "dyndns"		{$service="dyndns2";}
			case "easydns"		{$service="easydns";}
			case "hammernode"	{$service="hammernode1";}
			case "namecheap"	{$service="namecheap";}
			case "noip"			{$service="noip";}
			case "sitelutions"	{$service="sitelutions";}
			case "zoneedit"		{$service="zoneedit1";}
		}
		my $login = $config->returnValue("login");
		my $password = $config->returnValue("password");
		my @hostnames = $config->returnValues("host-name");
		my $server = $config->returnValue("server");
		my $opts = $config->returnValue("options");
		my $proto = $config->returnValue("protocol");
		if ($service =~ m/^custom-/) {
			$service = $proto;
		}
		if (!defined($service)) {
		  print "Must define \"protocol\" for custom service type\n";
		  exit 1;
		}
		foreach my $hostname (@hostnames) {
			my $zone;
			if ($service eq "cloudflare") {
				$server = "www.cloudflare.com";
				$zone = $hostname;
				$zone =~ s/.*?\.//;
			}
			$output .= "server=$server," if defined $server;
			$output .= "protocol=$service\n";
			$output .= "max-interval=28d\n";
			if (defined($opts)) {
				$output .= "$opts\n";
			}
			$output .= "login=$login\n";
			$output .= "password='$password'\n";
			$output .= "zone=$zone\n" if defined $zone;
			$output .= "$hostname\n\n";
			}
		}

		$config->setLevel("service dns dynamic interface $interface");
		my @rfc2136s = $config->listNodes("rfc2136");
		foreach my $rfc2136 (@rfc2136s) {
			$config->setLevel("service dns dynamic interface $interface rfc2136 $rfc2136");
			my $key_file = $config->returnValue("key");
			my @records = $config->returnValues("record");
			my $server = $config->returnValue("server");
			my $ttl = $config->returnValue("ttl");
			my $zone = $config->returnValue("zone");

			foreach my $record (@records) {
				$output .= "server=$server\n";
				$output .= "protocol=nsupdate\n";
				$output .= "login=/usr/bin/nsupdate\n";
				$output .= "password=$key_file\n";
				$output .= "ttl=$ttl\n";
				$output .= "zone=$zone\n";
				$output .= "$record\n\n";
			}
		}
		return $output;
}

sub dynamicdns_write_file {
    my ($config) = @_;

    if(! -d $ddclient_config_dir ){
            system ("mkdir $ddclient_config_dir\;");
    }
    open(my $fh, '>', "$ddclient_config_dir/ddclient_$interface.conf") || die "Couldn't open \"$ddclient_config_dir/ddclient_$interface.conf\" - $!";
    print $fh $config;
    close $fh;
}


# end of file
