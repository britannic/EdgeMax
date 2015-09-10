#!/usr/bin/env perl
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
# A copy of the GNU General Public License is available as
# '/usr/share/common-licenses/GPL' in the Debian GNU/Linux distribution
# or on the World Wide Web at `http://www.gnu.org/copyleft/gpl.html'.
# You can also obtain it by writing to the Free Software Foundation,
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# Author: Neil Beadle
# Date: September 2015
# Description: Script for writing a unique sorted list of adserver and blacklisted fqdns to
# a file in dnsmasq format
#
# **** End License ****
my $version                        = 2.0;

use integer;
use strict;
use warnings;
use lib '/opt/vyatta/share/perl5/';
use Getopt::Long;
use Vyatta::Config;
use Vyatta::ConfigMgmt;
use XorpConfigParser;

my @blacklist                      = ();
my @exclusions                     = ();
my @blacklist_urls                 = ();
my @blacklist_rgxs                 = ();

my $dnsmasq                        = "/etc/init.d/dnsmasq";

# The IP address below should point to the IP of your router/pixelserver or to 0.0.0.0
# 0.0.0.0 is easy and doesn't require much from the router
my $black_hole_ip                  = "0.0.0.0";
my $blacklist_file                 = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my $cfg_file;
my $mode                           = &cmd_line;

sub cmd_line {
    my $std_alone;
    my $in_cli;
    my $cmd_line;
    my $print_ver;

    GetOptions(
        "cfg-file=s"               => \$cfg_file,
        "in-cli!"                  => \$in_cli,
        "std-alone!"               => \$std_alone,
        "version!"                 => \$print_ver
    );

    if ( defined($std_alone) ) {
        $cmd_line                  = "std-alone";
    }
    elsif ( defined($in_cli) ) {
        $cmd_line                  = "in-cli";
    }
    elsif ( defined($cfg_file) ) {
        $cmd_line                  = "cfg-file";
    }
    else {
        $cmd_line                  = "ex-cli";
    }

    if ( defined($print_ver) ) {
        printf( "%s version: %.2f\n", $0, $version );
        exit 0;
    }
    return $cmd_line;

}

sub uniq {
    my %hash                       = map { $_ => 1 } @_;
    return keys %hash;
}

sub write_list {
    my $fh;
    my $file                       = shift;
    my @list                       = @_;
    open( $fh, '>', $file ) or die "Could not open file: '$file' $!";
    print $fh (@list);
    close($fh);
}

sub cfg_none {

    # Source urls for blacklisted adservers and malware servers
    @blacklist_urls                = (
        qw|
            "http://winhelp2002.mvps.org/hosts.txt"
            "http://someonewhocares.org/hosts/zero/"
            "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=dnsmasq&showintro=0&mimetype=plaintext"
            "http://www.malwaredomainlist.com/hostslist/hosts.txt"|
    );

    # regexs strings that will only the return the FQDN or hostname
    @blacklist_rgxs                = (
        '^0\.0\.0\.0\s([-a-z0-9_.]+).*',
        '^127\.0\.0\.1\s\s\b([-a-z0-9_\.]*)\b[\s]{0,1}',
        '^address=/\b([-a-z0-9_\.]+)\b/127\.0\.0\.1'
    );

    # Exclude good hosts
    @exclusions                    = (
        qw|
            localhost msdn.com
            appleglobal.112.2o7.net
            cdn.visiblemeasures.com
            hb.disney.go.com
            googleadservices.com
            hulu.com
            static.chartbeat.com
            survey.112.2o7.net|
    );

    # Include bad hosts
    gnash( 'include', 'beap.gemini.yahoo.com' );
    return 1;
}

sub isblacklist {
    my $config                     = new Vyatta::Config;
    my $blklst_exists;
    my $bool                       = 0;
    $config->setLevel("service dns forwarding");
    if ( $mode eq "in-cli" ) {
        $blklst_exists             = $config->exists("blacklist");
    }
    else {
        $blklst_exists             = $config->existsOrig("blacklist");
    }
    if ( defined($blklst_exists) ) {
        $bool                      = 1;
    }
    else {
        $bool                      = 0;
    }
    return $bool;
}

sub gnash {
    my $list                       = shift;
    my $line                       = shift;
    if ( defined($line) ) {
        for ($list) {
            /blacklisted|include/ and do push( @blacklist,
                sprintf( "address=/%s/%s\n", $line, $black_hole_ip ) ),
                last;
            /blacklist_urls/ and do push( @blacklist_urls, $line ), last;
            /blacklist_rgxs/ and do push( @blacklist_rgxs, $line ), last;
            /exclude/        and do push( @exclusions,     $line ), last;
        }
    }
}

sub cfg_active {
    my ( @sources, $source, @includes, $include, @excludes, $exclude );
    my $config                     = new Vyatta::Config;

    if (isblacklist) {
        if ( $mode eq "in-cli" ) {
            $config->setLevel('service dns forwarding blacklist');
            @includes              = $config->returnValues('include');
            @excludes              = $config->returnValues('exclude');
            @sources               = $config->listNodes('source');
        }
        else {
            $config->setLevel('service dns forwarding blacklist');
            @includes              = $config->returnOrigValues('include');
            @excludes              = $config->returnOrigValues('exclude');
            @sources               = $config->listOrigNodes('source');
        }

        foreach $include (@includes) {
            gnash( 'blacklisted', $include );
        }

        foreach $exclude (@excludes) {
            gnash( 'exclude', $exclude );
        }

        foreach $source (@sources) {
            $config->setLevel(
                "service dns forwarding blacklist source $source");
            if ( $mode eq "in-cli" ) {
                gnash( 'blacklist_urls',
                    $config->returnValue('url') );
                gnash( 'blacklist_rgxs',
                    $config->returnValue('regex') );
            }
            else {
                gnash( 'blacklist_urls', $config->returnOrigValue('url') );
                gnash( 'blacklist_rgxs', $config->returnOrigValue('regex') );
            }
        }
    }
    else {
        return 0;
    }
    return 1;
}

sub cfg_file {
    my $rgx_url                    = qr/^url\s+(.*)$/;
    my $rgx_re                     = qr/^regex\s["{0,1}](.*)["{0,1}].*$/;
    my $xcp                        = new XorpConfigParser();
    $xcp->parse($cfg_file);

    my $hashBlacklist
                                   = $xcp->get_node( [ 'service', 'dns', 'forwarding', 'blacklist' ] );

    if ( defined($hashBlacklist) ) {
        my $hashBlacklistChildren  = $hashBlacklist->{'children'};
        my @excludes               = $xcp->copy_multis( $hashBlacklistChildren, 'exclude' );
        my @includes               = $xcp->copy_multis( $hashBlacklistChildren, 'include' );
        my @sources                = $xcp->copy_multis( $hashBlacklistChildren, 'source' );

        for ( $hashBlacklist->{'name'} ) {
            /^blackhole\s(.*)$/
                and $black_hole_ip = $_ // $black_hole_ip;
        }

        foreach my $multiBlacklistExclude (@excludes) {
            gnash( 'exclude', $multiBlacklistExclude->{'name'} );
        }

        foreach my $multiBlacklistInclude (@includes) {
            gnash( 'include', $multiBlacklistInclude->{'name'} );
        }

        foreach my $multiBlacklistSource (@sources) {
            my $hashSource         = $xcp->get_node(
                [   'service', 'dns', 'forwarding', 'blacklist',
                    "source $multiBlacklistSource->{'name'}"
                ]
            );

            my $hashSourceChildren = $hashSource->{'children'};

            foreach my $node (@$hashSourceChildren) {
                for ( $node->{'name'} ) {
                    /$rgx_url/
                        and gnash( 'blacklist_urls', $1 ), last;
                    /$rgx_re/
                        and gnash( 'blacklist_rgxs', $1 ), last;
                }
            }
        }
    }
    else {
        return 0;
    }
    return 1;
}

sub get_blklist_cfg {

    # Make sure localhost is in the whitelist of exclusions
    gnash( 'exclusions', 'localhost' );

    for ($mode) {
        m/ex-cli|in-cli/ and cfg_active, last;
        m/cfg-file/      and cfg_file,   last;
        m/std-alone/     and cfg_none,   last;
    }
}

sub update_blacklist {
    get_blklist_cfg;

    my $exclude                    = join( "|", uniq(@exclusions) );
    my $regex                      = join( "|", uniq(@blacklist_rgxs) );

    $exclude                       = qr/$exclude/;
    $regex                         = qr/$regex/;

    # Get blacklist and convert the hosts file into a dnsmasq.conf format
    # file. Be paranoid and replace every IP address with $black_hole_ip.
    # We only want the actual blacklist, so we can prepend our own hosts.
    # $black_hole_ip="0.0.0.0" saves router CPU cycles and is more efficient
    if ( !@blacklist_urls == 0 ) {
        foreach my $url (@blacklist_urls) {
            if ( $url =~ m|^http://| ) {
                my @content        = qx(curl -s $url);
                chomp @content;

                for my $line (@content) {
                    $line          = lc $line;
                    $line =~ s/\s+$//;

                    for ($line) {
                        length($_) < 1 and last;
                        !defined       and last;
                        /$exclude/     and last;
                        /$regex/ and gnash( 'blacklisted', $1 ), last;
                    }
                }
            }
        }
    }
}

sub get_blacklist {

    update_blacklist;
    return sort( uniq(@blacklist) );
}

# main()
# debug - uncomment print and comment write_list && ...
# print get_blacklist;

write_list( $blacklist_file, get_blacklist() );

system("$dnsmasq force-reload") if $mode ne "in-cli";
