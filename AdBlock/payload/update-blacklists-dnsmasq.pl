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
my $version = 3.00;

use URI;
use integer;
use strict;
use warnings;
use lib '/opt/vyatta/share/perl5/';
use Getopt::Long;
use Vyatta::Config;
use Vyatta::ConfigMgmt;
use XorpConfigParser;

use constant blacklist => 'blacklist';
use constant url       => 'url';
use constant prefix    => 'prefix';
use constant exclude   => 'exclude';

my @blacklist      = ();
my $ref_blst       = \@blacklist;
my @exclusions     = ();
my $ref_excs       = \@exclusions;
my @blacklist_urls = ();
my $ref_urls       = \@blacklist_urls;
my @blacklist_prfx = ();
my $ref_prfx       = \@blacklist_prfx;
my $entry          = " - Entries processed: ";
my $dnsmasq        = "/etc/init.d/dnsmasq";
my $uri;
my $fqdn
    = '((?=.{1,254}$)((?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$))\s*$';

# The IP address below should point to the IP of your router/pixelserver or to 0.0.0.0
# 0.0.0.0 is easy and doesn't require much from the router
my $black_hole_ip;
my $ref_bhip       = \$black_hole_ip;
my $blacklist_file = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my $cfg_file;
my $ref_mode;
my $i       = 0;
my $counter = \$i;
my $list;
my $line;

my @debug;

sub cmd_line {
    my $cmdmode = \$ref_mode;
    my $in_cli;
    my $print_ver;
    my $std_alone;

    GetOptions(
        "cfg-file=s" => \$cfg_file,
        "in-cli!"    => \$in_cli,
        "std-alone!" => \$std_alone,
        "version!"   => \$print_ver
        )
        or print(
        "Valid options: --in-cli | --std-alone | --version | --cfg_file <filename>\n"
        ) and exit 0;

    if ( defined($std_alone) ) {
        $$cmdmode = "std-alone";
    }
    elsif ( defined($in_cli) ) {
        qx(/bin/cli-shell-api inSession);
        if ( $? > 0 ) {
            print
                "You must run $0 inside of configure when '--in-cli' is specified!\n";
            exit 0;
        }
        $$cmdmode = "in-cli";
    }
    elsif ( defined($cfg_file) ) {
        $$cmdmode = "cfg-file";
        if ( !-f $cfg_file ) {
            print("$cfg_file doesn't exist!\n");
            exit 0;
        }
    }
    else {
        $$cmdmode = "ex-cli";
    }

    if ( defined($print_ver) ) {
        printf( "%s version: %.2f\n", $0, $version );
        exit 0;
    }
}

sub sendit {
    my ( $listref, $lineref ) = @_;
    my ( $list, $line ) = ( $$listref, $$lineref );
    if ( defined($line) ) {
        for ($list) {
            /blacklist/ and push( @$ref_blst, "address=/$line/$$ref_bhip\n" ),
                last;
            /url/ and push( @$ref_urls, $line ), last;
            /prefix/ and push( @$ref_prfx, '^' . qq($line) . $fqdn ), last;
            /exclude/ and push( @$ref_excs, $line ), last;
        }
    }
}

sub uniq {
    @$_ = ( sort keys %{ { map { $_ => 1 } @$_ } } );
}

sub write_list($$) {
    my $fh;
    my ( $file, $list ) = @_;
    open( $fh, '>', $$file ) or die "Could not open file: '$file' $!";
    print $fh (@$list);
    close($fh);
}

sub cfg_none {
    $$ref_bhip = "0.0.0.0";

    # Source urls for blacklisted adservers and malware servers
    for (
        qw|
            http://winhelp2002.mvps.org/hosts.txt
            http://someonewhocares.org/hosts/zero/
            http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext
            http://www.malwaredomainlist.com/hostslist/hosts.txt|
    ){
        sendit( \url, \$_ );
    }

# prefix strings to be removed, leaving the FQDN or hostname + trailing suffix
    for (
        qw(
        0.0.0.0..
        127.0.0.1..
        address=/
        )
        )
    {
        sendit( \prefix, \$_ );
    }

    # Exclude our own good hosts
    for (
        qw|
        localhost
        msdn.com
        appleglobal.112.2o7.net
        cdn.visiblemeasures.com
        hb.disney.go.com
        googleadservices.com
        hulu.com
        static.chartbeat.com
        survey.112.2o7.net|
        )
    {
        sendit( \exclude, \$_ );
    }

    # Include our own bad hosts
    my $include = "beap.gemini.yahoo.com";
    sendit( \blacklist, \$include );
    return 1;
}

sub isblacklist {
    my $config = new Vyatta::Config;
    my $blklst_exists;
    my $bool = 0;
    $config->setLevel("service dns forwarding");
    if ( $ref_mode eq "in-cli" ) {
        $blklst_exists = $config->exists("blacklist");
    }
    else {
        $blklst_exists = $config->existsOrig("blacklist");
    }
    if ( defined($blklst_exists) ) {
        $bool = 1;
    }
    else {
        $bool = 0;
    }
    return $bool;
}

sub cfg_active {
    my ( @sources, @includes, @excludes );
    my $config = new Vyatta::Config;

    if (isblacklist) {
        if ( $ref_mode eq "in-cli" ) {
            $config->setLevel('service dns forwarding blacklist');
            @includes  = $config->returnValues('include');
            @excludes  = $config->returnValues('exclude');
            @sources   = $config->listNodes('source');
            $$ref_bhip = $config->returnValue('blackhole') // "0.0.0.0";
        }
        else {
            $config->setLevel('service dns forwarding blacklist');
            @includes  = $config->returnOrigValues('include');
            @excludes  = $config->returnOrigValues('exclude');
            @sources   = $config->listOrigNodes('source');
            $$ref_bhip = $config->returnOrigValue('blackhole') // "0.0.0.0";
        }

        for (@includes) {
            sendit( \blacklist, \$_ );
        }

        for (@excludes) {
            sendit( \exclude, \$_ );
        }

        for (@sources) {
            $config->setLevel("service dns forwarding blacklist source $_");
            if ( $ref_mode eq "in-cli" ) {
                sendit( \url,    \$config->returnValue('url') );
                sendit( \prefix, \$config->returnValue('prefix') );
            }
            else {
                sendit( \url,    \$config->returnOrigValue('url') );
                sendit( \prefix, \$config->returnOrigValue('prefix') );
            }
        }
    }
    else {
        return 0;
    }
    return 1;
}

sub cfg_file {
    my $mode = $ref_mode
        ; # not yet sure why $cmdmode ends up undef after this sub, so preserving it
    my $rgx_url = qr/^url\s+(.*)$/;
    my $prfx_re = qr/^prefix\s+["{0,1}](.*)["{0,1}].*$/;
    my $xcp     = new XorpConfigParser();
    $xcp->parse($cfg_file);

    my $hashBlacklist
        = $xcp->get_node( [ 'service', 'dns', 'forwarding', 'blacklist' ] );

    if ( defined($hashBlacklist) ) {
        my $hashBlacklistChildren = $hashBlacklist->{'children'};
        my @excludes = $xcp->copy_multis( $hashBlacklistChildren, 'exclude' );
        my @includes = $xcp->copy_multis( $hashBlacklistChildren, 'include' );
        my @sources  = $xcp->copy_multis( $hashBlacklistChildren, 'source' );

        for ( my $i = 0; $i < @{ $hashBlacklist->{'children'} }; $i++ ) {
            for ( $hashBlacklist->{'children'}[$i]{'name'} ) {
                /^blackhole\s+(.*)$/ and $$ref_bhip = $1 // "0.0.0.0";
            }

        }

        for my $multiBlacklistExclude (@excludes) {
            sendit( \exclude, \$multiBlacklistExclude->{'name'} );
        }

        for my $multiBlacklistInclude (@includes) {
            sendit( \blacklist, \$multiBlacklistInclude->{'name'} );
        }

        for my $multiBlacklistSource (@sources) {
            my $hashSource = $xcp->get_node(
                [   'service', 'dns', 'forwarding', 'blacklist',
                    "source $multiBlacklistSource->{'name'}"
                ]
            );

            my $hashSourceChildren = $hashSource->{'children'};

            for (@$hashSourceChildren) {
                for ( $_->{'name'} ) {
                    /$rgx_url/
                        and sendit( \url, \$1 ), last;
                    /$prfx_re/
                        and sendit( \prefix, \$1 ), last;
                }
            }
        }
    }
    else {
        return 0;
    }
    $ref_mode
        = $mode;   # restoring $cmdmode as this sub is clobbering it somewhere
    return 1;
}

sub get_blklist_cfg {

    # Make sure localhost is in the whitelist of exclusions
    my $exclude = 'localhost';
    sendit( \exclude, \$exclude );

    for ($ref_mode) {
        m/ex-cli|in-cli/ and cfg_active, last;
        m/cfg-file/      and cfg_file,   last;
        m/std-alone/     and cfg_none,   last;
    }
}

sub update_blacklist {

    my $mode = \$ref_mode;
    uniq($ref_excs);
    uniq($ref_prfx);

    my $exclude = join( "|", @$ref_excs );
    my $prefix  = join( "|", @$ref_prfx );
    my $strmregex = qr/^\s+|\s+$|\n|\r|^#.*$/;

    $exclude  = qr/$exclude/;
    $prefix   = qr/$prefix/;
    $$counter = scalar(@$ref_blst);

    # Get blacklist and convert the hosts file into a dnsmasq.conf format
    # file. Be paranoid and replace every IP address with $black_hole_ip.
    # We only want the actual blacklist, so we can prepend our own hosts.
    # $black_hole_ip="0.0.0.0" saves router CPU cycles and is more efficient
    if ( !@$ref_urls == 0 ) {

        for my $url (@$ref_urls) {

            if ( $url =~ m|^http://| ) {
                $uri = new URI($url);

                my %hash = map {
                    ( my $val = lc($_) ) =~ s/$strmregex//g;
                    $val => 1;
                } qx(curl -s $url);
                my @content = keys %hash;

                for my $line (@content) {
                    print( $uri->host, $entry, $$counter, "\r" )
                        if $$mode ne "ex-cli";
                    for ($line) {
                        length($_) < 1 and last;
                        !defined($_)   and last;
                        /$exclude/     and last;
                        /$prefix/ and sendit( \blacklist, \$1 ),
                            $$counter++, last;
                    }
                }
                print( "\r", " " x length( $uri->host . $entry . $$counter ),
                    "\r" )
                    if $$mode ne "ex-cli";
            }
        }
    }
}

# main()

cmd_line;

get_blklist_cfg;

update_blacklist;

uniq($ref_blst);

write_list( \$blacklist_file, $ref_blst );

printf( "\rEntries processed %d - unique records: %d \n",
    $$counter, scalar(@$ref_blst) )
    if $ref_mode ne "ex-cli";

system("$dnsmasq force-reload") if $ref_mode ne "in-cli";

