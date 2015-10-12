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

my $version                                               = '3.2';

use File::Basename;
use Getopt::Long;
use integer;
use lib '/opt/vyatta/share/perl5/';
use POSIX qw(strftime);
use strict;
use URI;
use v5.14;
use Vyatta::Config;
use Vyatta::ConfigMgmt;
use warnings;
use XorpConfigParser;

use constant blacklist                                    => 'blacklist';
use constant url                                          => 'url';
use constant prefix                                       => 'prefix';
use constant exclude                                      => 'exclude';
use constant true                                         => 1;
use constant false                                        => 0;

my $debug_flag                                            = undef;
my $debug_log                                             = "/var/log/update-blacklists-dnsmasq.log";
my @blacklist                                             = ();
my $ref_blst                                              = \@blacklist;
my @exclusions                                            = ();
my $ref_excs                                              = \@exclusions;
my @blacklist_urls                                        = ();
my $ref_urls                                              = \@blacklist_urls;
my @blacklist_prfx                                        = ();
my $ref_prfx                                              = \@blacklist_prfx;
my $dnsmasq                                               = "/etc/init.d/dnsmasq";
my $fqdn                                                  = '(\b([a-z0-9_]+(-[a-z0-9_]+)*\.)+[a-z]{2,}\b).*$';
my $black_hole_ip;
my $ref_bhip                                              = \$black_hole_ip;
my $blacklist_file                                        = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my $i                                                     = 0;
my $counter                                               = \$i;
my $enable                                                = undef;
my $disable                                               = undef;
my $cmd                                                   = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper";
my $begin                                                 = "$cmd begin";
my $commit                                                = "$cmd commit";
my $delete                                                = "$cmd delete";
my $end                                                   = "$cmd end";
my $save                                                  = "$cmd save";
my $set                                                   = "$cmd set";
my $prog                                                  = basename($0);
my $in_cli;
my $print_ver;
my $default;
my $list;
my $line;
my $uri;
my $loghandle;
my $cfg_file;
my $ref_mode;

my @opts = (
    [ q{--cfg-file <file>  # load a configuration file}, 'cfg-file=s' => \$cfg_file ],
    [ q{--debug            # enable debug output}, 'debug' => \$debug_flag ],
    [ q{--default          # loads default values for dnsmasq.conf file},'default' => \$default ],
    [ q{--disable          # disable dnsmasq blacklists}, 'disable' => \$disable ],
    [ q{--enable           # enable dnsmasq blacklists},'enable' => \$enable ],
    [ q{--help             # show help and usage text},'help'    => sub { Usage(0) } ],
    [ q{--in-cli           # use inside a configure session for status output},'in-cli' => \$in_cli] ,
    [ q{--version          # show program version number},'version' => \$print_ver ],
);

sub Usage {
    my $exitcode = shift;

    local $, = "\n";
    print @_;
    print "Usage: $prog <options>\n";
    print 'options:',
        map( ' ' x 4 . $_->[0],
        sort { $a->[1] cmp $b->[1] } grep ( $_->[0] ne '', @opts ) ),
        "\n";

    exit $exitcode;
}

sub cmd_line {
    my $cmdmode = \$ref_mode;

    GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts ) or Usage(1);

    if ( defined($default) ) {
        $$cmdmode = "default";
    }
    elsif ( defined($in_cli) ) {
        qx(/bin/cli-shell-api inSession);
        if ( $? > 0 ) {
            print
                "You must run $0 inside of configure when '--in-cli' is specified!\n";
            exit(1);
        }
        $$cmdmode = "in-cli";
    }
    elsif ( defined($cfg_file) ) {
        $$cmdmode = "cfg-file";
        if ( !-f $cfg_file ) {
            print("$cfg_file doesn't exist!\n");
            exit(1);
        }
    }
    else {
        $$cmdmode = "ex-cli";
    }

    if ( defined($print_ver) ) {
        printf( "%s version: %s\n", $prog, $version );
        exit(0);
    }

    $debug_flag = true if defined($debug_flag);
}

sub sendit {
    my ( $listref, $lineref ) = @_;
    my ( $list, $line ) = ( $$listref, $$lineref );
    if ( defined($line) ) {
        for ($list) {
            /blacklist/ and push( @$ref_blst, "address=/$line/$$ref_bhip\n" ),
                                                            last;
            /url/       and push( @$ref_urls, $line ),      last;
            /prefix/    and push( @$ref_prfx, qq($line) ),  last;
            /exclude/   and push( @$ref_excs, $line ),      last;
        }
    }
}

sub uniq {
    my @unsorted                                          = @_;
    my @sorted                                            = ( sort keys %{ { map { $_ => 1 } @unsorted } } );
    return @sorted;
}

sub write_list($$) {
    my $fh;
    my $file                                              = $_[0];
    my @list                                              = @{ $_[1] };
    open( $fh, '>', $$file ) or die "Could not open file: '$file' $!";
    print $fh (@list);
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
        http://www.malwaredomainlist.com/hostslist/hosts.txt
        https://openphish.com/feed.txt
        https://zeustracker.abuse.ch/blocklist.php?download=compromised
        https://zeustracker.abuse.ch/blocklist.php?download=hostfile
        |
        )
    {
        sendit( \url, \$_ );
    }

# prefix strings to be removed, leaving the FQDN or hostname + trailing suffix
    for (
        qw(
        0.0.0.0
        address=/
        htt.*//
        127.0.0.1
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
        survey.112.2o7.net
        |
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

    $config->setLevel("service dns forwarding");
    $blklst_exists =
        $ref_mode eq "in-cli"
        ? $config->exists("blacklist")
        : $config->existsOrig("blacklist");

    return my $bool =
        defined($blklst_exists)
        ? true
        : false;

}

sub isscheduled {
    my $schedule_exists;

    if (isblacklist) {
        my $config                                            = new Vyatta::Config;
        $config->setLevel("system task-scheduler task");

        $schedule_exists =
            $ref_mode eq "in-cli"
            ? $config->exists("update_blacklists")
            : $config->existsOrig("update_blacklists");
    }

    return my $bool =
        defined($schedule_exists)
        ? true
        : false;
}

sub cfg_active {
    my ( @sources, @includes, @excludes );
    my $config = new Vyatta::Config;
    my $enabled;

    if (isblacklist) {
        if ( $ref_mode eq "in-cli" ) {
            $config->setLevel('service dns forwarding blacklist');
            $enabled   = $config->returnValue('enabled') // false;
            @includes  = $config->returnValues('include');
            @excludes  = $config->returnValues('exclude');
            @sources   = $config->listNodes('source');
            $$ref_bhip = $config->returnValue('blackhole') // "0.0.0.0";
        }
        else {
            $config->setLevel('service dns forwarding blacklist');
            $enabled   = $config->returnOrigValue('enabled') // false;
            @includes  = $config->returnOrigValues('include');
            @excludes  = $config->returnOrigValues('exclude');
            @sources   = $config->listOrigNodes('source');
            $$ref_bhip = $config->returnOrigValue('blackhole') // "0.0.0.0";
        }

        for ($enabled) {
            /false/ and $enabled = false;
            /true/  and $enabled = true;
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
        log_msg( "INFO",
            "service dns forwarding blacklist is not configured, exiting!\n"
        );
        print(
            "service dns forwarding blacklist is not configured, exiting!\n");
        exit(1);
    }
    return (true);
}

sub cfg_file {
    my $enabled;
    my $mode = $ref_mode; # not yet sure why $cmdmode ends up undef after this sub, so preserving it
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
                /^enabled\s+(\w)$/   and $enabled   = $1 // false;
            }
        }

        for ($enabled) {
            /false/ and $enabled = false;
            /true/  and $enabled = true;
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
                    /$rgx_url/ and sendit( \url,    \$1 ), last;
                    /$prfx_re/ and sendit( \prefix, \$1 ), last;
                }
            }
        }
    }
    else {
        log_msg( "INFO",
            "service dns forwarding blacklist isn't configured, exiting!\n"
        );
        print(
            "service dns forwarding blacklist isn't configured, exiting!\n");
        exit(1);
    }
    $ref_mode
        = $mode;   # restoring $cmdmode as this sub is clobbering it somewhere
    return true;
}

sub get_blklist_cfg {

    # Make sure localhost is in the whitelist of exclusions
    my $exclude = 'localhost';
    sendit( \exclude, \$exclude );

    for ($ref_mode) {
        m/ex-cli|in-cli/ and cfg_active, last;
        m/cfg-file/      and cfg_file,   last;
        m/default/       and cfg_none,   last;
    }
}

sub enable {

    if (not isscheduled) {
        $debug_flag = true;
        log_msg("INFO","Enabling ADBlock [system task-scheduler task update_blacklists]\n");
        my @schedule = (
            "$begin; ",
            "$set system task-scheduler task update_blacklists executable path /config/scripts/update-blacklists-dnsmasq.pl; ",
            "$set system task-scheduler task update_blacklists interval 6h; ",
            "$commit; ",
            "$end; ",
        );
        my @output = qx(@schedule 2>&1);
        say (@output);
    }
    return(true);
}

sub disable {
    if (isscheduled) {
        $debug_flag = true;
        log_msg("INFO","Enabling ADBlock [system task-scheduler task update_blacklists]\n");
        my @schedule = (
            "$begin; ",
            "$delete system task-scheduler task update_blacklists; ",
            "$commit; ",
            "$end; ",
        );
        my @output = qx(@schedule 2>&1);
        say (@output);
    }
    return(true);
}

sub log_msg ($ $) {
    my $log_type                                          = shift;
    my $message                                           = shift;
    my $date                                              = strftime "%b %e %H:%M:%S %Y", localtime;

    print $loghandle ("$date: $log_type: $message");
    print("$log_type: $message") if $debug_flag;

}

sub update_blacklist {

    my $entry                                             = " - Entries processed: ";
    my $mode                                              = \$ref_mode;
    my $exclude                                           = join( "|", uniq(@$ref_excs) );
    my $prefix                                            = join( "|", uniq(@$ref_prfx) );
    my $strmregex                                         = qr/^\s+|\s+$|^\n|^#.*$/;

    $exclude                                              = qr/$exclude/;
    $prefix                                               = qr/^($prefix|)\s*$fqdn/;
    $$counter                                             = scalar(@$ref_blst);

    if (@$ref_urls) {
        for my $url (@$ref_urls) {
            if ( $url =~ m(^http://|^https://) ) {
                $uri                                      = new URI($url);
                my $host                                  = $uri->host;
                my $seconds                               = 1;
                my $i                                     = 0;
                my $max                                   = 2;
                log_msg( "INFO",
                    "Connecting to blacklist download host: $host\n" );
                while ( $i < $max ) {
                    my @content                           = keys {
                        my %hash                          = map {
                            ( my $val                     = lc($_) ) =~ s/$strmregex//;
                            $val                          => 1;
                        } qx(curl -s $url)
                    };
                    if (@content) {
                        $i                                = $max;
                        log_msg( "INFO",
                                  "Received "
                                . scalar(@content)
                                . " records from $host\n" );
                        print( "\r", " " x qx( tput cols ), "\r" )
                            if $$mode ne "ex-cli";

                        my $records                           = 0;

                        for my $line (@content) {
                            print( $host, $entry, $records, "\r" )
                                if $$mode ne "ex-cli";
                            for ($line) {
                                !$_        and last;
                                /$exclude/ and last;
                                /$prefix/  and sendit( \blacklist, \$2 ),
                                    $$counter++, $records++, last;
                            }
                        }
                        log_msg( "INFO",
                            "Processed $records records from $host\n" );
                        print( "\n" )
                            if $$mode ne "ex-cli";
                    }
                    elsif ( not @content and $i == $max - 1 ) {
                        print( "\r", " " x qx( tput cols ), "\r" )
                            if $$mode ne "ex-cli";
                        log_msg( "ERROR",
                            "Unable to connect to blacklist download host: $host!\n"
                        );
                        print("\rError: Unable to connect to host: $host!")
                            if $$mode ne "ex-cli";
                        log_msg( "WARNING",
                            "Received 0 records from $host\n" )
                            if ( scalar(@content) < 1 );
                        last;
                    }
                    else {
                        $i++;
                        log_msg( "WARNING",
                            "Unable to connect to: $host, retry in $seconds seconds...\n"
                        );
                        print(
                            "\rWarning: Unable to connect to: $host, retry in $seconds seconds..."
                        ) if $$mode ne "ex-cli";
                        $seconds = $seconds * 2;
                        sleep $seconds;
                    }
                }
            }
        }
    }
}

# main()
open( $loghandle, ">>$debug_log" ) or $debug_flag = undef;
log_msg( "INFO", "---+++ ADBlock $version +++---\n" );

cmd_line;

get_blklist_cfg;

if ( not $enable and not $disable ) {

    update_blacklist;
    @blacklist = uniq(@blacklist);
    write_list( \$blacklist_file, \@blacklist );

    printf( "\nEntries processed %d - unique records: %d \n",
        $$counter, scalar(@$ref_blst) )
        if $ref_mode ne "ex-cli";

    log_msg( "INFO",
              "Entries processed $$counter - unique records: "
            . scalar(@$ref_blst)
            . "\n" );

    $cmd
        = $ref_mode ne "in-cli"
        ? "$dnsmasq force-reload > /dev/null 2>1&"
        : "/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding";
    system($cmd);
}
elsif ($enable) {
    if (enable) {
        log_msg( "INFO", "Enabled dnsmasq ADBlock blacklist\n" );
    }
    else {
        log_msg( "ERROR", "Unable to enable dnsmasq ADBlock blacklist!\n" );
    }
}
elsif ($disable) {
    if (disable) {
        log_msg( "INFO", "Disabled dnsmasq ADBlock blacklist\n" );
    }
    else {
        log_msg( "ERROR", "Unable to disable dnsmasq ADBlock blacklist!\n" );
    }
}

close($loghandle);
