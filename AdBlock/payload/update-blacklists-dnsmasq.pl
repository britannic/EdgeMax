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
BEGIN { $Pod::Usage::Formatter = 'Pod::Text::Termcap'; }

my $version                    = '3.21';

# use Data::Dumper;
use File::Basename;
use Getopt::Long;
use integer;
use lib '/opt/vyatta/share/perl5/';
use LWP::UserAgent;
use POSIX qw(strftime);
use strict;
use threads;
use URI;
use v5.14;
use Vyatta::Config;
use Vyatta::ConfigMgmt;
use warnings;
use XorpConfigParser;

use constant true              => 1;
use constant false             => 0;

my @blacklist                  = ();
my @blacklist_prfx             = ();
my @blacklist_urls             = ();
my @exclusions                 = ();
my $black_hole_ip              = '0.0.0.0';
my $blacklist_file             = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my $debug_flag                 = undef;
my $debug_log                  = "/var/log/update-blacklists-dnsmasq.log";
my $disable                    = undef;
my $dnsmasq                    = "/etc/init.d/dnsmasq";
my $documentation              = undef;
my $enable                     = undef;
my $enabled                    = true;
my $fqdn                       = '(\b([a-z0-9_]+(-[a-z0-9_]+)*\.)+[a-z]{2,}\b).*$';
my ($i, $records)              = 0;
my $prog                       = basename($0);

my ($cfg_file, $default,   $download,  $in_cli,   $line,
    $list,     $loghandle, $print_ver, $opmode,   $uri
);

# CLI command set
my $cmd                        = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper";
my $begin                      = "$cmd begin";
my $commit                     = "$cmd commit";
my $delete                     = "$cmd delete";
my $end                        = "$cmd end";
my $save                       = "$cmd save";
my $set                        = "$cmd set";


my @opts = (
    [   q{--cfg-file <file>  # load a configuration file},
           'cfg-file=s'      => \$cfg_file
    ],
    [   q{--debug            # enable debug output},
           'debug'           => \$debug_flag
    ],
    [   q{--default          # loads default values for dnsmasq.conf file},
           'default'         => \$default
    ],
    [   q{--disable          # disable dnsmasq blacklists},
           'disable'         => \$disable
    ],
    [   q{--doc              # display documentation},
           'doc'             => sub { Usage( 0, 'doc' ) }
    ],
    [   q{--enable           # enable dnsmasq blacklists},
           'enable'          => \$enable
    ],
    [   q{--help             # show help and usage text},
           'help'            => sub { Usage( 0, 'help' ) }
    ],
    [   q{--in-cli           # use inside a configure session for status output},
           'in-cli'          => \$in_cli
    ],
    [   q{--version          # show program version number},
           'version'         => \$print_ver
    ],
);


sub Usage ($ $) {
    my $exitcode = shift;
    my $help     = shift;
    local $,     = "\n";

    if ($help eq 'help') {
        print STDERR (@_);
        print STDERR ("Usage: $prog <options>\n");
        print STDERR ('options:',
            map( ' ' x 4 . $_->[0],
            sort { $a->[1] cmp $b->[1] } grep ( $_->[0] ne '', @opts ) ),
            "\n");
    }
    else {
        while (<DATA>) {
            print STDERR ();
        }
        print STDERR ("\n");
    }
    exit $exitcode;
}

sub cmd_line {
    GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts ) or Usage(1, 'help');

    print STDERR ("\n    '--enable' and '--disable' are mutually exclusive options!\n\n")
        and Usage( 1, 'help' )
        if defined($enable)
        and defined($disable);

    if ( defined($default) ) {
        ${\$opmode} = "default";
    }
    elsif ( defined($in_cli) ) {
        qx(/bin/cli-shell-api inSession);
        if ( $? > 0 ) {
            print
                "You must run $0 inside of configure when '--in-cli' is specified!\n";
            exit(1);
        }
        ${\$opmode} = "in-cli";
    }
    elsif ( defined($cfg_file) ) {
        ${\$opmode} = "cfg-file";
        if ( !-f $cfg_file ) {
            print("$cfg_file doesn't exist!\n");
            exit(1);
        }
    }
    else {
        ${\$opmode} = "ex-cli";
    }

    if ( defined($print_ver) ) {
        printf( "%s version: %s\n", $prog, $version );
        exit(0);
    }

    ${\$debug_flag} = true if defined(${\$debug_flag});
}

sub cfg_none {
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
        push( @{ \@blacklist_urls }, $_ );
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
        push( @{ \@blacklist_prfx }, qq($_) );
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
        push( @{ \@exclusions }, $_ );
    }

    # Include our own bad hosts
    my $include = "beap.gemini.yahoo.com";

    push( @{ \@blacklist }, "address=/$include/${\$black_hole_ip}\n" );
    return 1;
}

sub isblacklist {
    my $config = new Vyatta::Config;

    $config->setLevel("service dns forwarding");
    my $blklst_exists
        = ${ \$opmode } eq "in-cli"
        ? $config->exists("blacklist")
        : $config->existsOrig("blacklist");

    return defined($blklst_exists)
        ? true
        : false;
}

sub isscheduled {
    my $schedule_exists;

    if (isblacklist) {
        my $config = new Vyatta::Config;
        $config->setLevel("system task-scheduler task");

        $schedule_exists
            = ${ \$opmode } eq "in-cli"
            ? $config->exists("update_blacklists")
            : $config->existsOrig("update_blacklists");
    }

    return my $bool
        = defined($schedule_exists)
        ? true
        : false;
}

sub cfg_active {
    my ( @sources, @includes, @excludes );
    my $config = new Vyatta::Config;

    if (isblacklist) {
        if ( ${ \$opmode } eq "in-cli" ) {
            $config->setLevel('service dns forwarding blacklist');
            ${ \$enabled } = $config->returnValue('enabled') // false;
            @includes = $config->returnValues('include');
            @excludes = $config->returnValues('exclude');
            @sources  = $config->listNodes('source');
            ${ \$black_hole_ip } = $config->returnValue('blackhole')
                // "0.0.0.0";
        }
        else {
            $config->setLevel('service dns forwarding blacklist');
            ${ \$enabled } = $config->returnOrigValue('enabled') // false;
            @includes = $config->returnOrigValues('include');
            @excludes = $config->returnOrigValues('exclude');
            @sources  = $config->listOrigNodes('source');
            ${ \$black_hole_ip } = $config->returnOrigValue('blackhole')
                // "0.0.0.0";
        }

        for ( ${ \$enabled } ) {
            /false/ and ${ \$enabled } = false;
            /true/  and ${ \$enabled } = true;
        }

        for (@includes) {
            push( @{ \@blacklist }, "address=/$_/${\$black_hole_ip}\n" );
        }

        for (@excludes) {
            push( @{ \@exclusions }, $_ );
        }

        for (@sources) {
            $config->setLevel("service dns forwarding blacklist source $_");
            if ( ${ \$opmode } eq "in-cli" ) {
                push( @{ \@blacklist_urls }, $config->returnValue('url') );
                push( @{ \@blacklist_prfx }, $config->returnValue('prefix') );
            }
            else {
                push( @{ \@blacklist_urls },
                    $config->returnOrigValue('url') );
                push(
                    @{ \@blacklist_prfx },
                    $config->returnOrigValue('prefix')
                );
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
                /^blackhole\s+(.*)$/
                    and ${ \$black_hole_ip } = $1 // "0.0.0.0";
                /^enabled\s+(\w)$/ and ${ \$enabled } = $1 // false;
            }
        }

        for ( ${ \$enabled } ) {
            /false/ and ${ \$enabled } = false;
            /true/  and ${ \$enabled } = true;
        }

        for my $multiBlacklistExclude (@excludes) {
            push( @{ \@exclusions }, $multiBlacklistExclude->{'name'} );
        }

        for my $multiBlacklistInclude (@includes) {
            push(
                @{ \@blacklist },
                "address=/$multiBlacklistInclude->{'name'}/${\$black_hole_ip}\n"
            );
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
                    /$rgx_url/ and push( @{ \@blacklist_urls }, $1 ), last;
                    /$prfx_re/ and push( @{ \@blacklist_prfx }, $1 ), last;
                }
            }
        }
    }
    else {
        ${ \$debug_flag } = true;
        log_msg( "ERROR",
            "ADBlock [service dns forwarding blacklist] isn't configured, exiting!\n"
        );
        exit(1);
    }
    return (true);
}

sub get_blklist_cfg {

    # Make sure localhost is in the whitelist of exclusions
    my $exclude = 'localhost';
    push( @{ \@exclusions }, $exclude );
    for ( ${ \$opmode } ) {
        m/ex-cli|in-cli/ and cfg_active, last;
        m/cfg-file/      and cfg_file,   last;
        m/default/       and cfg_none,   last;
    }
}

sub enable {
    my $bool          = ${ \$enabled };
    ${ \$debug_flag } = true;

    if ( not $bool ) {
        log_msg( "INFO", "Enabling ADBlock...\n" );
        my @command = (
            "$begin; ",
            "$set service dns forwarding blacklist enabled true; ",
            "$commit; ", "$end",
        );

        qx(@command 2>&1);
        if ( $? == 0 ) {
            $bool = true;

        isscheduled == true
            ? log_msg( "INFO", "Enabled dnsmasq ADBlock blacklist\n" )
            : log_msg( "WARNING",
                    "ADBlock blacklist is enabled but has no task-scheduler entry - dnsmasq blacklists will not be dynamically updated!\n"
                );
        }
    }
    return ($bool);
}

sub disable {
    my $bool          = ${ \$enabled };
    ${ \$debug_flag } = true;

    if ( $bool ) {

        log_msg( "INFO", "Disabling ADBlock\n" );

        my @command = (
            "$begin; ",
            "$set service dns forwarding blacklist enabled false; ",
            "$commit; ", "$end",
        );

        qx(@command 2>&1);
        if ( $? == 0 ) {
            $bool = true;
            log_msg( "INFO", "Disabled dnsmasq ADBlock blacklist\n" );
        }
    }
    else {
        log_msg( "INFO", "ADBlock already disabled\n" );
        $bool = true;
    }
    return ($bool);
}

sub log_msg ($ $) {
    my $log_type = shift;
    my $message  = shift;
    my $date     = strftime "%b %e %H:%M:%S %Y", localtime;

    return (false) if not $message;

    print $loghandle ("$date: $log_type: $message");
    print("$log_type: $message") if ${ \$debug_flag };
}

sub fetch_url {
    my $get;
    my $lines     = 0;
    my $secs      = 30;
    my $strmregex = qr/^\s+|\s+$|^\n|^#.*$/;
    my $ua        = LWP::UserAgent->new;
    my $url       = shift;
    my $uri       = new URI($url);
    my $host      = $uri->host;

    $ua->timeout($secs);

    print("Downloading blacklist from $host: ")
        if not ${ \$debug_flag }
        or ${ \$opmode } ne "ex-cli" or ${ \$enable };

    $ua->show_progress(true) if ${ \$debug_flag };

    $get = $ua->get($url);

    my @download = keys {
        my %hash = map {
            ( my $val = lc($_) ) =~ s/$strmregex//;
            $val => 1;
        } split( qr/\R/, $get->content )
    };

    $lines = scalar(@download);

    print("$lines lines retrieved\n")
        if not ${ \$debug_flag }
        or ${ \$opmode } ne "ex-cli";
    log_msg( "INFO", "$lines lines downloaded from: $host\n" );

    return $get->is_success
        ? @download
        : "$url download failed";
}

sub update_blacklist {
    my $exclude = join( "|",
        ( sort keys %{ { map { $_ => 1 } @{ \@exclusions } } } ) );
    my $prefix = join( "|",
        ( sort keys %{ { map { $_ => 1 } @{ \@blacklist_prfx } } } ) );
    my $cols = qx( tput cols );

    $exclude = qr/^($prefix|)\s*$exclude/;
    $prefix  = qr/^($prefix|)\s*$fqdn/;
    ${ \$i } = scalar( @{ \@blacklist } );

    my @content = map $_->join, map threads->create( \&fetch_url, $_ ),
        @blacklist_urls;

    if (@content) {
        log_msg( "INFO",
            "Received " . scalar(@content) . " records from all sources\n" );
        print( "\r", " " x $cols, "\r" ) if ${ \$opmode } ne "ex-cli";

        for my $line (@content) {
            for ($line) {
                /$exclude/ and last;
                /$prefix/  and push(
                    @{ \@blacklist },
                    "address=/$2/${\$black_hole_ip}\n"
                    ),
                    ${ \$i }++, last;
            }
            ${ \$records }++;
            print( "Entries processed: ",
                ${ \$i }, "host names from: ", ${ \$records }, " lines\r" )
                if ${ \$opmode } ne "ex-cli";
        }
        @{ \@blacklist }
            = ( sort keys %{ { map { $_ => 1 } @{ \@blacklist } } } );
        return (true);
    }
}

# main()
open( $loghandle, ">>$debug_log" ) or $debug_flag = undef;
log_msg( "INFO", "---+++ ADBlock $version +++---\n" );

cmd_line;
get_blklist_cfg;

if ( $enabled and not $disable ) {

    update_blacklist;

    my $u = scalar( @{ \@blacklist } );

    open( my $fh, '>', $blacklist_file )
        or die "Could not open file: '$blacklist_file' $!";
    print $fh ( @{ \@blacklist } );
    close($fh);

    printf(
        "\rProcessed: $u (unique), $i (processed) from $records (source lines)\n"
    ) if $opmode ne "ex-cli";

    log_msg( "INFO", "Processed: $u (unique), $i (processed) from $records (source lines)\n" );
}
elsif ($enable) {
    log_msg( "ERROR", "Unable to enable dnsmasq ADBlock blacklist!\n" )
        if not enable;
}
elsif ($disable) {
    if (disable) {
        log_msg( "INFO",
            "Removing blacklist configuration file $blacklist_file\n" );
        unlink($blacklist_file);
    }
    else {
        log_msg( "ERROR", "Unable to disable dnsmasq ADBlock blacklist!\n" );
        exit(1);
    }
}
elsif ( not $enabled ) {
    log_msg( "INFO",
        "Removing blacklist configuration file $blacklist_file\n" );
    unlink($blacklist_file);
}

$cmd
    = $opmode ne "in-cli"
    ? "$dnsmasq force-reload > /dev/null 2>1&"
    : "/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding";

qx($cmd);

close($loghandle);

__DATA__

UBNT EdgeMax Blacklist and Ad Server Blocking

EdgeMax Blacklist and Ad Server Blocking is derived from the received wisdom
    found at (https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)
    * Generates a dnsmasq configuration file
    * Integrated with the EdgeMax OS CLI
    * Uses any fqdn in a downloadable user specified blacklist

Compatibility
    * update-blacklists-dnsmasq.pl has been tested on the EdgeRouter Lite
        family of routers, version v1.6.0-v1.7.0.
    * Since the EdgeOS is a fork and port of Vyatta 6.3, this script could
        easily be adapted for work on VyOS and Vyatta derived ports.

Installation
    * upload install_adblock.tgz to your router
        (e.g. scp /ersetup.tgz @:/tmp/install_adblock.tgz
    * on your router: cd /tmp; sudo tar zxvf /tmp/install_adblock.tgz
    * sudo bash /tmp/install_adblock
    * The script has a menu to either add or remove (if previously installed)
        AdBlock. It will set up the system task scheduler (cron) via the CLI
        to run "/config/scripts/update-blacklists-dnsmasq.pl" at midnight
        local time.

License
    * GNU General Public License, version 3
    * GNU Lesser General Public License, version 3

Author
    * Neil Beadle - https://github.com/britannic/EdgeMax/tree/master/AdBlock
