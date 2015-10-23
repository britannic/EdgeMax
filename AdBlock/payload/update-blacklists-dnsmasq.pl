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

my $version                    = '3.22rc2';

# use Data::Dumper;
use File::Basename;
use Getopt::Long;
use integer;
use lib '/opt/vyatta/share/perl5/';
use LWP::UserAgent;
use POSIX qw(geteuid strftime);
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

my %blacklist                  = ();
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
my $fqdn                       = qr/(\b([a-z0-9_-]+(-[a-z0-9_]+)*\.)+[a-z]{2,}\b).*$/;
my $i                          = 0;
my $records                    = 0;
my $prog                       = basename($0);

my ($cfg_file, $default,   $download,  $ex_cli,    $ex_cli_dbg,
    $in_cli,   $line,      $list,      $loghandle, $print_ver,
    $uri
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
    [ q{--cfg-file <file> # load a configuration file},           'cfg-file=s' => \$cfg_file],
    [ q{--debug           # enable debug output},                 'debug'      => \$debug_flag],
    [ q{--default         # use default values for dnsmasq conf}, 'default'    => \$default],
    [ q{--disable         # disable dnsmasq blacklists},          'disable'    => \$disable],
    [ q{--doc             # display documentation},               'doc'        => sub { Usage( 0, 'doc' ) }],
    [ q{--enable          # enable dnsmasq blacklists},           'enable'     => \$enable],
    [ q{--help            # show help and usage text},            'help'       => sub { Usage( 0, 'help' ) }],
    [ q{--in-cli          # show status in configure session},    'in-cli'     => \$in_cli],
    [ q{--version         # show program version number},         'version'    => \$print_ver],
);

# Make sure script runs as root
sub is_sudo {
    my $euid = geteuid();
    if ( $euid ne 0 ) {
        print STDERR ( "This script must be run as root, use: sudo $0.\n");
        exit(1);
    }
}

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
    $ex_cli = false;

    GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts ) or Usage( 1, 'help' );

    print STDERR (
        "\n    '--enable' and '--disable' are mutually exclusive options!\n\n"
        )
        and Usage( 1, 'help' )
        if defined($enable)
        and defined($disable);

    if ( defined($print_ver) ) {
        printf( "%s version: %s\n", $prog, $version );
        exit(0);
    }

    if ( defined($in_cli) ) {
        qx(/bin/cli-shell-api inSession);
        if ( $? > 0 ) {
            print
                "You must run $0 inside of configure when '--in-cli' is specified!\n";
            exit(1);
        }
    }
    elsif ( defined($cfg_file) and !-f $cfg_file ) {
        exit(1);
    }
    elsif ( defined($default) ) {
        $ex_cli = false;
    }
    else {
        if ( defined($debug_flag) ) {
            $ex_cli_dbg = true;
        }
        else {
            $ex_cli = true;
        }
    }
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
    ${\${blacklist}{"address=/$include/${\$black_hole_ip}\n"}} = 1;
    return (true);
}

sub isblacklist {
    my $config = new Vyatta::Config;

    $config->setLevel("service dns forwarding");
    my $blklst_exists
        = defined($in_cli)
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
            = defined($in_cli)
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
        if ( defined($in_cli) ) {
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
            ${\${blacklist}{"address=/$_/${\$black_hole_ip}\n"}} = 1;
        }

        for (@excludes) {
            push( @{ \@exclusions }, $_ );
        }

        for (@sources) {
            $config->setLevel("service dns forwarding blacklist source $_");
            if ( defined($in_cli) ) {
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
            ${\${blacklist}{"address=/$multiBlacklistInclude->{'name'}/${\$black_hole_ip}\n"}} = 1;
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

    cfg_active if $ex_cli or $in_cli or $ex_cli_dbg;
    cfg_file   if $cfg_file;
    cfg_none   if $default;
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

    return (false) unless $message;

    print $loghandle ("$date: $log_type: $message");
    print("$log_type: $message") if ${ \$debug_flag };
}

sub fetch_url {
    my $ua = LWP::UserAgent->new;
    $ua->agent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56'
    );
    $ua->timeout(30);
    my $get;
    my $lines     = 0;
    my $splitline = qr/\R|<br \/>/;
    my $url       = shift;
    my $uri       = new URI($url);
    my $host      = $uri->host;

    print("Downloading blacklist from $host: ")
        unless $ex_cli == true;

    $ua->show_progress(true) if ${ \$debug_flag };
    $get = $ua->get($url);

    my %download = map { lc($_) => 1 } split( $splitline, $get->content );

    $lines = scalar( keys %download );

    print("$lines lines retrieved\n")
        unless $ex_cli == true;

    log_msg( "INFO", "$lines lines downloaded from: $host\n" );

    return $get->is_success
        ? %download
        : "$url download failed";
}

sub update_blacklist {
    my $exclude                   = join( "|",
        ( sort keys %{ { map { $_ => 1 } @{ \@exclusions } } } ) );
    my $prefix                    = join( "|",
        ( sort keys %{ { map { $_ => 1 } @{ \@blacklist_prfx } } } ) );
    my $cols                      = qx( tput cols );
    my $splitline                 = qr/\s+\b/;
    my $strmregex                 = qr/(?:^#|^\n|^\s*$|^\{)/;
    $exclude                      = qr/^(?:$prefix|)\s*$exclude/;
    $prefix                       = qr/^(?:$prefix|)\s*$fqdn/;
    $fqdn                         = qr/$fqdn/;
    ${ \$i }                      = scalar( keys \%blacklist );

    my @content                   = map $_->join, map threads->create( \&fetch_url, $_ ),
        @blacklist_urls;

    ${ \$records }                = scalar(@content) / 2;

    if (@content) {
        log_msg( "INFO",
            "Received " . ${ \$records } . " records from all sources\n" );
        print( "\r", " " x $cols, "\r" ) unless $ex_cli == true;

        for my $line (@content) {
            for ($line) {
                next if /$strmregex/;
                if (/$splitline/) {
                    for ( split /$splitline/ ) {
                        next if /$strmregex/;
                        next if /$exclude/;
                        /$fqdn/
                            and ${ \${blacklist}
                                {"address=/$1/${\$black_hole_ip}\n"} } = 1,
                            ${ \$i }++;
                    }
                }
                next if /$exclude/;
                /$prefix/
                    and ${ \${blacklist}{"address=/$1/${\$black_hole_ip}\n"} }
                    = 1,
                    ${ \$i }++;
            }
            print(
                "Entries processed: ",
                ${ \$i },
                " host names from: ",
                ${ \$records },
                " lines\r"
            ) unless $ex_cli == true;
        }
        return ( sort keys %{ \%blacklist } );
    }
}

sub main() {
    open( $loghandle, ">>$debug_log" ) or $debug_flag = undef;
    log_msg( "INFO", "---+++ ADBlock $version +++---\n" );

    cmd_line;
    get_blklist_cfg;

    if ( $enabled and not $disable ) {

        my @blacklist = &update_blacklist;

        my $u         = scalar( @blacklist );

        open( my $fh, '>', $blacklist_file )
            or die "Could not open file: '$blacklist_file' $!";
        print $fh ( @blacklist );
        close($fh);

        printf(
            "\rProcessed: $u (unique), $i (processed) from $records (source lines)\n"
        ) unless $ex_cli == true;

        log_msg( "INFO",
            "Processed: $u (unique), $i (processed) from $records (source lines)\n"
        );
    }
    elsif ($enable) {
        log_msg( "ERROR", "Unable to enable dnsmasq ADBlock blacklist!\n" )
            unless enable;
    }
    elsif ($disable) {
        if (disable) {
            log_msg( "INFO",
                "Removing blacklist configuration file $blacklist_file\n" );
            unlink($blacklist_file);
        }
        else {
            log_msg( "ERROR",
                "Unable to disable dnsmasq ADBlock blacklist!\n" );
            exit(1);
        }
    }
    elsif ( not $enabled ) {
        log_msg( "INFO",
            "Removing blacklist configuration file $blacklist_file\n" );
        unlink($blacklist_file);
    }

    $cmd
        = ! $in_cli
        ? "$dnsmasq force-reload > /dev/null 2>1&"
        : "/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding";

    qx($cmd);

    close($loghandle);

    exit(0);
}

############################### script runs here ###############################
is_sudo;
main;
################################################################################

__DATA__

UBNT EdgeMax Blacklist and Ad Server Blocking

EdgeMax Blacklist and Ad Server Blocking is derived from the received wisdom
    found at (https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)
    * Generates a dnsmasq configuration file
    * Integrated with the EdgeMax OS CLI
    * Uses any FQDN in a user specified downloadable blacklist

Compatibility
    * update-blacklists-dnsmasq.pl has been tested on the EdgeRouter Lite
        family of routers, version v1.6.0-v1.7.0.
    * Since the EdgeOS is a fork and port of Vyatta 6.3, this script could
        easily be adapted for work on VyOS and Vyatta derived ports.

Installation
    * upload install_adblock.<version>.tgz to your router
        (e.g. scp /install_adblock.<version>.tgz @:/tmp/install_adblock.<version>.tgz
    * on your router: cd /tmp; sudo tar zxvf /tmp/install_adblock.<version>.tgz
    * sudo bash /tmp/install_adblock.<version>
    * select option #1
    * The script has a menu to either add or remove (if previously installed)
        AdBlock. It will set up the system task scheduler (cron) via the CLI
        to run "/config/scripts/update-blacklists-dnsmasq.pl" at 6 hourly intervals

Removal
    * sudo bash ./install_adblock.v3.22rc1
    * select option #2

License
    * GNU General Public License, version 3
    * GNU Lesser General Public License, version 3

Author
    * Neil Beadle - https://github.com/britannic/EdgeMax/tree/master/AdBlock
