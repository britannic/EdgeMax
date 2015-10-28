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
# Description: Script for creating dnsmasq configuration files containing zone
# (domain) and host redirects
#
# **** End License ****

my $version                    = '4.0.alpha.102715';

# use Data::Dumper;
# use Benchmark qw(cmpthese);
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

use constant true  => 1;
use constant false => 0;

my @blst_domain    = ();
my @blst_host      = ();
my @blst_zone      = ();
my @excl_host      = ();
my @excl_domain    = ();
my @excl_zone      = ();
my @prfx_host      = ();
my @prfx_zone      = ();
my @prfx_domain    = ();
my @urls_host      = ();
my @urls_zone      = ();
my @urls_domain    = ();
my %blst_host      = ();
my %blst_zone      = ();
my %blst_domain    = ();
my $debug_log      = "/var/log/update-blacklists-dnsmasq.log";
my $disable        = undef;
my $dnsmasq_svc    = "/etc/init.d/dnsmasq";
my $documentation  = undef;
my $enable         = undef;
my $prfx_host      = undef;
my $prfx_zone      = undef;
my $icnt_domain    = 0;
my $icnt_host      = 0;
my $icnt_zone      = 0;
my $progname       = basename($0);
my $recs_host      = 0;
my $recs_zone      = 0;
my $recs_domain    = 0;
my $showstats      = undef;
my $ucnt_host      = 0;
my $ucnt_zone      = 0;
my $ucnt_domain    = 0;
my %dnsmasq = (
    blip_domains   => '0.0.0.0',
    blip_globl     => '0.0.0.0',
    blip_hosts     => '0.0.0.0',
    blip_zones     => '0.0.0.0',
    blst_domains   => \%blst_domains,
    blst_hosts     => \%blst_host,
    blst_zones     => \%blst_zone,
    debug_flag     => false,
    disabled       => false,
    excl_domains   => \@excl_domain,
    excl_hosts     => \@excl_host,
    excl_zones     => \@excl_zone,
    file_domains   => '/etc/dnsmasq.d/domains.blacklist.conf',
    file_hosts     => '/etc/dnsmasq.d/host.blacklist.conf',
    file_zones     => '/etc/dnsmasq.d/zone.blacklist.conf',
    icnt_domains   => \$icnt_domain,
    icnt_hosts     => \$icnt_host,
    icnt_zones     => \$icnt_zone,
    prfx_domains   => \@prfx_domains,
    prfx_hosts     => \@prfx_host,
    prfx_hosts     => \@prfx_zone,
    recs_domains   => \$recs_domain,
    recs_hosts     => \$recs_host,
    recs_zones     => \$recs_zone,
    rslt_domains   => \@blst_domain,
    rslt_hosts     => \@blst_host,
    rslt_zones     => \@blst_zone,
    target_domains => 'address',
    target_hosts   => 'address',
    type_domains   => 'domains',
    type_hosts     => 'hosts',
    type_zones     => 'server',
    ucnt_domains   => \$ucnt_domain,
    ucnt_hosts     => \$ucnt_host,
    ucnt_zones     => \$ucnt_zone,
    urls_domains   => \@urls_domain,
    urls_hosts     => \@urls_host,
    urls_zones     => \@urls_zone,
);
my $dnsmasq = \%dnsmasq;
my ($cfg_file,   $default,   $download, $ex_cli,
    $ex_cli_dbg, $in_cli,    $line,     $list,
    $loghandle,  $print_ver, $uri
);

# CLI command set
my $cmd           = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper";
my $begin         = "$cmd begin";
my $commit        = "$cmd commit";
my $delete        = "$cmd delete";
my $end           = "$cmd end";
my $save          = "$cmd save";
my $set           = "$cmd set";
my @opts = (
    [ q{--file <file> # load a configuration file},             'file=s'     => \$cfg_file],
    [ q{--debug       # enable debug output},                   'debug'      => \$dnsmasq->{'debug_flag'}],
    [ q{--default     # use default values for dnsmasq conf},   'default'    => \$default],
    [ q{--disable     # disable dnsmasq blacklists},            'disable'    => \$disable],
    [ q{--doc         # display documentation},                 'doc'        => sub { Usage( 0, 'doc' ) }],
    [ q{--enable      # enable dnsmasq blacklists},             'enable'     => \$enable],
    [ q{--help        # show help and usage text},              'help'       => sub { Usage( 0, 'help' ) }],
    [ q{--cli         # show status in configure session},      'cli'        => \$in_cli],
    [ q{--showstats   # show status outside configure session}, 'showstats'  => \$showstats],
    [ q{--version     # show program version number},           'version'    => \$print_ver],
);

# Make sure script runs as root
sub is_sudo {
    my $euid = geteuid();
    if ( $euid ne 0 ) {
        print STDERR ("This script must be run as root, use: sudo $0.\n");
        exit(1);
    }
}

sub Usage ($ $) {
    my $exitcode = shift;
    my $help     = shift;
    local $, = "\n";

    if ( $help eq 'help' ) {
        print STDERR (@_);
        print STDERR ("Usage: $progname <options>\n");
        print STDERR (
            'options:',
            map( ' ' x 4 . $_->[0],
                sort { $a->[1] cmp $b->[1] } grep ( $_->[0] ne '', @opts ) ),
            "\n"
        );
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
        printf( "%s version: %s\n", $progname, $version );
        exit(0);
    }

    if ( defined($in_cli) ) {
        qx(/bin/cli-shell-api inSession);
        if ( $? > 0 ) {
            print
                "You must run $0 inside of configure when '--cli' is specified!\n";
            exit(1);
        }
    }
    elsif ( defined($cfg_file) and !-f $cfg_file ) {
        exit(1);
    }
    elsif ( defined($default) ) {
        $ex_cli = true unless defined($showstats);
    }
    elsif ( defined($showstats) ) {
        $ex_cli = false;
    }
    else {
        if ( $dnsmasq->{'debug_flag'} ) {
            $ex_cli_dbg = true;
        }
        else {
            $ex_cli = true;
        }
    }
}

sub cfg_default {

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
        push( @{ $dnsmasq->{'urls_hosts'} }, $_ );
    }

    # Source urls for blacklisted domains
    for (
        qw|
        http://malc0de.com/bl/domains
        |
        )
    {
        push( @{ $dnsmasq->{'urls_domains'} }, $_ );
    }

# prefix strings to be removed, leaving the fully qualified domain name
# (hostname + domain + top level domain)
    for (
        qw(
        0.0.0.0
        address=/
        htt.*//
        127.0.0.1
        )
        )
    {
        push( @{ $dnsmasq->{'prfx_hosts'} }, qq($_) );
    }

    # prefix strings to be removed, leaving the domain + TLD
    for (
        qw(
        zone
        )
        )
    {
        push( @{ $dnsmasq->{'prfx_domains'} }, qq($_) );
    }

    # Exclude our own good hosts
    for (
        qw(
        localhost
        msdn.com
        appleglobal.112.2o7.net
        cdn.visiblemeasures.com
        hb.disney.go.com
        googleadservices.com
        hulu.com
        static.chartbeat.com
        survey.112.2o7.net
        )
        )
    {
        push( @{ $dnsmasq->{'excl_hosts'} }, $_ );
    }

    # Exclude our own good domains
    for (qw(msdn.com)) {
        push( @{ $dnsmasq->{'excl_domains'} }, $_ );
    }

    # Include our own redirected hosts
    for (qw(beap.gemini.yahoo.com)) {
        ${ ${ $dnsmasq->{'blst_hosts'} }{ $_ } }= 1;
    }

    # Include our own redirected domains
    for (qw(coolwebhosts.com)) {
        ${ ${ $dnsmasq->{'blst_hosts'} }{ $_ } }= 1;
    }

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
    if (isblacklist) {
        my $config       = new Vyatta::Config;
        my ($listNodes, $returnValue, $returnValues);
        my $parse_cfg = {
            blip_hosts   => undef,
            blip_zones   => undef,
            blip_domains => undef,
            excl_hosts   => undef,
            excl_zones   => undef,
            excl_domains => undef,
            incl_hosts   => undef,
            incl_domains => undef,
            incl_zones   => undef,
            listNodes    => undef,
            returnValue  => undef,
            returnValues => undef,
            src_hosts    => undef,
            src_domains  => undef,
            src_zones    => undef,
        };

        if ( defined($in_cli) ) {
            $returnValue  = "returnValue";
            $returnValues = "returnValues";
            $listNodes    = "listNodes";
        }
        else {
            $returnValue  = "returnOrigValue";
            $returnValues = "returnOrigValues";
            $listNodes    = "listOrigNodes";
        }

        $config->setLevel('service dns forwarding blacklist');
        $dnsmasq->{'disabled'}
            = $config->$returnValue('disabled') // false;
        $dnsmasq->{'blip_globl'}
            = $config->$returnValue('blackhole-ip') // '0.0.0.0';

        $dnsmasq->{'disabled'}
            = $dnsmasq->{'disabled'} eq 'false'
            ? false
            : true;

        for my $area (qw/hosts domains zones/) {
            $config->setLevel("service dns forwarding blacklist $area");
            $dnsmasq->{"blip_$area"}
                = $config->$returnValue('dns-redirect-ip')
                // '0.0.0.0' if $area eq 'zones';
            $dnsmasq->{"blip_$area"}
                = $config->$returnValue('blackhole-ip')
                // '0.0.0.0' if $area ne 'zones';
            @{$parse_cfg->{"incl_$area"}}
                = $config->$returnValues('include');
            @{$parse_cfg->{"excl_$area"}}
                = $config->$returnValues('exclude');
            @{$parse_cfg->{"src_$area"}} = $config->$listNodes('source');

            for ( @{$parse_cfg->{"src_$area"}} ) {
                $config->setLevel(
                    "service dns forwarding blacklist $area source $_");
                push(
                    @{ $dnsmasq->{"urls_$area"} },
                    $config->$returnValue('url')
                );
                push(
                    @{ $dnsmasq->{"prfx_$area"} },
                    $config->$returnValue('prefix')
                );
            }

            for ( @{$parse_cfg->{"incl_$area"}} ) {
                ${ $dnsmasq->{"blst_$area"}{"$_"} } = 1;
            }

            for ( @{$parse_cfg->{"excl_$area"}} ) {
                push( @{ $dnsmasq->{"excl_$area"} }, $_ );
            }
        }
    }
    else {
        $dnsmasq->{'debug_flag'} = true;
        log_msg( "ERROR",
            '[service dns forwarding blacklist is not configured], exiting!\n'
        );

        exit(1);
    }
    if ( not ( @{ $dnsmasq->{'urls_domains'} } ) or not ( @{ $dnsmasq->{'urls_hosts'} } ) ) {
        print STDERR (
            "At least one domain or host source must be configured\n");
        exit(1);
    }
    return (true);
}

sub cfg_file {
    my $parse_cfg = {
        excl_hosts   => undef,
        excl_domains => undef,
        incl_hosts   => undef,
        incl_domains => undef,
        kids_hosts   => undef,
        kids_domains => undef,
        src_hosts    => undef,
        src_domains  => undef,
        type_hosts   => undef,
        type_domains => undef,
    };
    my $rgx_url = qr/^url\s+(.*)$/;
    my $prfx_re = qr/^prefix\s+["{0,1}](.*)["{0,1}].*$/;
    my $xcp     = new XorpConfigParser();
    $xcp->parse($cfg_file);
    my $blist = $xcp->get_node( [qw/service dns forwarding blacklist/] );

    if ($blist) {
        for my $area ( [qw/hosts domains zones/] ) {
            for ( my $i = 0; $i < @{ $blist->{'children'} }; $i++ ) {
                for ( $blist->{'children'}[$i]{'name'} ) {
                    /^blackhole-ip\s+(.*)$/
                        and $dnsmasq->{'blip_globl'} = $1 // "0.0.0.0";
                    /^disabled\s+(\w)$/
                        and $dnsmasq->{'disabled'} = $1 // false;
                }

            }

            $dnsmasq->{'disabled'} eq 'false'
                ? false
                : true;

            $parse_cfg->{"type_$area"}
                = $xcp->get_node(
                [qw/service dns forwarding blacklist $area/] );

            if ( $parse_cfg->{"type_$area"} ) {
                $parse_cfg->{"kids_$area"} = $parse_cfg->{"type_$area"}->{'children'};
                $parse_cfg->{"excl_$area"}
                    = $xcp->copy_multis( $parse_cfg->{"kids_$area"},
                    'exclude' );
                $parse_cfg->{"incl_$area"}
                    = $xcp->copy_multis( $parse_cfg->{"kids_$area"},
                    'include' );
                $parse_cfg->{"src_$area"}
                    = $xcp->copy_multis( $parse_cfg->{"kids_$area"},
                    'source' );

                for ( @{$parse_cfg->{"excl_$area"}} ) {
                    push( @{ $dnsmasq->{"excl_$area"} }, $_->{'name'} );
                }

                for ( @{$parse_cfg->{"incl_$area"}} ) {
                    ${ $dnsmasq->{"blst_$area"}{"$_->{'name'}"} } = 1;
                }

                for ( @{$parse_cfg->{"src_$area"}} ) {
                    my $source = $xcp->get_node(
                        [   'service',    'dns',
                            'forwarding', 'blacklist',
                            $area,        "source $_->{'name'}"
                        ]
                    );

                    $parse_cfg->{"kids_$area"} = $source->{'children'};

                    for ( @{$parse_cfg->{"kids_$area"}} ) {
                        for ( $_->{'name'} ) {
                            /$rgx_url/
                                and push( @{ $dnsmasq->{'urls_host'} }, $1 ),
                                last;
                            /$prfx_re/
                                and push( @{ $dnsmasq->{'prfx_host'} }, $1 ),
                                last;
                        }
                    }
                }
            }
        }
    }
    else {
        $dnsmasq->{'debug_flag'} = true;
        log_msg( "ERROR",
            "[service dns forwarding blacklist] isn't configured, exiting!\n"
        );
        exit(1);
    }
    return (true);
}

sub get_blklist_cfg {

    # Make sure localhost is in the whitelist of exclusions
    my $exclude = 'localhost';
    push( @{ $dnsmasq->{'excl_host'} }, $exclude );

    cfg_active    if $ex_cli or $in_cli or $ex_cli_dbg;
    cfg_file      if $cfg_file;
    cfg_default   if $default;
}

sub enable {
    my $bool = $dnsmasq->{'disabled'};
    $dnsmasq->{'debug_flag'} = true;

    if ( not $bool ) {
        log_msg( "INFO", "Enabling blacklist...\n" );
        my @command = (
            "$begin; ",
            "$set service dns forwarding blacklist disabled false; ",
            "$commit; ", "$end",
        );

        qx(@command 2>&1);
        if ( $? == 0 ) {
            $bool = true;

            isscheduled == true
                ? log_msg( "INFO", "Enabled dnsmasq blacklist\n" )
                : log_msg(
                "WARNING",
                "blacklist is enabled but has no task-scheduler entry - dnsmasq blacklists will not be dynamically updated!\n"
                );
        }
    }
    return ($bool);
}

sub disable {
    my $bool = $dnsmasq->{'disabled'};
    $dnsmasq->{'debug_flag'} = true;

    if ($bool) {

        log_msg( "INFO", "Disabling dnsmasq blacklist\n" );

        my @command = (
            "$begin; ",
            "$set service dns forwarding blacklist disabled true; ",
            "$commit; ", "$end",
        );

        qx(@command 2>&1);
        if ( $? == 0 ) {
            $bool = true;
            log_msg( "INFO", "Disabled dnsmasq blacklist\n" );
        }
    }
    else {
        log_msg( "INFO", "dnsmasq blacklist already disabled\n" );
        $bool = true;
    }
    return ($bool);
}

sub log_msg {
    my $log_type = shift;
    my $message  = shift;
    my $date     = strftime "%b %e %H:%M:%S %Y", localtime;

    return (false) unless $message;

    print $loghandle ("$date: $log_type: $message");
    print("$log_type: $message") if $dnsmasq->{'debug_flag'};
}

# sub get_tlds {
#     my $url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt';
#     my $ua = LWP::UserAgent->new;
#     $ua->agent(
#         'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56'
#     );
#     $ua->timeout(30);
#     my $get = $ua->get($url);
# }

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
        unless $ex_cli;

    $ua->show_progress(true) if $dnsmasq->{'debug_flag'};
    $get = $ua->get($url);

    my %download = map { lc($_) => 1 } split( $splitline, $get->content );

    $lines = scalar( keys %download );

    print("$lines lines retrieved\n")
        unless $ex_cli;

    log_msg( "INFO", "$lines lines downloaded from: $host\n" );

    return $get->is_success
        ? %download
        : "$url download failed";
}

sub update_blacklist {
    my @todo                    = ();
    my $ignore                  = '^#|^\n|^\s*$';
    my $cols                    = qx( tput cols );
    my $host                    = qr{(\b([a-z0-9_-]+(-[a-z0-9_]+)*\.)+[a-z]{2,}\b)};
    my $splitline               = qr{\s+\b};
    my $suffix                  = qr{(?:#.*$|\{.*$|\/.*$)};

    for my $area (qw/domains hosts/) {
        push( @todo, $area ) if scalar( @{ $dnsmasq->{"urls_$area"} } );
    }

    unless (@todo) {
        print(
            "configure: [service dns forwarding blacklist] must have at least one complete source configured under domains or hosts!\n"
        );
        exit(1);
    }

    for my $area (@todo) {
        my ($exclude, $prefix);

        ${$dnsmasq->{"icnt_$area"}} = scalar( keys %{ $dnsmasq->{"blst_$area"} } ) // 0;

        if ($area eq 'domains') {
            $exclude = join(
                '|', $ignore,
                (   sort { length($b) <=> length($a) }
                        @{ $dnsmasq->{"excl_$area"} }
                )
            ) if ( @{ $dnsmasq->{"excl_$area"} } );
            $exclude
                = defined( $exclude )
                ? qr/$exclude/
                : qr/$ignore/;
        }
        else {
            push(
                @{ $dnsmasq->{"excl_$area"} },
                keys %{ $dnsmasq->{"blst_domains"} }
            ) if ( keys %{ $dnsmasq->{"blst_domains"} } );
            $exclude = join(
                '|', $ignore,
                (   sort { length($b) <=> length($a) }
                        @{ $dnsmasq->{"excl_$area"} }
                )
            ) if ( @{ $dnsmasq->{"excl_$area"} } );
            $exclude
                = defined( $exclude )
                ? qr/$exclude/
                : qr/$ignore/;
        }

        $prefix = join(
            '|', $ignore,
            (   sort { length($b) <=> length($a) }
                    @{ $dnsmasq->{"prfx_$area"} }
            )
        ) if ( @{ $dnsmasq->{"prfx_$area"} } );

        $prefix
            = defined($prefix)
            ? qr/^$prefix\s*/
            : qr/^/;

        my @content = map $_->join, map threads->create( \&fetch_url, $_ ),
            @{ $dnsmasq->{"urls_$area"} };

        if (@content) {
            ${$dnsmasq->{"recs_$area"}} = scalar(@content) / 2;
            log_msg( "INFO",
                      "Received "
                    . ${$dnsmasq->{"recs_$area"}}
                    . " records from all sources\n" );
            print( "\r", " " x $cols, "\r" ) unless $ex_cli;

            for my $line (@content) {
                for ($line) {
                    $_ =~  s/$suffix//;
                    $_ =~  s/$prefix//;
                    next if /$exclude/;
                    if (/$splitline/) {
                        for ( split /$splitline/ ) {
                            next if /$exclude/;
                            /$host/
                                and ${ ${ $dnsmasq->{"blst_$area"} }{ $1 } }
                                = 1,
                                ${ $dnsmasq->{"icnt_$area"} }++;
                        }
                    }
                    else {
                        /$host/
                            and ${ ${ $dnsmasq->{"blst_$area"} }{ $1 } }
                            = 1,
                            ${ $dnsmasq->{"icnt_$area"} }++;
                    }
                }
                printf(
                    "Entries processed: %s %s from: %s lines\r",
                    ${ $dnsmasq->{"icnt_$area"} },
                    $dnsmasq->{"type_$area"},
                    ${ $dnsmasq->{"recs_$area"} }
                ) unless $ex_cli;
            }
        }
    }
}

sub main() {
    log_msg( "INFO", "---+++ blacklist $version +++---\n" );

    if ( not $dnsmasq->{'disabled'} and not $disable ) {
        my @todo    = ();

        update_blacklist();

#     if ( keys %{ $dnsmasq->{"blst_zone"} } ) {
#         my $rgx = join '|', keys %{ $dnsmasq->{"blst_zone"} };
#         my @matches = map {$_ => 1, $_ =~ qr/$rgx/} keys %{ $dnsmasq->{"blst_host"} };
#         delete @{ $dnsmasq->{"blst_host"} }{@matches};
#     }
        for my $area (qw/domains hosts/) {
            if (${ $dnsmasq->{"icnt_$area"} }) {
                push( @todo, $area );
                @{ $dnsmasq->{"rslt_$area"} } = ( sort keys %{ $dnsmasq->{"blst_$area"} } );
                ${ $dnsmasq->{"ucnt_$area"} } = scalar(@{ $dnsmasq->{"rslt_$area"} });
            }
        }

        die("Zero source records returned, exiting!") unless (@todo);

        for my $area (@todo) {
            open( my $fh, '>', $dnsmasq->{"file_$area"} )
                or die sprintf( "Could not open file: s% $!",
                $dnsmasq->{"file_$area"} );

            for ( @{ $dnsmasq->{"rslt_$area"} } ) {
                printf $fh (
                    "%s=/%s/%s\n", $dnsmasq->{"target_$area"},
                    $_,            $dnsmasq->{"blip_$area"}
                ) unless $area eq 'domains';
                printf $fh (
                    "%s=/.%s/%s\n", $dnsmasq->{"target_$area"},
                    $_,            $dnsmasq->{"blip_$area"}
                ) if $area eq 'domains';
            }
            close($fh);

            printf(
                "\rCompiled: %s (unique %s), %s (processed) from %s (source lines)\n",
                ${ $dnsmasq->{"ucnt_$area"} },
                   $dnsmasq->{"type_$area"},
                ${ $dnsmasq->{"icnt_$area"} },
                ${ $dnsmasq->{"recs_$area"} }
            ) unless $ex_cli;

            log_msg(
                "INFO",
                sprintf(
                    "Compiled: %s (unique %s), %s (processed) from %s (source lines)",
                    ${ $dnsmasq->{"ucnt_$area"} },
                       $dnsmasq->{"type_$area"},
                    ${ $dnsmasq->{"icnt_$area"} },
                    ${ $dnsmasq->{"recs_$area"} }
                )
            );
        }
    }
    elsif ($enable) {
        log_msg( "ERROR", "Unable to enable dnsmasq blacklist!\n" )
            unless enable;
    }
    elsif ($disable) {
        if ( disable or $dnsmasq->{'disabled'} ) {
            log_msg(
                "INFO",
                sprintf( "Removing blacklist configuration file %s\n",
                    $dnsmasq->{"file_zone"} )
            );
            unlink( $dnsmasq->{"file_host"} );
            log_msg(
                "INFO",
                sprintf( "Removing blacklist configuration file %s\n",
                    $dnsmasq->{"file_zone"} )
            );
            unlink( $dnsmasq->{"file_zone"} );
        }
        else {
            log_msg( "ERROR",
                "Unable to disable dnsmasq blacklist!\n" );
            exit(1);
        }
    }

    $cmd
        = !$in_cli
        ? "$dnsmasq_svc force-reload > /dev/null 2>1&"
        : "/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding";

#     qx($cmd);

    close($loghandle);

    exit(0);
}

############################### script runs here ###############################
is_sudo;
cmd_line;
open( $loghandle, ">>$debug_log" ) or $dnsmasq->{'debug_flag'} = undef;
get_blklist_cfg;
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
