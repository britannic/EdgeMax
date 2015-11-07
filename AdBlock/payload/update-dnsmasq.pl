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

my $version = '4.0.alpha.110715';

use Data::Dumper;

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

use constant TRUE  => 1;
use constant FALSE => 0;

my $cols            = qx( tput cols );
my $disable         = undef;
my $dnsmasq_svc     = '/etc/init.d/dnsmasq';
my $enable          = undef;
my $progname        = basename($0);
my $showstats       = undef;
my $cfg_ref         = {
    debug           => 0,
    disabled        => 0,
    domains        => {
        blackhole   => '0.0.0.0',
        blacklist   => {},
        file        => '/etc/dnsmasq.d/domain.blacklist.conf',
        icount      => 0,
        records     => 0,
        target      => 'address',
        type        => 'domains',
        unique      => 0,
    },
    hosts          => {
        blackhole   => '0.0.0.0',
        blacklist   => {},
        file        => '/etc/dnsmasq.d/host.blacklist.conf',
        icount      => 0,
        records     => 0,
        target      => 'address',
        type        => 'hosts',
        unique      => 0,
    },
    zones          => {
        blackhole   => '0.0.0.0',
        blacklist   => {},
        file        => '/etc/dnsmasq.d/zone.blacklist.conf',
        icount      => 0,
        records     => 0,
        target      => 'server',
        type        => 'zone',
        unique      => 0,
    },
    load_cfg        => {
        active      => sub { cfg_actv() },
        default     => sub { cfg_dflt() },
        file        => sub { cfg_file() },
    },
    log_file        => '/var/log/update-blacklists-dnsmasq.log',
};
my $re              = {
        fqdn        =>
        qr{(\b(?:(?![.]|-)[a-zA-Z0-9_-]{1,63}(?<!-)[.]{1})+(?:[a-zA-Z]{2,63})\b)}o,
        lspaces     => qr{^\s+}o,
        rspaces     => qr{\s+$}o,
        suffix      => qr{(?:#.*$|\{.*$|[/[].*$)}o,
    };

my ($cfg_file,  $default, $download, $line, $list, $LOGHANDLE,
    $print_ver, $show,    $loadcfg,  $uri,  $usage
);

# CLI command set
my $begin  = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin';
my $commit = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit';
my $delete = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete';
my $end    = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end';
my $save   = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save';
my $set    = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set';

my @opts = (
    [ q{--i <file>  # load a configuration file},             'i=s'       => \$cfg_file],
    [ q{--debug     # enable verbose debug output},           'debug'     => \$cfg_ref->{'debug'}],
    [ q{--default   # use default values for dnsmasq conf},   'default'   => \$default],
    [ q{--disable   # disable dnsmasq blacklists},            'disable'   => \$disable],
    [ q{--man       # display documentation},                 'man'       => sub {$usage->{'man'}->(0)}],
    [ q{--enable    # enable dnsmasq blacklists},             'enable'    => \$enable],
    [ q{--help      # show help and usage text},              'help'      => sub {$usage->{'help'}->(0)}],
    [ q{--v         # verbose (outside configure session)},   'v'         => \$show],
    [ q{--version   # show program version number},           'version'   => sub {$usage->{'version'}->(0)}],
);

$usage = {
    cfg_file => sub {
        my $exitcode = shift;
        print STDERR (
            "$cfg_file not found, check path and file name correct\n");
        exit($exitcode);
    },
    cli => sub {
        my $exitcode = shift;
        print STDERR (
            "You must run $0 inside of configure when '--cli' is specified!\n"
        );
        exit($exitcode);
    },
    enable => sub {
        my $exitcode = shift;
        print STDERR (
            "\n    ERROR: '--enable' and '--disable' are mutually exclusive options!\n\n"
        );
        $usage->{'help'}->($exitcode);
    },
    default => sub {
        my $exitcode = shift;
        print STDERR (
            "\n    ERROR: '--cfg_file' and '--default' are mutually exclusive options!\n\n"
        );
        $usage->{'help'}->($exitcode);
    },
    man => sub {
        my $exitcode = shift;
        $usage->{'help'}->( 9, 'doc' );
        while (<DATA>) {
            print STDERR;
        }
        print STDERR "\n";
        exit($exitcode);
    },
    help => sub {
        my $exitcode = shift;
        local $, = "\n";
        print STDERR (@_);
        print STDERR ("usage: $progname <options>\n");
        print STDERR (
            'options:',
            map( ' ' x 4 . $_->[0],
                sort { $a->[1] cmp $b->[1] } grep ( $_->[0] ne '', @opts ) ),
            "\n"
        );
        $exitcode == 9 ? return (1) : exit($exitcode);
    },
    sudo => sub {
        my $exitcode = shift;
        print STDERR ("This script must be run as root, use: sudo $0.\n");
        exit($exitcode);
    },
    version => sub {
        my $exitcode = shift;
        printf STDERR ( "%s version: %s\n", $progname, $version );
        exit($exitcode);
    },
};

sub is_cli () {

    qx(/bin/cli-shell-api inSession);

    return ( $? > 0 )
        ? FALSE
        : TRUE;
}

sub is_blacklist {
    my $config = new Vyatta::Config;

    $config->setLevel("service dns forwarding");
    my $blklst_exists
        = is_cli()
        ? $config->exists("blacklist")
        : $config->existsOrig("blacklist");

    return defined($blklst_exists)
        ? TRUE
        : FALSE;
}

sub is_scheduled {
    my $schedule_exists;

    if (is_blacklist) {
        my $config = new Vyatta::Config;
        $config->setLevel("system task-scheduler task");

        $schedule_exists
            = is_cli()
            ? $config->exists("blacklist")
            : $config->existsOrig("blacklist");
    }

    return my $bool
        = defined($schedule_exists)
        ? TRUE
        : FALSE;
}

sub cfg_actv {
    if (is_blacklist) {
        my $config = new Vyatta::Config;
        my ( $listNodes, $returnValue, $returnValues );

        if ( is_cli() ) {
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
        $cfg_ref->{'disabled'}
            = $config->$returnValue('disabled') // FALSE;
        $cfg_ref->{'blackhole-ip'}
            = $config->$returnValue('blackhole-ip') // '0.0.0.0';

        $cfg_ref->{'disabled'}
            = $cfg_ref->{'disabled'} eq 'false'
            ? FALSE
            : TRUE;

        for my $area (qw/hosts domains zones/) {
            $config->setLevel("service dns forwarding blacklist $area");
            $cfg_ref->{$area}->{'blackhole'}
                = $config->$returnValue('dns-redirect-ip') // '0.0.0.0'
                if $area eq 'zones';
            $cfg_ref->{$area}->{'blackhole'}
                = $config->$returnValue('blackhole-ip') // '0.0.0.0'
                if $area ne 'zones';
            $cfg_ref->{$area}->{'include'} = {
                map{ $_ => 1} $config->$returnValues('include')};
            $cfg_ref->{$area}->{'exclude'}= {
                map{ $_ => 1} $config->$returnValues('exclude')};

            for my $source ( $config->$listNodes('source') ) {
                $config->setLevel("service dns forwarding blacklist $area source $source");
                $cfg_ref->{$area}->{'src'}->{$source}->{'url'} = $config->$returnValue('url');
                $cfg_ref->{$area}->{'src'}->{$source}->{'prefix'} = $config->$returnValue('prefix');
            }
        }
    }
    else {
        $show = TRUE;
        log_msg(
            {   msg_typ => 'ERROR',
                msg_str =>
                    '[service dns forwarding blacklist is not configured], exiting!'
            }
        );

        exit(1);
    }
    if (   ( scalar( keys %{ $cfg_ref->{'domains'}->{'src'} } ) < 1 )
        && ( scalar( keys %{ $cfg_ref->{'hosts'}->{'src'} } ) < 1 ) )
    {
        say STDERR ('At least one domain or host source must be configured');
        exit(1);
    }

    return (TRUE);
}

sub cfg_dflt {

    # Sources for blacklisted hosts
    $cfg_ref->{'hosts'}->{'src'} = {
        malwaredomainlist => {
            url    => 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
            prefix => '127.0.0.1',
        },
        openphish =>
            { url => 'https://openphish.com/feed.txt', prefix => 'htt.*//', },
        someonewhocares => {
            url    => 'http://someonewhocares.org/hosts/zero/',
            prefix => '0.0.0.0',
        },
        winhelp2002 => {
            url    => 'http://winhelp2002.mvps.org/hosts.txt',
            prefix => '0.0.0.0',
        },
        yoyo => {
            url =>
                'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext',
            prefix => '',
        },
        zeustracker_compromised => {
            url =>
                'https://zeustracker.abuse.ch/blocklist.php?download=compromised',
            prefix => '',
        },
        zeustracker_hosts => {
            url =>
                'https://zeustracker.abuse.ch/blocklist.php?download=hostfile',
            prefix => '127.0.0.1',
        },
    };

    # Exclude our own good hosts
    $cfg_ref->{'hosts'}->{'exclude'} = {
        'appleglobal.112.2o7.net' => 1,
        'cdn.visiblemeasures.com' => 1,
        'googleadservices.com'    => 1,
        'hb.disney.go.com'        => 1,
        'hulu.com'                => 1,
        'msdn.com'                => 1,
        'static.chartbeat.com'    => 1,
        'survey.112.2o7.net'      => 1,
    };

    # Include our own redirected hosts
    $cfg_ref->{'hosts'}->{'include'}
        = { 'beap.gemini.yahoo.com' => 1 };

    # Sources for blacklisted domains
    $cfg_ref->{'domains'}->{'src'}
        = { malwaredomainlist =>
            { url => 'http://malc0de.com/bl/ZONES', prefix => 'zone', }, };

    # Exclude our own good domains
    $cfg_ref->{'domains'}->{'exclude'} = { 'msdn.com' => 1 };

    # Include our own redirected domains
    $cfg_ref->{'domains'}->{'include'} = { 'coolwebhosts.com' => 1 };

    return (TRUE);
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
    my $rgx_url = qr{\Aurl\s+(.*)\z}xms;
    my $prfx_re = qr{\Aprefix\s+["{0,1}](.*)["{0,1}].*\z}xms;
    my $xcp     = new XorpConfigParser();
    $xcp->parse($cfg_file);
    my $blist = $xcp->get_node( [qw/service dns forwarding blacklist/] );

    if ($blist) {
        for my $area (qw/hosts domains zones/) {
            for my $child ( @{ $blist->{'children'} } ) {
                for ( $blist->{'children'}[$child]->{'name'} ) {
                    /^blackhole-ip\s+(.*)$/
                        and $cfg_ref->{'blip_globl'} = $1
                        // "0.0.0.0";
                    /^disabled\s+(\w)$/
                        and $cfg_ref->{'disabled'} = $1 // FALSE;
                }
            }

            $cfg_ref->{'disabled'} eq 'false'
                ? FALSE
                : TRUE;

            $parse_cfg->{"type_$area"}
                = $xcp->get_node(
                [qw/service dns forwarding blacklist $area/] );

            if ( $parse_cfg->{"type_$area"} ) {
                $parse_cfg->{"kids_$area"}
                    = $parse_cfg->{"type_$area"}->{'children'};
                $parse_cfg->{$area}->{'exclude'}
                    = $xcp->copy_multis( $parse_cfg->{"kids_$area"},
                    'exclude' );
                $parse_cfg->{"incl_$area"}
                    = $xcp->copy_multis( $parse_cfg->{"kids_$area"},
                    'include' );
                $parse_cfg->{"src_$area"}
                    = $xcp->copy_multis( $parse_cfg->{"kids_$area"},
                    'source' );

                for my $exclude ( @{ $parse_cfg->{$area}->{'exclude'} } ) {
                    push(
                        $cfg_ref->{$area}->{'exclude'},
                        $exclude->{'name'}
                    );
                }

                for my $include ( @{ $parse_cfg->{"incl_$area"} } ) {
                    push(
                        $cfg_ref->{$area}->{'include'},
                        "$include->{'name'}"
                    );
                }

                for my $src_name ( @{ $parse_cfg->{"src_$area"} } ) {
                    my $source = $xcp->get_node(
                        [   'service',    'dns',
                            'forwarding', 'blacklist',
                            $area,        "source $src_name->{'name'}"
                        ]
                    );

                    $parse_cfg->{"kids_$area"} = $source->{'children'};

                    for my $src_name ( @{ $parse_cfg->{"kids_$area"} } ) {
                        for ( $src_name->{'name'} ) {
                            /$rgx_url/
                                and
                                push( $cfg_ref->{'urls_host'}, $1 ),
                                last;
                            /$prfx_re/
                                and
                                push( $cfg_ref->{'prfx_host'}, $1 ),
                                last;
                        }
                    }
                }
            }
        }
    }
    else {
        $cfg_ref->{'debug'} = TRUE;
        log_msg(
            {   msg_typ => 'ERROR',
                msg_str =>
                    q{[service dns forwarding blacklist] isn't configured, exiting!}
            }
        );
        exit(1);
    }
    return (TRUE);
}

sub enable {
    my $blacklist_enabled = $cfg_ref->{'disabled'};
    $cfg_ref->{'debug'} = TRUE;

    if ( not $blacklist_enabled ) {
        log_msg( { msg_typ => 'INFO', msg_str => 'Enabling blacklist...' } );
        my @command = (
            "$begin; ",
            "$set service dns forwarding blacklist disabled false; ",
            "$commit; $end"
        );

        qx(@command 2>&1);
        if ( $? == 0 ) {
            $blacklist_enabled = TRUE;

            is_scheduled == TRUE
                ? log_msg(
                {   msg_typ => 'INFO',
                    msg_str => 'Enabled dnsmasq blacklist\n'
                }
                )
                : log_msg(
                {   msg_typ => 'WARNING',
                    msg_str =>
                        'blacklist is enabled but has no task-scheduler entry - dnsmasq blacklists will not be dynamically updated!'
                }
                );
        }
    }
    return ($blacklist_enabled);
}

sub disable {
    my $blacklist_disabled = $cfg_ref->{'disabled'};
    $cfg_ref->{'debug'} = TRUE;

    if ($blacklist_disabled) {

        log_msg(
            { msg_typ => 'INFO', msg_str => 'Disabling dnsmasq blacklist' } );

        my @command = (
            "$begin; ",
            "$set service dns forwarding blacklist disabled true; ",
            "$commit; $end"
        );

        qx(@command 2>&1);
        if ( $? == 0 ) {
            $blacklist_disabled = TRUE;
            log_msg(
                {   msg_typ => 'INFO',
                    msg_str => 'Disabled dnsmasq blacklist'
                }
            );
        }
    }
    else {
        log_msg(
            {   msg_typ => 'INFO',
                msg_str => 'dnsmasq blacklist already disabled'
            }
        );
        $blacklist_disabled = TRUE;
    }
    return ($blacklist_disabled);
}

sub log_msg {
    my $msg_ref = shift;
    my $date = strftime "%b %e %H:%M:%S %Y", localtime;

    return (FALSE)
        unless ( length( $msg_ref->{msg_typ} . $msg_ref->{msg_str} ) > 2 );

    print {$LOGHANDLE} ("$date: $msg_ref->{msg_typ}: $msg_ref->{msg_str}");
    say("$msg_ref->{msg_typ}: $msg_ref->{msg_str}")
        if $cfg_ref->{'debug'} || $show;

    return TRUE;
}

sub fetch_url {
    my $ua = LWP::UserAgent->new;
    $ua->agent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56'
    );
    $ua->timeout(30);
    my $input     = shift;
    my $get;
    my $select    = $cfg_ref->{$input->{'area'}}->{src}->{$input->{'src'}}->{'prefix'};
    $select       = qr{$select};
    my $reject    = qr{^#|^$|^\n};
    my $lines     = 0;
    my $splitline = qr{\R|<br \/>}xms;
    my $div       = qr{\s+\b}xms;
    my $uri       = new URI( $input->{'url'} );
    my $host      = $uri->host;

    log_msg(
        {   msg_typ => 'INFO',
            msg_str => "Downloading blacklist from $host"
        }
    ) if $show;

    $ua->show_progress(TRUE) if $cfg_ref->{'debug'};
    $get = $ua->get( $input->{'url'} );

    my %download = map { my $key = $_; lc($key) => 1 } grep {/$select/} grep {!/$reject/} split( $splitline, $get->content );

    $cfg_ref->{$input->{'area'}}->{'records'} = scalar( keys %download );

    log_msg(
        {   msg_typ => 'INFO',
            msg_str => $cfg_ref->{$input->{'area'}}->{'records'}
                . " lines downloaded from: $host"
        }
    );

    return $get->is_success
        ? sort keys %download
        : undef;
}

# Make sure script runs as root
sub is_sudo {
    return (TRUE) if geteuid() == 0;
    return (FALSE);
}

############################### script runs here ###############################

# Read command line flags and exit with help message if any are unknown
GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts ) or $usage->{'help'}->( 1, 'help' );

# Find reasons to quit
$usage->{'sudo'}->(1)     if not is_sudo;
$usage->{'enable'}->(1)   if defined($enable) and defined($disable);
$usage->{'default'}->(1)  if defined($default) and defined($cfg_file);
$usage->{'cfg_file'}->(1) if defined($cfg_file) and not -f $cfg_file;

# Start logging
open( $LOGHANDLE, '>>', $cfg_ref->{'log_file'} )
    or die(q{Cannot open log file - this shouldn't happen!});
log_msg(
    {   msg_typ => 'INFO',
        msg_str =>,
        "---+++ blacklist $version +++---"
    }
);

# Make sure localhost is always in the exclusions whitelist
$cfg_ref->{'hosts'}->{'exclude'}->{'localhost'} = 1;

# Now choose which data set will define the configuration
my $cfg_type
    = defined($default)  ? 'default'
    : defined($cfg_file) ? 'file'
    :                      'active';

# Now load the appropriate data set
$cfg_ref->{load_cfg}->{$cfg_type}->();

# Now proceed if blacklist is enabled
if ( not $cfg_ref->{'disabled'} and not $disable ) {
    my (@content, @todo);

    # Add areas to process only if they contain sources
    push(@todo, 'domains') if (scalar (keys %{$cfg_ref->{'domains'}->{'src'}}) > 0);
    push(@todo, 'hosts')   if (scalar (keys %{$cfg_ref->{'hosts'  }->{'src'}}) > 0);
    for my $area (@todo) {
        my @sources = keys %{ $cfg_ref->{$area}->{'src'} };
        $cfg_ref->{$area}->{'icount'}
            = scalar( keys %{ $cfg_ref->{$area}->{'blacklist'} } )
            // 0;

        my $exclude
            = ( scalar( keys %{ $cfg_ref->{$area}->{'exclude'} } ) > 0 )
            ? join(
            '|',
            (   sort { length($b) <=> length($a) }
                    keys %{ $cfg_ref->{$area}->{'exclude'} }
            )
            )
            : '^#';

        # create asynchronous threaded fetch web content jobs collect downloaded data
        for my $source (@sources) {
            my $url = $cfg_ref->{$area}->{'src'}->{$source}->{'url'};
            my @data = map $_->join, threads->create( \&fetch_url, { area => $area, url => $url, src => $source } );
            push (@content, @data);
        }

        print( "\r", " " x $cols, "\r" ) if $show;

        if ( scalar(@content) > 0 ) {
            $cfg_ref->{$area}->{'records'} = scalar(@content);

            log_msg(
                {   msg_typ => 'INFO',
                    msg_str => "Received "
                        . $cfg_ref->{$area}->{'records'}
                        . " total records\n"
                }
            );

            LINE:
            for my $line (@content) {
                next LINE if $line eq '';
                $line =~ s/$re->{suffix}//;
                $line =~ s/$re->{lspaces}//;
                $line =~ s/$re->{rspaces}//;
                my @elements = $line =~ m/$re->{fqdn}/gc;

                if ( @elements > 0 ) {
                    map {
                        $cfg_ref->{$area}->{'blacklist'}->{$_} = 1;
                        }
                        grep { !/$exclude/ } @elements;
                    printf(
                        "Entries processed: %s %s from: %s lines\r",
                        $cfg_ref->{$area}->{'icount'}
                        += scalar(@elements),
                        $cfg_ref->{$area}->{'type'},
                        $cfg_ref->{$area}->{'records'}
                    ) if $show;
                }
            }
        }

        if ( $cfg_ref->{$area}->{'icount'} > 0 ) {
            $cfg_ref->{$area}->{'unique'}
                = scalar(
                keys %{ $cfg_ref->{$area}->{'blacklist'} } );
        open( my $FH, '>', $cfg_ref->{$area}->{'file'} )
            or die sprintf( "Could not open file: s% $!",
            $cfg_ref->{$area}->{'file'} );

        ( $area ne 'domains' )
            ? print $FH map {
            my $val = $_;
            $cfg_ref->{$area}->{'target'}, '=/', $val, '/',
                $cfg_ref->{$area}->{'blackhole'}, "\n"
            } sort keys %{ $cfg_ref->{$area}->{'blacklist'} }
            : print $FH map {
            my $val = $_;
            $cfg_ref->{$area}->{'target'}, '=/.', $val, '/',
                $cfg_ref->{$area}->{'blackhole'}, "\n"
            } sort keys %{ $cfg_ref->{$area}->{'blacklist'} };

        close( $FH );

        log_msg(
            {   msg_typ => 'INFO',
                msg_str => sprintf(
                    'Compiled: %s (unique %s), %s (processed) from %s (source lines)',
                    $cfg_ref->{$area}->{'unique'},
                    $cfg_ref->{$area}->{'type'},
                    $cfg_ref->{$area}->{'icount'},
                    $cfg_ref->{$area}->{'records'}
                )
            }
        );
        }
        else {
            # Get outta here if no records returned from any area
            log_msg(
                {   msg_typ => 'ERROR',
                    msg_str => 'Zero source records returned from $area!'
                }
                );
        }
    }
}
elsif ($enable) {
    log_msg(
        {   msg_typ => 'ERROR',
            msg_str => 'Unable to enable dnsmasq blacklist!'
        }
    ) unless enable;
}
elsif ($disable) {
    if ( disable or $cfg_ref->{'disabled'} ) {
        for my $area (qw{domains hosts _zones}) {
            if ( -f "$cfg_ref->{$area}->{file}" ) {
                log_msg(
                    {   msg_typ => 'INFO',
                        msg_str =>
                            sprintf(
                            "Removing blacklist configuration file %s
                            $cfg_ref->{$area}->{file}" )
                    }
                );
                unlink( "$cfg_ref->{$area}->{file}" );
            }
        }
    }
    else {
        log_msg(
            {   msg_typ => 'ERROR',
                msg_str => 'Unable to disable dnsmasq blacklist!'
            }
        );
        exit(1);
    }
}

my $cmd
    = is_cli()
    ? '/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding'
    : "$dnsmasq_svc force-reload > /dev/null 2>1&";

qx($cmd);

# Close the log
close($LOGHANDLE);

# Exit normally
exit(0);

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
        to run "/config/scripts/update-dnsmasq.pl" at 6 hourly intervals

Removal
    * sudo bash ./install_adblock.v4.0rc1
    * select option #2

License
    * GNU General Public License, version 3
    * GNU Lesser General Public License, version 3

Author
    * Neil Beadle - https://github.com/britannic/EdgeMax/tree/master/AdBlock
