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

my $version = '4.0.alpha.111615';

use threads;
use strict;

# use Benchmark qw(cmpthese);

use English qw( -no_match_vars );
use feature qw/switch/;
use File::Basename;
use Getopt::Long;
use integer;
use lib '/opt/vyatta/share/perl5/';
use LWP::UserAgent;
use POSIX qw(geteuid strftime);
use URI;
use v5.14;
use Vyatta::Config;
use warnings;
# no warnings 'experimental::smartmatch';

use constant TRUE  => 1;
use constant FALSE => 0;

my $cols            = qx( tput cols );
my $disable         = undef;
my $dnsmasq_svc     = '/etc/init.d/dnsmasq';
my $enable          = undef;
my $progname        = basename($0);
my $showstats       = undef;
my $cfg_ref = {
        debug           => 0,
        disabled        => 0,
        domains         => {
        dns_redirect_ip => '0.0.0.0',
        blacklist       => {},
        file            => '/etc/dnsmasq.d/domain.blacklist.conf',
        icount          => 0,
        records         => 0,
        target          => 'address',
        type            => 'domains',
        unique          => 0,
        },
        hosts => {
        dns_redirect_ip => '0.0.0.0',
        blacklist       => {},
        file            => '/etc/dnsmasq.d/host.blacklist.conf',
        icount          => 0,
        records         => 0,
        target          => 'address',
        type            => 'hosts',
        unique          => 0,
        },
        zones => {
        dns_redirect_ip => '0.0.0.0',
        blacklist       => {},
        file            => '/etc/dnsmasq.d/zone.blacklist.conf',
        icount          => 0,
        records         => 0,
        target          => 'server',
        type            => 'zones',
        unique          => 0,
        },
        log_file => '/var/log/update-dnsmasq.log',
};

my ( $cfg_file, $default, $LH, $show, );

# CLI command set
my $begin  = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin';
my $commit = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit';
my $delete = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete';
my $end    = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end';
my $save   = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save';
my $set    = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set';

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
        $cfg_ref->{'disabled'} = $config->$returnValue('disabled') // FALSE;
        $cfg_ref->{'dns_redirect_ip'}
            = $config->$returnValue('dns-redirect-ip') // '0.0.0.0';

        $cfg_ref->{'disabled'}
            = $cfg_ref->{'disabled'} eq 'false'
            ? FALSE
            : TRUE;

        for my $area (qw/hosts domains zones/) {
            $config->setLevel("service dns forwarding blacklist $area");
            $cfg_ref->{$area}->{'blackhole'}
                = $config->$returnValue('dns-redirect-ip') // '0.0.0.0';
            $cfg_ref->{$area}->{'blacklist'} = {
                map {
                    my $element = $_;
                    my @domain = split( /[.]/, $element );
                    shift(@domain) if scalar(@domain) > 2;
                    my $value = join( '.', @domain );
                    $element => $value
                } $config->$returnValues('include')
            };
            $cfg_ref->{$area}->{'exclude'} = {
                map {
                    my $element = $_;
                    my @domain = split( /[.]/, $element );
                    shift(@domain) if scalar(@domain) > 2;
                    my $value = join( '.', @domain );
                    $element => $value
                } $config->$returnValues('exclude')
            };

            for my $source ( $config->$listNodes('source') ) {
                $config->setLevel(
                    "service dns forwarding blacklist $area source $source");
                $cfg_ref->{$area}->{'src'}->{$source}->{'url'}
                    = $config->$returnValue('url');
                $cfg_ref->{$area}->{'src'}->{$source}->{'prefix'}
                    = $config->$returnValue('prefix');
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

        return (FALSE);
    }
    if (   ( ! scalar( keys %{ $cfg_ref->{'domains'}->{'src'} } ) )
        && ( ! scalar( keys %{ $cfg_ref->{'hosts'  }->{'src'} } ) )
        && ( ! scalar( keys %{ $cfg_ref->{'zones'  }->{'src'} } ) )
        )
    {
        say STDERR ('At least one domain or host source must be configured');
        return (FALSE);
    }

    return (TRUE);
}

sub cfg_dflt {

    # Sources for blacklisted hosts
    $cfg_ref->{'hosts'}->{'src'} = {
        malwarehostlist => {
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
        'appleglobal.112.2o7.net' => 'appleglobal.112.2o7.net',
        'cdn.visiblemeasures.com' => 'cdn.visiblemeasures.com',
        'googleadservices.com'    => 'googleadservices.com',
        'hb.disney.go.com'        => 'hb.disney.go.com',
        'hulu.com'                => 'hulu.com',
        'msdn.com'                => 'msdn.com',
        'static.chartbeat.com'    => 'static.chartbeat.com',
        'survey.112.2o7.net'      => 'survey.112.2o7.net'
    };

    # Include our own redirected hosts
    $cfg_ref->{'hosts'}->{'blacklist'} = {
        'beap.gemini.yahoo.com' => 'gemini.yahoo.com',
        '.kiosked.com'          => '.kiosked.com'
    };

    # Sources for blacklisted domains
    $cfg_ref->{'domains'}->{'src'} = {
        malwaredomainlist =>
            { url => 'http://malc0de.com/bl/ZONES', prefix => 'zone' }
    };

    # Exclude our own good domains
    $cfg_ref->{'domains'}->{'exclude'} = {
        'msdn.com' => 'msdn.com'
    };

    # Include our own redirected domains
    $cfg_ref->{'domains'}->{'blacklist'} = {
        'coolwebhosts.com' => 'coolwebhosts.com',
        'centade.com'      => 'centade.com',
        'kiosked.com'      => 'kiosked.com'
    };

    return (TRUE);
}

sub get_hash {
    my $input    = shift;
    my $hash     = \$input->{'hash_ref'};
    my @nodes    = @{ $input->{'nodes'} };
    my $value    = pop(@nodes);
    my $hash_ref = $$hash;

    for my $key (@nodes) {
        $hash = \$$hash->{$key};
    }

    $$hash = $value if $value;

    return $hash_ref;
}

sub parse_node {
    my $input   = shift;
    my ( @hasher, @nodes );
    my $cfg_ref = {};
    my $leaf    = 0;
    my $level   = 0;
    my $re      = {
        BRKT => qr/[}]/o,
        CMNT => qr/^(?<LCMT>[\/*]+).*(?<RCMT>[*\/]+)$/o,
        DESC => qr/^(?<NAME>[\w-]+)\s"?(?<DESC>[^"]+)?"?$/o,
        MPTY => qr/^$/o,
        LEAF => qr/^(?<LEAF>[\w\-]+)\s(?<NAME>[\S]+)\s[{]{1}$/o,
        LSPC => qr/\s+$/o,
        MISC => qr/^(?<MISC>[\w-]+)$/o,
        MULT => qr/^(?<MULT>(?:include|exclude)+)\s(?<VALU>[\S]+)$/o,
        NAME => qr/^(?<NAME>[\w\-]+)\s(?<VALU>[\S]+)$/o,
        NODE => qr/^(?<NODE>[\w-]+)\s[{]{1}$/o,
        RSPC => qr/^\s+/o,
    };

    for my $line ( @{$input->{'config_data'}} ) {
        $line =~ s/$re->{LSPC}//;
        $line =~ s/$re->{RSPC}//;

        given ($line) {
            when (/$re->{MULT}/) {
                push( @nodes, $+{MULT} );
                push (@nodes, $+{VALU});
                my @domain = split( /[.]/, $+{VALU} );
                shift(@domain) if scalar(@domain) > 2;
                my $value = join( '.', @domain );
                push (@nodes, $value);
                get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
                pop(@nodes);
                pop(@nodes);
                pop(@nodes);
            }
            when (/$re->{NODE}/) {
                push( @nodes, $+{NODE} );
            }
            when (/$re->{LEAF}/) {
                $level++;
                push( @nodes, $+{LEAF} );
                push( @nodes, $+{NAME} );
            }
            when (/$re->{NAME}/) {
                push (@nodes, $+{NAME});
                push (@nodes, $+{VALU});
                get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
                pop(@nodes);
                pop(@nodes);
            }
            when (/$re->{DESC}/) {
                push (@nodes, $+{NAME});
                push (@nodes, $+{DESC});
                get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
                pop(@nodes);
                pop(@nodes);
            }
            when (/$re->{MISC}/) {
                push (@nodes, $+{MISC});
                push (@nodes, $+{MISC});
                get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
                pop(@nodes);
                pop(@nodes);
            }
            when (/$re->{CMNT}/) {
                next;
            }
            when (/$re->{BRKT}/) {
                pop(@nodes);
                if ( $level > 0 ) {
                    pop(@nodes);
                    $level--;
                }
            }
            when (/$re->{MPTY}/) {
                next;
            }
            default {
                print( sprintf( 'Parse error: "%s"', $line ) );
            }
        }

    }
    return ( $cfg_ref->{'service'}->{'dns'}->{'forwarding'}->{'blacklist'} );
}

sub get_file {
    my $input = shift;
    my @cfg_data;

    if ( exists $input->{'cfg_file'} ) {
        open( my $CF, '<', $input->{'cfg_file'} )
            or die "ERROR: Unable to open $cfg_file: $!";
        chomp( @cfg_data = <$CF> );
        close($CF);
        return \@cfg_data;
    }
    else {
        return FALSE;
    }
}

sub cfg_file {
    my $tmp_ref = parse_node(
        { config_data => get_file( { cfg_file => $cfg_file } ) } );
    my $configured
        = (    $tmp_ref->{'domains'}->{'source'}
            || $tmp_ref->{'hosts'  }->{'source'}
            || $tmp_ref->{'zones'  }->{'source'} )
        ? TRUE
        : FALSE;

    if ($configured) {
        $cfg_ref->{'dns_redirect_ip'} = $tmp_ref->{'dns-redirect-ip'}
            // '0.0.0.0';
        $cfg_ref->{'disabled'}
            = ( $tmp_ref->{'disabled'} eq 'false' )
            ? FALSE
            : TRUE;

        for my $area (qw/hosts domains zones/) {
            $cfg_ref->{$area}->{'dns_redirect_ip'}
                = $cfg_ref->{'dns_redirect_ip'}
                if !exists( $tmp_ref->{$area}->{'dns-redirect-ip'} );
            $cfg_ref->{$area}->{'exclude'}   = $tmp_ref->{$area}->{'exclude'};
            $cfg_ref->{$area}->{'blacklist'} = $tmp_ref->{$area}->{'include'};
            $cfg_ref->{$area}->{'src'}       = $tmp_ref->{$area}->{'source'};
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
        return (FALSE);
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

    say {$LH} ("$date: $msg_ref->{msg_typ}: $msg_ref->{msg_str}");
    say("$msg_ref->{msg_typ}: $msg_ref->{msg_str}")
        if $cfg_ref->{'debug'} || $show;

    return TRUE;
}

sub fetch_url {
    my $input               = shift;
    my $ua                  = LWP::UserAgent->new;
    $ua->agent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56'
    );
    $ua->timeout(60);
    my $get;
    my $data_ref->{'host'}  = $input->{'host'};
    my $lines               = 0;
    $input->{'prefix'}      =~ s/^["](?<UNCMT>.*)["]$/$+{UNCMT}/g;
    my $re                  = {
        REJECT    => qr{^#|^$|^\n}o,
        SELECT    => qr{^$input->{'prefix'}.*$}o,
        SPLIT     => qr{\R|<br \/>}oms,
        };

    $ua->show_progress(TRUE) if $input->{'debug'};
    $get = $ua->get( $input->{'url'} );

    $data_ref->{'data'}
        = { map { my $key = $_; lc($key) => 1 }
        grep { $_ =~ /$re->{SELECT}/ }
        split( /$re->{SPLIT}/, $get->content ) };

    return $get->is_success
        ? $data_ref
        : undef;
}

# Make sure script runs as root
sub is_sudo {
    return (TRUE) if geteuid() == 0;
    return (FALSE);
}

sub write_file {
    my $input = shift;
    open( my $FH, '>', $input->{'file'} ) or return FALSE;
    log_msg (
        {   msg_typ => 'INFO',
            msg_str => "Writing dnsmasq configuration data to $input->{'file'}"
        }
    );
    print {$FH} (
        map {
            my $val = $_;
            $input->{'target'}, $input->{'equals'}, $val, '/', $input->{'ip'}, "\n"
        } @{ $input->{'data'} }
    );
    close($FH);

    return TRUE;
}

sub get_data {
    my $input = shift;
    my ( @threads, @content );
    my $re = {
        FQDN =>
            qr{(\b(?:(?![.]|-)[\w-]{1,63}(?<!-)[.]{1})+(?:[a-zA-Z]{2,63})\b)}o,
        LSPACES => qr{^\s+}o,
        RSPACES => qr{\s+$}o,
        SUFFIX  => qr{(?:#.*$|\{.*$|[/[].*$)}o,
    };
    my @sources = keys %{ $cfg_ref->{ $input->{'area'} }->{'src'} };
    $cfg_ref->{ $input->{'area'} }->{'icount'}
        = scalar( keys %{ $cfg_ref->{ $input->{'area'} }->{'blacklist'} } )
        // 0;
    $cfg_ref->{ $input->{'area'} }->{'records'}
        = $cfg_ref->{ $input->{'area'} }->{'icount'};

    if ( $input->{'area'} eq 'hosts'
        && scalar( keys %{ $cfg_ref->{'domains'}->{'blacklist'} } ) )
    {
        @{ $cfg_ref->{ $input->{'area'} }->{'exclude'} }{
            keys $cfg_ref->{'domains'}->{'blacklist'}
        } = values %{ $cfg_ref->{'domains'}->{'blacklist'} };
    }

 # create asynchronous threaded fetch web content jobs collect downloaded data
    for my $source (@sources) {
        my $url = $cfg_ref->{ $input->{'area'} }->{'src'}->{$source}->{'url'};
        my $max_threads = 10;
        my $uri         = new URI($url);
        my $host        = $uri->host;
        $re->{'PREFIX'}
            = $cfg_ref->{ $input->{'area'} }->{'src'}->{$source}->{'prefix'}
            ~~ 'http'
            ? qr{(?:(?:http:|https:){1}[/]{1,2})}o
            : $cfg_ref->{ $input->{'area'} }->{'src'}->{$source}->{'prefix'};
        log_msg(
            {   msg_typ => 'INFO',
                msg_str => "Downloading $input->{'area'} blacklist from $host"
            }
        ) if $show;
        push @threads,
            threads->create(
            { 'context' => 'list', 'exit' => 'thread_only' },
            \&fetch_url,
            {   area   => $input->{'area'},
                host   => $host,
                prefix => $re->{'PREFIX'},
                src    => $source,
                url    => $url
            }
            );
        sleep(1)
            while ( scalar threads->list(threads::running) >= $max_threads );
    }

    for my $thread (@threads) {
        my $data_ref = $thread->join();
        my $rec_count
            = ( exists $data_ref->{'data'} )
            ? scalar( keys %{ $data_ref->{'data'} } )
            : 0;
        $cfg_ref->{ $input->{'area'} }->{'records'} += $rec_count;

        log_msg(
            {   msg_typ => 'INFO',
                msg_str => $rec_count
                    . " lines downloaded from: $data_ref->{'host'}"
            }
        ) if exists $data_ref->{'host'};

        push( @content, keys $data_ref->{'data'} );
    }
    print( "\r", " " x $cols, "\r" ) if $show;

    if ( $cfg_ref->{ $input->{'area'} }->{'records'} > 0 ) {
        log_msg(
            {   msg_typ => 'INFO',
                msg_str => "Received "
                    . $cfg_ref->{ $input->{'area'} }->{'records'}
                    . " total records\n"
            }
        );

    LINE:
        for my $line (@content) {
            next LINE if $line eq '';
            $line =~ s/$re->{PREFIX}//;
            $line =~ s/$re->{SUFFIX}//;
            $line =~ s/$re->{LSPACES}//;
            $line =~ s/$re->{RSPACES}//;
            my @elements = $line =~ m/$re->{FQDN}/gc;
            my @domain;

            if ( scalar(@elements) > 0 ) {
                map {
                    my $element = $_;
                    @domain = split( /[.]/, $element );
                    if ( $input->{'area'} ne 'domain' ) {
                        given ( scalar(@domain) ) {
                            when ( $_ > 2 ) { shift(@domain); }
                            when ( $_ < 2 ) { unshift( @domain, '.' ); }
                        }
                    }
                    my $value = join( '.', @domain );
                    $cfg_ref->{ $input->{'area'} }->{'blacklist'}->{$element}
                        = $value
                        if !
                        exists $cfg_ref->{ $input->{'area'} }->{'exclude'}
                        ->{$value};
                } @elements;
                printf(
                    "Entries processed: %s %s from: %s lines\r",
                    $cfg_ref->{ $input->{'area'} }->{'icount'}
                        += scalar(@elements),
                    $cfg_ref->{ $input->{'area'} }->{'type'},
                    $cfg_ref->{ $input->{'area'} }->{'records'}
                ) if $show;
            }
        }
    }
}

sub get_config {
    my $input = shift;

    for ($input->{'type'}) {
        /active/  and return cfg_actv();
        /default/ and return cfg_dflt();
        /file/    and return cfg_file();
    }

    return FALSE;
}

sub usage {
    my $input = shift;
    my $usage = {
        cfg_file => sub {
            my $exitcode = shift;
            print STDERR (
                "$cfg_file not found, check path and file name is correct\n");
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
            usage({option => 'help', exit_code => $exitcode});
        },
        default => sub {
            my $exitcode = shift;
            print STDERR (
                "\n    ERROR: '--cfg_file' and '--default' are mutually exclusive options!\n\n"
            );
            usage({option => 'help', exit_code => $exitcode});
        },
        help => sub {
            my $exitcode = shift;
            local $, = "\n";
            print STDERR (@_);
            print STDERR ("usage: $progname <options>\n");
            print STDERR (
                'options:',
                map( ' ' x 4 . $_->[0],
                    sort { $a->[1] cmp $b->[1] } grep ( $_->[0] ne '', @{get_options({option => TRUE})} ) ),
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

    # Process option argument
    $usage->{$input->{'option'}}->($input->{'exit_code'})
}

sub get_options {
    my $input = shift;
    my @opts = (
        [ q{-f <file>   # load a configuration file},             'f=s'       => \$cfg_file],
        [ q{--debug     # enable verbose debug output},           'debug'     => \$cfg_ref->{'debug'}],
        [ q{--default   # use default values for dnsmasq conf},   'default'   => \$default],
        [ q{--disable   # disable dnsmasq blacklists},            'disable'   => \$disable],
        [ q{--enable    # enable dnsmasq blacklists},             'enable'    => \$enable],
        [ q{--help      # show help and usage text},              'help'      => sub {usage({ option => 'help', exit_code => 0} )}],
        [ q{-v          # verbose (outside configure session)},   'v'         => \$show],
        [ q{--version   # show program version number},           'version'   => sub {usage({ option => 'version', exit_code => 0} )}],
        );

    return \@opts if $input->{'option'};
    # Read command line flags and exit with help message if any are unknown
    return GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts );
}
############################### script runs here ###############################

get_options() || usage( { option => 'help', exit_code => 1 } );

# Find reasons to quit
usage( { option => 'sudo',   exit_code => 1 } ) if not is_sudo;
usage( { option => 'enable', exit_code => 1 } )
    if defined($enable)
    and defined($disable);
usage( { option => 'default', exit_code => 1 } )
    if defined($default)
    and defined($cfg_file);
usage( { option => 'cfg_file', exit_code => 1 } )
    if defined($cfg_file)
    and not( -f $cfg_file );

# Start logging
open( $LH, '>>', $cfg_ref->{'log_file'} )
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

exit (1) unless get_config( { type => $cfg_type } );

# Now proceed if blacklist is enabled
if ( not $cfg_ref->{'disabled'} and not $disable ) {
    my @areas;
    # Add areas to process only if they contain sources
    for my $area (qw/domains hosts zones/) {
        push(@areas, $area) if (scalar (keys %{$cfg_ref->{$area}->{'src'}}));
    }

    for my $area (@areas) {

        get_data({area => $area});

        if ( $cfg_ref->{$area}->{'icount'} > 0 ) {
            my $equals = ( $area ne 'domains' ) ? '=/' : '=/.';
            write_file(
                {   file   => $cfg_ref->{$area}->{'file'},
                    target => $cfg_ref->{$area}->{'target'},
                    equals => $equals,
                    ip     => $cfg_ref->{$area}->{'dns_redirect_ip'},
                    data   => [sort keys $cfg_ref->{$area}->{'blacklist'}],
                }
            )
            or die(
            sprintf( "Could not open file: s% $!",
                $cfg_ref->{$area}->{'file'} )
            );

            $cfg_ref->{$area}->{'unique'}
                = scalar( keys %{$cfg_ref->{$area}->{'blacklist'}} );

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
        for my $area (qw{domains hosts zones}) {
            if ( -f "$cfg_ref->{$area}->{file}" ) {
                log_msg(
                    {   msg_typ => 'INFO',
                        msg_str => sprintf(
                            "Removing blacklist configuration file %s
                            $cfg_ref->{$area}->{file}"
                        )
                    }
                );
                unlink("$cfg_ref->{$area}->{file}");
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
close($LH);

# Exit normally
exit(0);

################################################################################
