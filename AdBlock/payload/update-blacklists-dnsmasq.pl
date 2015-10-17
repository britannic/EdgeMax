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

my $version                                               = '3.2e';

# use Data::Dumper;
use File::Basename;
use Getopt::Long;
use integer;
use lib '/opt/vyatta/share/perl5/';
use LWP::UserAgent;
use Pod::Usage qw(pod2usage);
use POSIX qw(strftime);
use strict;
use threads;
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
my @exclusions                                            = ();
my @blacklist_urls                                        = ();
my @blacklist_prfx                                        = ();
my $dnsmasq                                               = "/etc/init.d/dnsmasq";
my $fqdn                                                  = '(\b([a-z0-9_]+(-[a-z0-9_]+)*\.)+[a-z]{2,}\b).*$';
my $black_hole_ip;
my $blacklist_file                                        = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my $i                                                     = 0;
my $enable                                                = undef;
my $disable                                               = undef;
my $documentation                                         = undef;
my $cmd                                                   = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper";
my $begin                                                 = "$cmd begin";
my $commit                                                = "$cmd commit";
my $delete                                                = "$cmd delete";
my $end                                                   = "$cmd end";
my $save                                                  = "$cmd save";
my $set                                                   = "$cmd set";
my $prog                                                  = basename($0);
my $cfg_file;
my $default;
my $download;
my $in_cli;
my $line;
my $list;
my $loghandle;
my $print_ver;
my $ref_mode;
my $uri;

my @opts = (
    [ q{--cfg-file <file>  # load a configuration file}, 'cfg-file=s' => \$cfg_file ],
    [ q{--debug            # enable debug output}, 'debug' => \$debug_flag ],
    [ q{--default          # loads default values for dnsmasq.conf file},'default' => \$default ],
    [ q{--disable          # disable dnsmasq blacklists}, 'disable' => \$disable ],
    [ q{--doc              # display documentation},'doc' => sub { Usage(0, 'doc') } ],
    [ q{--enable           # enable dnsmasq blacklists},'enable' => \$enable ],
    [ q{--help             # show help and usage text},'help'    => sub { Usage(0, 'help') } ],
    [ q{--in-cli           # use inside a configure session for status output},'in-cli' => \$in_cli] ,
    [ q{--version          # show program version number},'version' => \$print_ver ],
);

sub Usage ($ $) {
    my $exitcode = shift;
    my $help = shift;
    local $, = "\n";

    if ($help eq 'help') {
        print @_;
        print "Usage: $prog <options>\n";
        print 'options:',
            map( ' ' x 4 . $_->[0],
            sort { $a->[1] cmp $b->[1] } grep ( $_->[0] ne '', @opts ) ),
            "\n";
    }
    else {
        pod2usage(-verbose => 2)
    }
    exit $exitcode;
}

sub cmd_line {
    my $cmdmode = \$ref_mode;

    GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts ) or Usage(1, 'help');

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

sub uniq {
    my $unsorted = shift;
    my @sorted   = ( sort keys %{ { map { $_ => 1 } @$unsorted } } );
    return \@sorted;
}

sub write_list($$) {
    my $fh;
    my $file = $_[0];
    my @list = @{ $_[1] };
    open( $fh, '>', $$file ) or die "Could not open file: '$file' $!";
    print $fh (@list);
    close($fh);
}

sub cfg_none {
    $black_hole_ip = "0.0.0.0";

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
            $enabled       = $config->returnValue('enabled') // false;
            @includes      = $config->returnValues('include');
            @excludes      = $config->returnValues('exclude');
            @sources       = $config->listNodes('source');
            $black_hole_ip = $config->returnValue('blackhole') // "0.0.0.0";
        }
        else {
            $config->setLevel('service dns forwarding blacklist');
            $enabled       = $config->returnOrigValue('enabled') // false;
            @includes      = $config->returnOrigValues('include');
            @excludes      = $config->returnOrigValues('exclude');
            @sources       = $config->listOrigNodes('source');
            $black_hole_ip = $config->returnOrigValue('blackhole')
                // "0.0.0.0";
        }

        for ($enabled) {
            /false/ and $enabled = false;
            /true/  and $enabled = true;
        }

        for (@includes) {
            push( @{ \@blacklist }, "address=/$_/${\$black_hole_ip}\n" );
        }

        for (@excludes) {
            push( @{ \@exclusions }, $_ );
        }

        for (@sources) {
            $config->setLevel("service dns forwarding blacklist source $_");
            if ( $ref_mode eq "in-cli" ) {
                push( @{ \@blacklist_urls }, $config->returnValue('url') );
                push( @{ \@blacklist_prfx }, $config->returnValue('prefix') );
            }
            else {
                push( @{ \@blacklist_urls }, $config->returnOrigValue('url') );
                push( @{ \@blacklist_prfx }, $config->returnOrigValue('prefix') );
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
                /^blackhole\s+(.*)$/ and $black_hole_ip = $1 // "0.0.0.0";
                /^enabled\s+(\w)$/   and $enabled       = $1 // false;
            }
        }

        for ($enabled) {
            /false/ and $enabled = false;
            /true/  and $enabled = true;
        }

        for my $multiBlacklistExclude (@excludes) {
            push( @{ \@exclusions }, $multiBlacklistExclude->{'name'} );
        }

        for my $multiBlacklistInclude (@includes) {
            push( @{ \@blacklist }, "address=/$multiBlacklistInclude->{'name'}/${\$black_hole_ip}\n" );
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
        log_msg( "INFO",
            "service dns forwarding blacklist isn't configured, exiting!\n" );
        print(
            "service dns forwarding blacklist isn't configured, exiting!\n");
        exit(1);
    }
    $ref_mode
        = $mode;   # restoring $cmdmode as this sub is clobbering it somewhere
    return (true);
}

sub get_blklist_cfg {
    # Make sure localhost is in the whitelist of exclusions
    my $exclude = 'localhost';
    push( @{ \@exclusions }, $exclude );
    for ($ref_mode) {
        m/ex-cli|in-cli/ and cfg_active, last;
        m/cfg-file/      and cfg_file,   last;
        m/default/       and cfg_none,   last;
    }
}

sub enable {
    my $bool;
    my $status;
    $debug_flag = true;

    if ( not isscheduled ) {
        log_msg( "INFO",
            "Enabling ADBlock [set system task-scheduler task update_blacklists]\n"
        );
        my @schedule = (
            "$begin; ",
            "$set system task-scheduler task update_blacklists executable path /config/scripts/update-blacklists-dnsmasq.pl; ",
            "$set system task-scheduler task update_blacklists interval 6h; ",
            "$commit; ",
            "$end; ",
        );
        my @output = qx(@schedule 2>&1);
        if ( $? == 0 ) {
            $bool   = true;
            $status = "INFO";
            log_msg( $status, "Disabled dnsmasq ADBlock blacklist\n" );
        }
        else {
            $bool   = false;
            $status = "ERROR";
        }
        log_msg( $status, @output );
    }
    else {
        log_msg( "INFO", "ADBlock already enabled\n" );
        $bool = true;
    }
    return ($bool);
}

sub disable {
    my $bool;
    my $status;
    $debug_flag = true;

    if (isscheduled) {
        $debug_flag = true;
        log_msg( "INFO",
            "Disabling ADBlock [delete system task-scheduler task update_blacklists]\n"
        );

        my @schedule = (
            "$begin; ",
            "$delete system task-scheduler task update_blacklists; ",
            "$commit; ", "$end;",
        );

        my @output = qx(@schedule 2>&1);
        if ( $? == 0 ) {
            $bool   = true;
            $status = "INFO";
            log_msg( $status, "Enabled dnsmasq ADBlock blacklist\n" );
        }
        else {
            $bool   = false;
            $status = "ERROR";
        }
        log_msg( $status, @output );
    }
    else {
        log_msg( "INFO", "ADBlock already disabled\n" );
        $bool = true;
    }
    return ($bool);
}

sub log_msg ($ $) {
    my $log_type                                          = shift;
    my $message                                           = shift;
    my $date                                              = strftime "%b %e %H:%M:%S %Y", localtime;

    return(false) if not $message;

    print $loghandle ("$date: $log_type: $message");
    print("$log_type: $message") if $debug_flag;
}

sub fetch_url {
    my $get;
    my $secs      = 30;
    my $strmregex = qr/^\s+|\s+$|^\n|^#.*$/;
    my $ua        = LWP::UserAgent->new;
    my $url       = shift;

    $ua->timeout($secs);

    if ( ${\$ref_mode} eq "ex-cli" and not $debug_flag ) {
        $get = $ua->get($url);
    }
    else {
        print STDERR ("Downloading blacklist from $url...\n")
            if not $debug_flag;

        #         $ua->add_handler(response_header => \pinwheel);
        $ua->show_progress(true) if $debug_flag;
        $get = $ua->get($url);
        #         print STDERR ( $get->status_line(), "\n" );
        #         print STDERR ( "\n" );
        #         $ua->remove_handler('response_header');
    }

    return $get->is_success
        ? keys {
        my %hash = map {
            ( my $val = lc($_) ) =~ s/$strmregex//;
            $val => 1;
            } split( qr/\R/, $get->content ) }
        : "$url download failed";
}

sub update_blacklist {
    my $mode      = \$ref_mode;
    my $exclude   = join( "|", @{ uniq(\@exclusions) } );
    my $prefix    = join( "|", @{ uniq(\@blacklist_prfx) } );
    my $cols      = qx( tput cols );
    my $counter   = \$i;

    $exclude  = qr/^($prefix|)\s*$exclude/;
    $prefix   = qr/^($prefix|)\s*$fqdn/;
    $$counter = scalar( @{ \@blacklist } );

    my @content = map $_->join, map threads->create( \&fetch_url, $_ ),
        @blacklist_urls;

    if (@content) {
        log_msg( "INFO", "Received " . scalar(@content) . " records\n" );
        print( "\r", " " x $cols, "\r" )
            if $$mode ne "ex-cli";

        my $records = 0;

        for my $line (@content) {
            print( "Entries processed: ", $records, "\r" )
                if $$mode ne "ex-cli";
            for ($line) {
                /$$exclude/ and last;
                /$$prefix/  and push( @{ \@blacklist }, "address=/$2/${\$black_hole_ip}\n" ),
                    $$counter++, $records++, last;
            }
        }
        log_msg( "INFO", "Processed $records records\n" );
#         print("\n") if $$mode ne "ex-cli";
    }
}

# main()
open( $loghandle, ">>$debug_log" ) or $debug_flag = undef;
log_msg( "INFO", "---+++ ADBlock $version +++---\n" );

cmd_line;

get_blklist_cfg;

if ( not $enable and not $disable ) {

    update_blacklist;

    write_list( \$blacklist_file, \@{ uniq(\@blacklist) } );

    printf( "\rUnique entries processed %d\n",
        $i )
        if $ref_mode ne "ex-cli";

    log_msg( "INFO",
              "Unique entries processed: $i"
            . $i
            . "\n" );

    $cmd
        = $ref_mode ne "in-cli"
        ? "$dnsmasq force-reload > /dev/null 2>1&"
        : "/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding";

    qx($cmd);
}
elsif ($enable) {
    log_msg( "ERROR", "Unable to enable dnsmasq ADBlock blacklist!\n" ) if not enable;
}
elsif ($disable) {
    log_msg( "ERROR", "Unable to disable dnsmasq ADBlock blacklist!\n" ) if not disable;
}

close($loghandle);

__END__

=head1 B<NAME>

B<UBNT EdgeMax Blacklist and Ad Server Blocking>

=head1 B<SYNOPSIS>

EdgeMax Blacklist and Ad Server Blocking is derived from the received wisdom found at (https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)

=over

=item * Generates a dnsmasq configuration file that can be used directly by dnsmasq

=item * Integrated with the EdgeMax OS CLI

=item * Uses any fqdn in the blacklist will return the configured Blackhole IP address

=back

=head1 B<Compatibility>

=over

=item * update-blacklists-dnsmasq.pl has been tested on the EdgeRouter Lite family of routers, version v1.6.0-v1.7.0.

=item * Since the EdgeOS is a fork and port of Vyatta 6.3, this script could easily be adapted for work on VyOS and Vyatta derived ports.

=back

=head2 B<Installation>

To install:

=over

=item * upload install_adblock.tgz to your router (e.g. scp /ersetup.tgz @:/tmp/install_adblock.tgz

=item * on your router: cd /tmp; sudo tar zxvf /tmp/install_adblock.tgz

=item * sudo bash /tmp/install_adblock

=item * The script has a menu to either add or remove (if previously installed) AdBlock. It will set up the system task scheduler (cron) via the CLI to run "/config/scripts/update-blacklists-dnsmasq.pl" at mindnight local time.

=back

=head1 B<LICENSE>

=over

=item * GNU General Public License, version 3

=item * GNU Lesser General Public License, version 3

=back

=head1 AUTHOR

Neil Beadle - L<https://github.com/britannic/EdgeMax/tree/master/AdBlock>

=head1 SEE ALSO

L<perlpod>, L<perlpodspec>

=cut
