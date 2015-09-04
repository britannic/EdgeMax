#!/usr/bin/env perl
# This script writes a unique sorted list of adserver and blacklisted fqdns to
# a file in dnsmasq format
#

use warnings;
use strict;
use integer;
use Switch;

my @blacklist_urls                            = (
    qw|"http://winhelp2002.mvps.org/hosts.txt"
        "http://someonewhocares.org/hosts/zero/"
        "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=dnsmasq&showintro=0&mimetype=plaintext"
        "http://www.malwaredomainlist.com/hostslist/hosts.txt"|
);

my $dnsmasq                                   = "/etc/init.d/dnsmasq";

# The IP address below should point to the IP of your router/pixelserver or to 0.0.0.0
# 0.0.0.0 is easy and doesn't require much from the router
my $black_hole_ip                             = "0.0.0.0";
my $blacklist_file                            = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my @blacklist;

# Add any exclusions here (i.e. Hulu, Google lead services) - see examples below
my @exclusions
                                              = (
    qw/appleglobal.112.2o7.net cdn.visiblemeasures.com hb.disney.go.com googleadservices.com hulu.com localhost static.chartbeat.com survey.112.2o7.net/
    );

sub uniq {
    my %hash                                  = map { $_ => 1 } @_;
    return keys %hash;
}

sub write_list {
    my $fh;
    my $file                                  = shift;
    my @list                                  = @_;
    open( $fh, '>', $file ) || die "Could not open file: '$file' $!";
    print $fh (@list);
    close($fh);
}

sub update_blacklist {
    my $addr                                  = qr|^address=/\b([-a-z0-9_\.]+)\b/127\.0\.0\.1|;
    my $zero                                  = qr|^0\.0\.0\.0\s\b([-a-z0-9_\.]*\b).*|;
    my $lhst                                  = qr|^127\.0\.0\.1\s\s\b([-a-z0-9_\.]*)\b[\s]{0,1}|;
    my $exclusions;

    foreach (@exclusions) {
        $_                                    = ".*" . $_ . ".*";
    }
    my $exclude                               = join( "|", @exclusions );

    # Get blacklist and convert the hosts file into a dnsmasq.conf format
    # file. Be paranoid and replace every IP address with $black_hole_ip.
    # We only want the actual blacklist, so we can prepend our own hosts.
    # $black_hole_ip="0.0.0.0" saves router CPU cycles and is more efficient

    foreach my $url (@blacklist_urls) {
        foreach my $line (qx(curl -s $url)) {
            chomp $line;
            $line                             =  lc $line;

            switch ($line) {
                case m/$exclude/ { }
                case m/$zero/ {
                    $line                     =~ s/$zero/$1/;
                    if ( length($line) > 1 ) {
                        push @blacklist,
                            sprintf( "address=/%s/%s\n",
                            $line, $black_hole_ip );
                    }
                }
                case m/$addr/ {
                    $line                     =~ s/$addr/$1/;
                    if ( length($line) > 1 ) {
                        push @blacklist,
                            sprintf( "address=/%s/%s\n",
                            $line, $black_hole_ip );
                    }
                }
                case m/$lhst/ {
                    $line                     =~ s/$lhst/$1/;
                    if ( length($line) > 1 ) {
                        push @blacklist,
                            sprintf( "address=/%s/%s\n",
                            $line, $black_hole_ip );
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

# debug - uncomment print and comment write_list && ...
# print get_blacklist;

write_list( $blacklist_file, get_blacklist() )
    && system("$dnsmasq force-reload");
