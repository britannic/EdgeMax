#!/usr/bin/env perl
# This script will write a combined, unique sorted list of adserver and
# blacklisted fqdns to a file in dnsmasq format
#
use warnings;
use strict;
use integer;

my $ad_list_url
                   = "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=dnsmasq&showintro=0&mimetype=plaintext";
my $blacklist_url  = "http://winhelp2002.mvps.org/hosts.txt";
my $dnsmasq        = "/etc/init.d/dnsmasq";

# The IP address below should point to the IP of your router/pixelserver or to 0.0.0.0
# 0.0.0.0 is easy and doesn't require much from the router
my $black_hole_ip  = "0.0.0.0";
my $blacklist_file = "/etc/dnsmasq.d/dnsmasq.blacklist.conf";
my @blacklist;
my @adlist;

# Add any exclusions here (i.e. Hulu, Google lead services). Note, in order to
# use regex matching, prepend the domain or fqdn with '.*' - see examples below
my $exclusions     = ( join( "|", ".*googleadservices.com", ".*hulu.com" ) );

sub uniq {
    my %hash       = map { $_ => 1 } @_;
    return keys %hash;
}

sub write_list {
    my $fh;
    my $file       = shift;
    my @list       = @_;
    open( $fh, '>', $file ) || die "Could not open file: '$file' $!";
    print $fh (@list);
    close($fh);
}

sub update_adlist {

    # Get ad block list
    foreach my $line (qx(curl -s $ad_list_url)) {
        chomp $line;
        if ( $line =~ /^address/ ) {
            if ( $line !~ /$exclusions/ ) {
                push @adlist,
                    lc( $line
                        =~ s|^(address=/.*)(/127\.0\.0\.1)|$1/$black_hole_ip\n|r
                    );
            }
        }
    }
}

sub update_blacklist {

    # Get blacklist and convert the hosts file into a dnsmasq.conf format
    # file. Be paranoid and replace every IP address with $black_hole_ip.
    # We only want the actual blacklist, so we can prepend our own hosts.
    # $black_hole_ip="0.0.0.0" saves router CPU cycles and is more efficient

    foreach my $line (qx(curl -s $blacklist_url)) {
        chomp $line;
        if ( $line =~ /^0\.0\.0\.0.[-a-z0-9.]*/ ) {
            if ( $line !~ /$exclusions/ ) {
                push @blacklist,
                    lc( $line
                        =~ s|^(0\.0\.0\.0\s)([-a-z0-9_.]*)(.*)|address=/$2/$black_hole_ip\n|r
                    );
            }
        }
    }
}

sub get_blacklist {
    update_adlist;
    update_blacklist;
    push @blacklist, @adlist;
    return sort( uniq(@blacklist) );
}

# print get_blacklist;
write_list( $blacklist_file, get_blacklist() )
    && system("$dnsmasq force-reload");

