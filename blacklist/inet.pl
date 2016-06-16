#!/usr/bin/env perl
#
require 5.014;
use Socket
    qw( getaddrinfo getnameinfo inet_ntop unpack_sockaddr_in unpack_sockaddr_in6 AF_INET);

my $host = "www.adsrvr.org";

sub get_ip {
    my $host = shift;
    my $addr, $ip;
    my ( $err, @getaddr ) = getaddrinfo( $host, 0 );
    if ( $getaddr[0]->{family} == AF_INET ) {
        $addr = unpack_sockaddr_in( $getaddr[0]->{addr} );
        $ip = inet_ntop( AF_INET, $addr );
    }
    else {
        $addr = unpack_sockaddr_in6( $getaddr[0]->{addr} );
        $ip = inet_ntop( $getaddr[0]->{family}, $addr );
    }
    return $ip;
}

print "NEW: inet_ntop() Address = " . get_ip($host) . "\n";
