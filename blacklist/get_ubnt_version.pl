#!/usr/bin/env perl
#

use v5.14;
use strict;
use warnings;
use lib q{/opt/vyatta/share/perl5/};

# get EdgeOS version
sub is_version {
  my ( $build, $version ) = ( q{UNKNOWN BUILD}, q{UNKNOWN VERSION} );
  my $cmd = qq{cat /opt/vyatta/etc/version};
  chomp( my $edgeOS = qx{$cmd} );

  if ( $edgeOS =~ s{^Version:\s*(?<VERSION>.*)$}{$+{VERSION}}xms ) {
    my @ver = split /\./ => $edgeOS;
    $version = join "." => @ver[ 0..$#ver-3];
    $build = $ver[$#ver-2];
  }

  return { version => $version, build => $build };
}

my $input = is_version();
print $input->{build} . "\n";
print $input->{version} . "\n";
