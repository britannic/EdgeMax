#!/usr/bin/env perl
#
# **** License ****
# COPYRIGHT AND LICENCE
#
# Copyright (C) 2016 by Neil Beadle
#
# This library is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself, either Perl version 5.23.4 or,
# at your option, any later version of Perl 5 you may have available.
#
# Author: Neil Beadle
# Date:   December 2015
# Description: Script for creating dnsmasq configuration files to redirect dns
# look ups to alternative IPs (blackholes, pixel servers etc.)
#
# **** End License ****
use feature qw{switch};
use lib q{/opt/vyatta/share/perl5/};
use Test::More;

note("Testing dnsmasq blacklist configuration");

my $t_count = { tests => 22, failed => 0 };

# Check all the required modules can be loaded
use_ok(q{POSIX}) or $tcount->{failed}++;
require_ok(q{POSIX}) or $tcount->{failed}++;
use_ok(q{HTTP::Tiny}) or $tcount->{failed}++;
require_ok(q{HTTP::Tiny}) or $tcount->{failed}++;
use_ok(q{IO::Select}) or $tcount->{failed}++;
require_ok(q{IO::Select}) or $tcount->{failed}++;
use_ok(q{IPC::Open3}) or $tcount->{failed}++;
require_ok(q{IPC::Open3}) or $tcount->{failed}++;
use_ok(q{Term::ReadKey}) or $tcount->{failed}++;
require_ok(q{Term::ReadKey}) or $tcount->{failed}++;
use_ok(q{Sys::Syslog}) or $tcount->{failed}++;
require_ok(q{Sys::Syslog}) or $tcount->{failed}++;
use_ok(q{threads}) or $tcount->{failed}++;
require_ok(q{threads}) or $tcount->{failed}++;
use_ok(q{File::Basename}) or $tcount->{failed}++;
require_ok(q{File::Basename}) or $tcount->{failed}++;
use_ok(q{Getopt::Long}) or $tcount->{failed}++;
require_ok(q{Getopt::Long}) or $tcount->{failed}++;
use_ok(EdgeOS::DNS::Blacklist) or $tcount->{failed}++;
require_ok( q{EdgeOS::DNS::Blacklist} ) or $tcount->{failed}++;
use_ok(q{Vyatta::Config}) or $tcount->{failed}++;
require_ok(q{Vyatta::Config}) or $tcount->{failed}++;
use v5.14;

use EdgeOS::DNS::Blacklist (
  qw{
    $c
    get_cfg_actv
    get_cfg_file
    get_file
    is_configure
    is_admin
    log_msg
    popx
    pushx
    }
);

use constant TRUE  => 1;
use constant FALSE => 0;
my $version = q{1.1};
my ( $blacklist_removed, $cfg_file );

########## Run main ###########
&main();
my $t_word = $t_count->{failed} <= 1 ? q{test} : q{tests};
if ( $t_count->{failed} == 0 && !$blacklist_removed ) {
  say(  qq{$c->{grn}All $t_count->{tests} tests passed - dnsmasq }
      . qq{blacklisting is configured correctly$c->{clr}} );
  exit 0;
}
elsif ( $blacklist_removed && $t_count->{failed} != 0 ) {
  say(  qq{$c->{red} $t_count->{failed} $t_word failed out of }
      . qq{$t_count->{tests} - dnsmasq blacklisting has not been removed }
      . qq{correctly$c->{clr}} );
  exit 1;
}
elsif ( $blacklist_removed && $t_count->{failed} == 0 ) {
  say(  qq{$c->{grn}All $t_count->{tests} tests passed - dnsmasq }
      . qq{blacklisting has been completely removed$c->{clr}} );
  exit 0;
}
else {
  say(  qq{$c->{red} $t_count->{failed} $t_word failed out of }
      . qq{$t_count->{tests} - dnsmasq blacklisting is not working correctly}
      . qq{$c->{clr}} );
  exit 1;
}
############ exit #############

# Set up command line options
sub get_options {
  my $input = shift;
  my @opts  = (
    [ q{-f <file> # load a configuration file}, q{f=s} => \$cfg_file ],
    [
      q{-help     # show help and usage text},
      q{help} => sub { usage( { option => q{help}, exit_code => 0 } ) }
    ],
    [
      q{-version  # show program version number},
      q{version} => sub { usage( { option => q{version}, exit_code => 0 } ) }
    ],
  );

  return \@opts if $input->{option};

  # Read command line flags and exit with help message if any are unknown
  return GetOptions( map { my $options = $_; (@$options)[ 1 .. $#$options ] }
      @opts );
}

# Main script
sub main {
  my $cfg = {
    dnsmasq_dir  => q{/etc/dnsmasq.d},
    flag_file    => q{/var/log/update-dnsmasq-flagged.cmds},
    no_op        => q{/tmp/.update-dnsmasq.no-op},
    testscript   => q{/config/scripts/blacklist.t},
    updatescript => q{/config/scripts/update-dnsmasq.pl}
  };

  # Get command line options or print help if no valid options
  get_options() || usage( { option => q{help}, exit_code => 1 } );

  usage( { option => q{cfg_file}, exit_code => 1 } )
    if defined $cfg_file && !-f $cfg_file;

  # Now choose which data set will define the configuration
  my $success
    = defined $cfg_file
    ? get_cfg_file( { config => $cfg, file => $cfg_file } )
    : get_cfg_actv( { config => $cfg, show => TRUE } );

  $cfg->{domains_pre_f}
    = [ glob qq{$cfg->{dnsmasq_dir}/domains.pre*blacklist.conf} ];
  $cfg->{hosts_pre_f}
    = [ glob qq{$cfg->{dnsmasq_dir}/hosts.pre*blacklist.conf} ];
  $cfg->{zones_pre_f}
    = [ glob qq{$cfg->{dnsmasq_dir}/zones.pre*blacklist.conf} ];

  # If blacklist is disabled - check it really is
  if ( exists $cfg->{disabled} && $cfg->{disabled} ) {
    $t_count->{tests} += 4;
    is( -f $cfg->{updatescript},
      TRUE, q{Checking } . basename( $cfg->{updatescript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg->{flag_file},
      TRUE, q{Checking } . basename( $cfg->{flag_file} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{flag_file} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg->{no_op},
      TRUE, q{Checking } . basename( $cfg->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg->{testscript},
      TRUE, q{Checking } . basename( $cfg->{testscript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{testscript} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
  }
  elsif ( exists $cfg->{disabled} && !$cfg->{disabled} ) {
    $t_count->{tests} += 4;
    is( -f $cfg->{updatescript},
      TRUE, q{Checking } . basename( $cfg->{updatescript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg->{flag_file},
      TRUE, q{Checking } . basename( $cfg->{flag_file} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{flag_file} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg->{no_op},
      TRUE, q{Checking } . basename( $cfg->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg->{testscript},
      TRUE, q{Checking } . basename( $cfg->{testscript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{testscript} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
  }
  elsif ( !$success ) {
    $blacklist_removed = TRUE;
    $t_count->{tests} += 5;
    isnt( -f $cfg->{updatescript},
      TRUE,
      q{Checking } . basename( $cfg->{updatescript} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg->{flag_file},
      TRUE, q{Checking } . basename( $cfg->{flag_file} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{flag_file} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg->{no_op},
      TRUE, q{Checking } . basename( $cfg->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg->{testscript},
      TRUE, q{Checking } . basename( $cfg->{testscript} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg->{testscript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;

    # Check for stray files
    $cfg->{strays}
      = [ glob qq{$cfg->{dnsmasq_dir}/{domains,zones,hosts}*.blacklist.conf} ];
    my $no_strays = isnt( scalar( @{ $cfg->{strays} } ),
      TRUE, qq{Checking *.blacklist.conf files not found in /etc/dnsmasq.d/} )
      or diag( qq{$c->{red} Found blacklist configuration files in }
        . qq{$cfg->{dnsmasq_dir}/ - they should be deleted!}
        . $c->{clr} ), $t_count->{failed}++;
    if ( !$no_strays ) {
      say(qq{The following files were found in $cfg->{dnsmasq_dir}/:});
      for ( @{ $cfg->{strays} } ) {
        say;
      }
    }
    done_testing( $t_count->{tests} );
    return TRUE;
  }

  # Add areas to process only if they contain sources
  my @areas;
  for my $area (qw{domains zones hosts}) {
    push @areas, $area if scalar keys %{ $cfg->{$area}->{src} };
  }

  for my $area (@areas) {
    my @files;
    my $ip = $cfg->{$area}->{dns_redirect_ip};
    if ( exists $cfg->{$area}->{src} ) {
      for my $source ( sort keys %{ $cfg->{$area}->{src} } ) {
        push @files, [$source, qq{$cfg->{dnsmasq_dir}/$area.$source.blacklist.conf}];
      }
      for my $f_ref (@files) {
        my ($source, $file) = @{$f_ref};
        $t_count->{tests}++;
        is( -f $file, TRUE, qq{Checking $source has a file} )
          or diag( qq{$c->{red}}
            . basename($file)
            . qq{ not found for $source - investigate!}
            . $c->{clr} ), $t_count->{failed}++;
      }

      # Test global and area exclusions
      for my $f_ref (@files) {
        my ($source, $file) = @{$f_ref};
        my $content = get_file( { file => $file } );
        if ( @{$content} ) {
          for my $host ( sort keys %{ $cfg->{exclude} } ) {
            my $re = qr{address=[/][.]{0,1}$host[/].*};
            $t_count->{tests}++;
            is( $re ~~ @{$content},
              q{},
              qq{Checking "global exclude" $host not in } . basename($file) )
              or diag( qq{$c->{red}}
                . qq{Found "global exclude" $host in }
                . basename($file) . q{!}
                . $c->{clr} ), $t_count->{failed}++;
          }
          for my $host ( sort keys %{ $cfg->{$area}->{exclude} } ) {
            my $re = qr{address=[/][.]{0,1}$host[/].*};
            $t_count->{tests}++;
            is( $re ~~ @{$content},
              q{},
              qq{Checking "$area exclude" $host not in } . basename($file) )
              or diag( qq{$c->{red}}
                . qq{Found "$area exclude" $host in }
                . basename($file) . q{!}
                . $c->{clr} ), $t_count->{failed}++;
          }
          my $re        = qr{(?:address=[/][.]{0,1}.*[/])(?<IP>.*)};
          my %found_ips = map {
            my $found_ip = $_;
            $found_ip =~ s/$re/$+{IP}/ms;
            $found_ip => 1;
          } @{$content};
          for my $found_ip ( sort keys %found_ips ) {
            $t_count->{tests}++;
            cmp_ok( $found_ip, q{eq}, $ip,
                  qq{IP address $found_ip found in }
                . basename($file)
                . qq{ matches configured $ip} )
              or diag( qq{$c->{red}}
                . qq{IP address $found_ip found in }
                . basename($file)
                . qq{ doesn't match configured $ip!}
                . $c->{clr} ), $t_count->{failed}++;
          }
        }
      }

      for my $file ( @{ $cfg->{ $area . q{_pre_f} } } ) {
        my $content = get_file( { file => $file } );
        if ( @{$content} ) {
          for my $host ( sort keys %{ $cfg->{$area}->{blklst} } ) {
            $t_count->{tests}++;
            my $re = qr{address=[/][.]{0,1}$host[/].*};
            is( $re ~~ @{$content},
              TRUE,
              qq{Checking "$area include" $host is in } . basename($file) )
              or diag( qq{$c->{red}}
                . qq{"$area include" $host not found in }
                . basename($file)
                . $c->{clr} ), $t_count->{failed}++;
          }
          $t_count->{tests}++;
          my $address = $area ne q{domains} ? q{address=/} : q{address=/.};
          my @includes = map { my $include = $_; qq{$address$include/$ip} }
            @{ [ sort keys %{ $cfg->{$area}->{blklst} } ] };
          my $success = is(
            @includes ~~ @{$content},
            TRUE,
            qq{Checking }
              . basename($file)
              . qq{ only contains "$area include" entries}
          );
          if ( !$success ) {
            $t_count->{failed}++;
            diag( qq{$c->{red}}
                . qq{"$area include" has additional entries in }
                . basename($file)
                . qq{ investigate the following entries:$c->{clr}} );
            my $re_fqdn = qr{address=[/][.]{0,1}(.*)[/].*}o;
            my %found   = ();
            @found{ @{$content} } = ();
            delete @found{@includes};
            my @ufo = sort keys %found;
            for my $alien (@ufo) {
              $alien =~ s/$re_fqdn/$1/ms;
              say(qq{Found: $c->{mag}$alien$c->{clr}});
            }
          }
        }
      }
    }
  }
  done_testing( $t_count->{tests} );
}

# Process command line options and print usage
sub usage {
  my $input    = shift;
  my $progname = basename($0);
  my $usage    = {
    cfg_file => sub {
      my $exitcode = shift;
      print STDERR
        qq{$cfg_file not found, check path and file name is correct\n};
      exit $exitcode;
    },
    help => sub {
      my $exitcode = shift;
      local $, = qq{\n};
      print STDERR @_;
      print STDERR qq{usage: $progname <options>\n};
      print STDERR q{options:},
        map( q{ } x 4 . $_->[0],
        sort { $a->[1] cmp $b->[1] } grep $_->[0] ne q{},
        @{ get_options( { option => TRUE } ) } ),
        qq{\n};
      $exitcode == 9 ? return TRUE : exit $exitcode;
    },
    version => sub {
      my $exitcode = shift;
      printf STDERR qq{%s version: %s\n}, $progname, $version;
      exit $exitcode;
    },
  };

  # Process option argument
  $usage->{ $input->{option} }->( $input->{exit_code} );
}
