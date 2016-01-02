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
use lib q{/opt/vyatta/share/perl5};
use lib q{/config/lib/perl};
use lib q{./lib};
use Socket;
use Test::More;
use File::Basename;
use Getopt::Long;
use HTTP::Tiny;
use IO::Select;
use IPC::Open3;
use POSIX;
use strict;
use Sys::Syslog;
use Term::ReadKey;
use threads;
use Vyatta::Config;
use v5.14;
use warnings;
use EdgeOS::DNS::Blacklist (
  qw{
    $c
    append_spaces
    get_cfg_actv
    get_cfg_file
    get_cols
    get_file
    is_configure
    is_admin
    log_msg
    popx
    }
);

use constant TRUE  => 1;
use constant FALSE => 0;
my $version = q{1.2};
my ( $blacklist_removed, $cfg_file, $spoke );

########## Run main ###########
exit 0 if &main();
############ exit #############

sub exec_test {
  my $input = shift;
  my $test  = {
    is => sub {
      my $rslt = is(
        $input->{run}->{lval},
        $input->{run}->{result},
        $input->{run}->{comment}
      );
      if ( !$rslt ) {
        diag( $input->{run}->{diag} );
        $input->{run}->{run_sub}->() if defined $input->{run}->{run_sub};
        return;
      }
      return $rslt;
    },
    is_file => sub {
      my $rslt = is(
        -f $input->{run}->{lval},
        $input->{run}->{result},
        $input->{run}->{comment}
      );
      if ( !$rslt ) {
        diag( $input->{run}->{diag} );
        $input->{run}->{run_sub}->() if defined $input->{run}->{run_sub};
        return;
      }
      return $rslt;
    },
    isnt => sub {
      my $rslt = isnt(
        $input->{run}->{lval},
        $input->{run}->{result},
        $input->{run}->{comment}
      );
      if ( !$rslt ) {
        diag( $input->{run}->{diag} );
        $input->{run}->{run_sub}->() if defined $input->{run}->{run_sub};
        return;
      }
      return $rslt;
    },
    isnt_file => sub {
      my $rslt = isnt(
        -f $input->{run}->{lval},
        $input->{run}->{result},
        $input->{run}->{comment}
      );
      if ( !$rslt ) {
        diag( $input->{run}->{diag} );
        $input->{run}->{run_sub}->() if defined $input->{run}->{run_sub};
        return;
      }
      return $rslt;
    },
    isnt_dir => sub {
      my $rslt = isnt(
        -d $input->{run}->{lval},
        $input->{run}->{result},
        $input->{run}->{comment}
      );
      if ( !$rslt ) {
        diag( $input->{run}->{diag} );
        $input->{run}->{run_sub}->() if defined $input->{run}->{run_sub};
        return;
      }
      return $rslt;
    },
    cmp_ok => sub {
      return cmp_ok(
        $input->{run}->{lval}, $input->{run}->{op},
        $input->{run}->{rval}, $input->{run}->{comment}
      ) or diag( $input->{run}->{diag} );
    },
  };

  $test->{ $input->{run}->{test} }->();

}

sub get_areas {
  my $input = shift;

  # Add areas to process only if they contain sources
  my @areas;
  for my $area (qw{domains hosts zones}) {
    push @areas, $area if scalar keys %{ $input->{cfg}->{$area}->{src} };
  }
  return \@areas;
}

sub get_files {
  my $input = shift;
  my @files;

  for my $source ( sort keys %{ $input->{cfg}->{ $input->{area} }->{src} } ) {
    push @files,
      [
      $source,
      qq{$input->{cfg}->{dnsmasq_dir}/$input->{area}.$source.blacklist.conf}
      ];
  }

  return \@files;
}

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

sub get_tests {
  my $input = shift;
  my $tests = {};
  my $ikey  = 1;

  print append_spaces(
    pinwheel() . qq{ Loading EdgeOS router configuration...} );

  # Now choose which data set will define the configuration
  my $success
    = defined $cfg_file
    ? get_cfg_file( { config => $input->{cfg}, file => $cfg_file } )
    : get_cfg_actv( { config => $input->{cfg}, show => TRUE } );

  $input->{cfg}->{domains_pre_f}
    = [ glob qq{$input->{cfg}->{dnsmasq_dir}/domains.pre*blacklist.conf} ];
  $input->{cfg}->{hosts_pre_f}
    = [ glob qq{$input->{cfg}->{dnsmasq_dir}/hosts.pre*blacklist.conf} ];
  $input->{cfg}->{zones_pre_f}
    = [ glob qq{$input->{cfg}->{dnsmasq_dir}/zones.pre*blacklist.conf} ];

  if ($success) {
    print append_spaces( pinwheel() . q{ Adding tests for key files...} );

    $tests->{ $ikey++ } = {
      comment => q{Checking }
        . basename( $input->{cfg}->{updatescript} )
        . q{ exists},
      diag => qq{$c->{red}}
        . basename( $input->{cfg}->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr},
      lval   => qq{$input->{cfg}->{updatescript}},
      result => TRUE,
      test   => q{is_file},
    };

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => q{Checking }
        . basename( $input->{cfg}->{flag_file} )
        . q{ exists},
      diag => qq{$c->{red}}
        . basename( $input->{cfg}->{flag_file} )
        . qq{ should exist - investigate!}
        . $c->{clr},
      lval   => qq{$input->{cfg}->{flag_file}},
      result => TRUE,
      test   => q{is_file},
    };

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => q{Checking }
        . basename( $input->{cfg}->{no_op} )
        . q{ doesn't exist},
      diag => qq{$c->{red}}
        . basename( $input->{cfg}->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr},
      lval   => qq{$input->{cfg}->{no_op}},
      result => TRUE,
      test   => q{isnt_file},
    };

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => q{Checking }
        . basename( $input->{cfg}->{testscript} )
        . q{ exists},
      diag => qq{$c->{red}}
        . basename( $input->{cfg}->{testscript} )
        . qq{ should exist - investigate!}
        . $c->{clr},
      lval   => qq{$input->{cfg}->{testscript}},
      result => TRUE,
      test   => q{is_file},
    };

    if ( $input->{cfg}->{disabled} ) {
      print append_spaces( pinwheel()
          . q{ Blacklist is disabled, no further testing required...} );
      return;
    }
  }
  else {
    $blacklist_removed = TRUE;
    print append_spaces( pinwheel()
        . qq{ Blacklist is removed - testing to check its cleanly removed...} );

    # Check for stray files
    $input->{cfg}->{strays}
      = [
      glob
        qq{$input->{cfg}->{dnsmasq_dir}/{domains,zones,hosts}*.blacklist.conf}
      ];

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => q{Checking }
        . basename( $input->{cfg}->{testscript} )
        . q{ removed},
      diag => qq{$c->{red}}
        . basename( $input->{cfg}->{testscript} )
        . qq{ shouldn't exist - investigate!}
        . $c->{clr},
      lval   => qq{$input->{cfg}->{testscript}},
      result => FALSE,
      test   => q{isnt_file},
    };

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => qq{Checking *.blacklist.conf files don't exist},
      diag    => qq{$c->{red} Found @{ $input->{cfg}->{strays} } in }
        . qq{$input->{cfg}->{dnsmasq_dir}/ - they should be deleted!}
        . $c->{clr},
      lval   => scalar( @{ $input->{cfg}->{strays} } ),
      result => TRUE,
      test   => q{isnt},
    };

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => qq{Checking blacklist configure templates don't exist},
      diag =>
        qq{$c->{red} Found $input->{cfg}->{tmplts} - it should be removed!}
        . $c->{clr},
      lval   => $input->{cfg}->{tmplts},
      result => FALSE,
      test   => q{isnt_dir},
    };

    print pinwheel();
    $tests->{ $ikey++ } = {
      comment => qq{Checking Blacklist.pm perl module doesn't exist},
      diag => qq{$c->{red} Found $input->{cfg}->{lib} - it should be removed!}
        . $c->{clr},
      lval   => $input->{cfg}->{lib},
      result => FALSE,
      test   => q{isnt_dir},
    };
  }

  my @areas = @{ get_areas( { cfg => $input->{cfg} } ) };

  for my $area (@areas) {

    print append_spaces( pinwheel() . qq{ Adding tests for $area content...} );

    my %content;
    my @files = @{ get_files( { cfg => $input->{cfg}, area => $area } ) };
    my $ip = $input->{cfg}->{$area}->{dns_redirect_ip};

    if (@files) {
      for my $f_ref (@files) {
        my ( $source, $file ) = @{$f_ref};

        print pinwheel();
        $tests->{ $ikey++ } = {
          comment => qq{$source},
          diag    => qq{$c->{red}}
            . basename($file)
            . qq{ not found for $source - investigate!}
            . $c->{clr},
          lval   => $file,
          result => TRUE,
          test   => q{is_file},
        };
      }

      # Test global and area exclusions
      for my $f_ref (@files) {
        my ( $source, $file ) = @{$f_ref};
        print append_spaces(
          pinwheel() . qq{ Deep scanning content from $area files...} );

        %content = map { ( $_ => 1, tmpkey => print pinwheel(), ) }
          @{ get_file( { file => $file } ) };
        delete $content{tmpkey};
        if ( keys %content ) {
          for my $host ( sort keys %{ $input->{cfg}->{exclude} } ) {
            my @keys = ( qq{address=/.$host/$ip}, qq{address=/$host/$ip} );
            print append_spaces(
              pinwheel() . qq{ Adding global $area $host exclusion tests...} );

            $tests->{ $ikey++ } = {
              comment => qq{Checking "global exclude" $host not in }
                . basename($file),
              diag => qq{$c->{red}}
                . qq{Found "global exclude" $host in }
                . basename($file) . q{!}
                . $c->{clr},
              lval => @keys ~~ %content,
              result => q{},
              test   => q{is},
            };
          }
        }

        for my $host ( sort keys %{ $input->{cfg}->{$area}->{exclude} } ) {
          my @keys = ( qq{address=/.$host/$ip}, qq{address=/$host/$ip} );
          print append_spaces(
            pinwheel() . qq{ Adding tests for $area $host exclusion...} );

          $tests->{ $ikey++ } = {
            comment => qq{Checking "$area exclude" $host not in }
              . basename($file),
            diag => qq{$c->{red}}
              . qq{Found "$area exclude" $host in }
              . basename($file) . q{!}
              . $c->{clr},
            lval => @keys ~~ %content,
            result => q{},
            test   => q{is},
          };
        }

        print append_spaces(
          pinwheel() . qq{ Deep scanning data for $area IP tests...} );

        my $re        = qr{(?:address=[/][.]{0,1}.*[/])(?<IP>.*)};
        my %found_ips = map {
          my $found_ip = $_;
          $found_ip =~ s/$re/$+{IP}/ms;
          $found_ip => 1,
            tmpkey  => print pinwheel(),
        } keys %content;
        delete $found_ips{tmpkey};

        for my $found_ip ( sort keys %found_ips ) {
          print append_spaces(
            pinwheel() . qq{ Adding test for correct IP...} );
          $tests->{ $ikey++ } = {
            comment => qq{IP address $found_ip found in }
              . basename($file)
              . qq{ matches configured $ip},
            diag => qq{$c->{red}}
              . qq{IP address $found_ip found in }
              . basename($file)
              . qq{ doesn't match configured $ip!}
              . $c->{clr},
            lval   => $found_ip,
            op     => q{eq},
            result => TRUE,
            rval   => $ip,
            test   => q{cmp_ok},
          };
        }
      }

      for my $file ( @{ $input->{cfg}->{ $area . q{_pre_f} } } ) {
        %content = map { ( $_ => 1, tmpkey => print pinwheel(), ) }
          @{ get_file( { file => $file } ) };
        delete $content{tmpkey};

        print pinwheel();

        if ( keys %content ) {
          for my $host ( sort keys %{ $input->{cfg}->{$area}->{blklst} } ) {
            my @keys = ( qq{address=/.$host/$ip}, qq{address=/$host/$ip} );

            print append_spaces(
              pinwheel() . qq{ Adding tests for blacklisted $host...} );
            $tests->{ $ikey++ } = {
              comment => qq{Checking "$area include" $host is in }
                . basename($file),
              diag => qq{$c->{red}}
                . qq{"$area include" $host not found in }
                . basename($file)
                . $c->{clr},
              lval => @keys ~~ %content,
              result => TRUE,
              test   => q{is},
            };
          }

          my $address = $area ne q{domains} ? q{address=/} : q{address=/.};
          my @keys = map { my $include = $_; qq{$address$include/$ip} }
            sort keys %{ $input->{cfg}->{$area}->{blklst} };
          print append_spaces( pinwheel() . qq{ Adding additional tests...} );

          $tests->{ $ikey++ } = {
            comment => qq{Checking }
              . basename($file)
              . qq{ only contains "$area include" entries},
            diag => qq{$c->{red}"$area include" has additional entries in }
              . basename($file)
              . qq{ - investigate the following entries:$c->{clr}\n},
            lval    => scalar @content{@keys},
            result  => TRUE,
            run_sub => sub {
              my $re_fqdn = qr{address=[/][.]{0,1}(.*)[/].*}o;
              my %found;
              @found{ keys %content } = ();
              delete @found{@keys};
              my @ufo = sort keys %found;
              for my $alien (@ufo) {
                $alien =~ s/$re_fqdn/$1/ms;
                say(qq{Found: $c->{mag}$alien$c->{clr}});
              }
            },
            test => q{is},
          };
        }
      }
    }
  }

HOST:
  for my $area (@areas) {
    my $ip = $input->{cfg}->{$area}->{dns_redirect_ip};
    print append_spaces(
      pinwheel() . qq{ Scanning $area redirection DNS resolution...} );

    for my $host ( sort keys %{ $input->{cfg}->{$area}->{blklst} } ) {
      $host = q{www.} . $host if $area eq q{domains};
      my $resolved_ip = inet_ntoa( inet_aton($host) ) or next HOST;
      print append_spaces( pinwheel() . qq{ Resolved $host to $resolved_ip} );

      $tests->{ $ikey++ } = {
        comment => qq{Checking $host is redirected by dnsmasq to $ip},
        diag    => qq{$c->{red}}
          . qq{dnsmasq replied with $host = $resolved_ip, should have been }
          . $ip . q{!}
          . $c->{clr},
        lval   => $resolved_ip,
        op     => q{eq},
        result => TRUE,
        rval   => $ip,
        test   => q{cmp_ok},
      };
    }
  }
  say q{};
  return $tests;
}

sub main {
  my $t_count = { tests => 0, failed => 0 };
  my $cfg = {
    dnsmasq_dir => q{/etc/dnsmasq.d},
    failed      => 0,
    flag_file   => q{/var/log/update-dnsmasq-flagged.cmds},
    lib         => q{/config/lib/perl/},
    no_op       => q{/tmp/.update-dnsmasq.no-op},
    tmplts      => q{/opt/vyatta/share/vyatta-cfg/templates/service/dns/}
      . q{forwarding/blacklist/},
    testscript   => q{/config/scripts/blacklist.t},
    updatescript => q{/config/scripts/update-dnsmasq.pl}
  };

  # Get command line options or print help if no valid options
  get_options() || usage( { option => q{help}, exit_code => 1 } );

  usage( { option => q{cfg_file}, exit_code => 1 } )
    if defined $cfg_file && !-f $cfg_file;

  print append_spaces(
    pinwheel() . q{ Testing dnsmasq blacklist configuration} );

  my $planned_tests = get_tests( { cfg => $cfg } );

  $t_count->{tests} = scalar keys %{$planned_tests};

  plan tests => $t_count->{tests};

  for my $key ( 1 .. $t_count->{tests} ) {
    exec_test( { run => $planned_tests->{$key} } ) || $t_count->{failed}++;
  }

  my $t_word = $t_count->{failed} <= 1 ? q{test} : q{tests};
  if ( $t_count->{failed} == 0 && !$blacklist_removed ) {
    say(  qq{$c->{grn}All $t_count->{tests} tests passed - dnsmasq }
        . qq{blacklisting is configured correctly$c->{clr}} );
    return TRUE;
  }
  elsif ( $blacklist_removed && $t_count->{failed} != 0 ) {
    say(  qq{$c->{red} $t_count->{failed} $t_word failed out of }
        . qq{$t_count->{tests} - dnsmasq blacklisting has not been removed }
        . qq{correctly$c->{clr}} );
    return;
  }
  elsif ( $blacklist_removed && $t_count->{failed} == 0 ) {
    say(  qq{$c->{grn}All $t_count->{tests} tests passed - dnsmasq }
        . qq{blacklisting has been completely removed$c->{clr}} );
    return TRUE;
  }
  else {
    say(  qq{$c->{red} $t_count->{failed} $t_word failed out of }
        . qq{$t_count->{tests} - dnsmasq blacklisting is not working correctly}
        . qq{$c->{clr}} );
    return;
  }
}

sub pinwheel {
  my %wheel = ( q{|} => q{/}, q{/} => q{-}, q{-} => q{\\}, q{\\} => q{|}, );

  $spoke = ( not defined $spoke ) ? q{|} : $wheel{$spoke};
  return qq{\r[$c->{ylw}$spoke$c->{clr}]};
}

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
