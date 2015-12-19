# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl EdgeOS-DNS-Blacklist.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More;
BEGIN { use_ok('EdgeOS::DNS::Blacklist') }

#########################

use v5.14;
use File::Basename;
use Getopt::Long;
use EdgeOS::DNS::Blacklist (
  qw{get_file
    get_hash
    get_nodes
    get_options
    main
    popx
    process_cfg
    pushx}
);
use constant TRUE  => 1;
use constant FALSE => 0;

my $version  = q{1.0};
my $cfg_file = q{/config/config.boot};
my $t_count  = { tests => 0, failed => 0 };
my $blacklist_removed;

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
  my $cfg_ref = {
    dnsmasq_dir  => q{/etc/dnsmasq.d},
    flag_file    => q{/var/log/update-dnsmasq-flagged.cmds},
    no_op        => q{/tmp/.update-dnsmasq.no-op},
    testscript   => q{/config/scripts/blacklist.t},
    updatescript => q{/config/scripts/update-dnsmasq.pl}
  };

  # Get command line options or print help if no valid options
  get_options() || usage( { option => q{help}, exit_code => 1 } );

  usage( { option => q{cfg_file}, exit_code => 1 } ) if !-f $cfg_file;

  #Process the configuration file into a hash ref
  process_cfg(
    { config => $cfg_ref, data => get_file( { file => $cfg_file } ) } );

  $cfg_ref->{domains_pre_f}
    = [ glob qq{$cfg_ref->{dnsmasq_dir}/domains.pre*blacklist.conf} ];
  $cfg_ref->{hosts_pre_f}
    = [ glob qq{$cfg_ref->{dnsmasq_dir}/hosts.pre*blacklist.conf} ];
  $cfg_ref->{zones_pre_f}
    = [ glob qq{$cfg_ref->{dnsmasq_dir}/zones.pre*blacklist.conf} ];
  $cfg_ref->{global_ex} = [ keys %{ $cfg_ref->{blacklist}->{exclude} } ];

  # If blacklist is disabled - check it really is
  if ( exists $cfg_ref->{blacklist}->{disabled}
    && $cfg_ref->{blacklist}->{disabled} )
  {
    $t_count->{tests} += 4;
    is( -f $cfg_ref->{updatescript},
      TRUE, q{Checking } . basename( $cfg_ref->{updatescript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg_ref->{flag_file},
      TRUE, q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{flag_file} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg_ref->{testscript},
      TRUE, q{Checking } . basename( $cfg_ref->{testscript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{testscript} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
  }
  elsif ( exists $cfg_ref->{blacklist}->{disabled}
    && !$cfg_ref->{blacklist}->{disabled} )
  {
    $t_count->{tests} += 4;
    is( -f $cfg_ref->{updatescript},
      TRUE, q{Checking } . basename( $cfg_ref->{updatescript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg_ref->{flag_file},
      TRUE, q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{flag_file} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    is( -f $cfg_ref->{testscript},
      TRUE, q{Checking } . basename( $cfg_ref->{testscript} ) . q{ exists} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{testscript} )
        . qq{ should exist - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
  }
  else {
    $blacklist_removed = TRUE;
    $t_count->{tests} += 5;
    isnt( -f $cfg_ref->{updatescript},
      TRUE,
      q{Checking } . basename( $cfg_ref->{updatescript} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{updatescript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{flag_file},
      TRUE,
      q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{flag_file} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{no_op} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{testscript},
      TRUE,
      q{Checking } . basename( $cfg_ref->{testscript} ) . q{ doesn't exist} )
      or diag( qq{$c->{red}}
        . basename( $cfg_ref->{testscript} )
        . qq{ found - investigate!}
        . $c->{clr} ), $t_count->{failed}++;

    # Check for stray files
    $cfg_ref->{strays} = [
      glob qq{$cfg_ref->{dnsmasq_dir}/{domains,zones,hosts}*.blacklist.conf} ];
    my $no_strays = isnt( scalar( @{ $cfg_ref->{strays} } ),
      TRUE, qq{Checking *.blacklist.conf files not found in /etc/dnsmasq.d/} )
      or diag( qq{$c->{red} Found blacklist configuration files in }
        . qq{$cfg_ref->{dnsmasq_dir}/ - they should be deleted!}
        . $c->{clr} ), $t_count->{failed}++;
    if ( !$no_strays ) {
      say(qq{The following files were found in $cfg_ref->{dnsmasq_dir}/:});
      for ( @{ $cfg_ref->{strays} } ) {
        say;
      }
    }
    done_testing( $t_count->{tests} );
    return TRUE;
  }

  # Add areas to process only if they contain sources
  for my $area (qw{domains zones hosts}) {
    my $ip = $cfg_ref->{blacklist}->{$area}->{dns_redirect_ip};
    $cfg_ref->{ $area . q{_ex} }
      = [ keys %{ $cfg_ref->{blacklist}->{$area}->{exclude} } ];
    if ( exists $cfg_ref->{blacklist}->{$area}->{src} ) {
      my @sources = keys %{ $cfg_ref->{blacklist}->{$area}->{src} };
      for my $source (@sources) {
        $cfg_ref->{ $area . q{_f} }
          = [qq{$cfg_ref->{dnsmasq_dir}/$area.$source.blacklist.conf}];
        for my $file ( @{ $cfg_ref->{ $area . q{_f} } } ) {
          $t_count->{tests}++;
          is( -f $file, TRUE, qq{Checking $source has a file} )
            or diag( qq{$c->{red}}
              . basename($file)
              . qq{ not found for $source - investigate!}
              . $c->{clr} ), $t_count->{failed}++;
        }

        # Test global and area exclusions
        for my $file ( @{ $cfg_ref->{ $area . q{_f} } } ) {
          my $content = get_file( { file => $file } );
          for my $host ( @{ $cfg_ref->{global_ex} } ) {
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
          for my $host ( @{ $cfg_ref->{ $area . q{_ex} } } ) {
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
          for my $found_ip ( keys %found_ips ) {
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

        for my $file ( @{ $cfg_ref->{ $area . q{_pre_f} } } ) {
          my $content = get_file( { file => $file } );
          for my $host ( keys %{ $cfg_ref->{blacklist}->{$area}->{blklst} } ) {
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
            @{ [ sort keys %{ $cfg_ref->{blacklist}->{$area}->{blklst} } ] };
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
            my @ufo = keys %found;
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

