#!/usr/bin/env perl
#

use File::Basename;
use feature qw{switch};
use Getopt::Long;
use strict;
use Test::More;
use v5.14;
use warnings;

# no warnings 'experimental::smartmatch';

use constant TRUE  => 1;
use constant FALSE => 0;

my $version  = q{1.0};
my $cfg_file = q{/config/config.boot};
my $t_count  = { tests => 0, failed => 0 };
my $crsr     = {
  off            => qq{\033[?25l},
  on             => qq{\033[?25h},
  clear          => qq{\033[0m},
  reset          => qq{\033[0m},
  bright_green   => qq{\033[92m},
  bright_magenta => qq{\033[95m},
  bright_red     => qq{\033[91m},
};

########## Run main ###########
&main();
if ( $t_count->{failed} == 0 ) {
  say(  qq{$crsr->{bright_green}All $t_count->{tests} tests passed - dnsmasq }
      . qq{blacklisting is configured correctly$crsr->{clear}} );
  exit 0;
}
my $t_word = $t_count->{failed} <= 1 ? q{test} : q{tests};
say(  qq{$crsr->{bright_red} $t_count->{failed} $t_word failed out of }
    . qq{$t_count->{tests} - dnsmasq blacklisting is not working correctly}
    . qq{$crsr->{clear}} );
exit 1;
##########   exit   ###########

# Read a file into memory and return the data to the calling function
sub get_file {
  my $input = shift;
  my @data  = ();
  if ( exists $input->{file} ) {
    open my $CF, q{<}, $input->{file}
      or die qq{error: Unable to open $input->{file}: $!};
    chomp( @data = <$CF> );

    close $CF;
  }
  return $input->{data} = \@data;
}

# Build hashes from the configuration file data (called by get_nodes())
sub get_hash {
  my $input    = shift;
  my $hash     = \$input->{hash_ref};
  my @nodes    = @{ $input->{nodes} };
  my $value    = pop @nodes;
  my $hash_ref = ${$hash};

  for my $key (@nodes) {
    $hash = \${$hash}->{$key};
  }

  ${$hash} = $value if $value;

  return $hash_ref;
}

# Process a configure file and extract the blacklist data set
sub get_nodes {
  my $input = shift;
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

  for my $line ( @{ $input->{config_data} } ) {
    $line =~ s/$re->{LSPC}//;
    $line =~ s/$re->{RSPC}//;

    for ($line) {
      when (/$re->{MULT}/) {
        push @nodes, $+{MULT};
        push @nodes, $+{VALU};
        push @nodes, 1;
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop @nodes;
        pop @nodes;
        pop @nodes;
      }
      when (/$re->{NODE}/) {
        push @nodes, $+{NODE};
      }
      when (/$re->{LEAF}/) {
        $level++;
        push @nodes, $+{LEAF};
        push @nodes, $+{NAME};
      }
      when (/$re->{NAME}/) {
        push @nodes, $+{NAME};
        push @nodes, $+{VALU};
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop @nodes;
        pop @nodes;
      }
      when (/$re->{DESC}/) {
        push @nodes, $+{NAME};
        push @nodes, $+{DESC};
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop @nodes;
        pop @nodes;
      }
      when (/$re->{MISC}/) {
        push @nodes, $+{MISC};
        push @nodes, $+{MISC};
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop @nodes;
        pop @nodes;
      }
      when (/$re->{CMNT}/) {
        next;
      }
      when (/$re->{BRKT}/) {
        pop @nodes;
        if ( $level > 0 ) {
          pop @nodes;
          $level--;
        }
      }
      when (/$re->{MPTY}/) {
        next;
      }
      default {
        printf q{Parse error: "%s"}, $line;
      }
    }
  }
  return $cfg_ref->{service}->{dns}->{forwarding};
}

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

  return \@opts if $input->{'option'};

  # Read command line flags and exit with help message if any are unknown
  return GetOptions( map { my $options = $_; (@$options)[ 1 .. $#$options ] }
      @opts );
}

# Main script
sub main {
  my $cfg_ref = {
    dnsmasq_dir => q{/etc/dnsmasq.d},
    flag_file   => q{/var/log/update-dnsmasq-flagged.cmds},
    no_op       => q{/tmp/.update-dnsmasq.no-op},
    testscript  => q{/config/scripts/blacklist.t},
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
    $t_count->{tests} += 3;
    is( -f $cfg_ref->{flag_file},
      TRUE, q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ exists} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{flag_file} )
        . qq{ should exist - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{no_op} )
        . qq{ found - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
    is( -f $cfg_ref->{testscript},
      TRUE, q{Checking } . basename( $cfg_ref->{testscript} ) . q{ exists} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{testscript} )
        . qq{ should exist - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
  }
  elsif ( exists $cfg_ref->{blacklist}->{disabled}
    && !$cfg_ref->{blacklist}->{disabled} )
  {
    $t_count->{tests} += 3;
    is( -f $cfg_ref->{flag_file},
      TRUE, q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ exists} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{flag_file} )
        . qq{ should exist - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{no_op} )
        . qq{ found - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
    is( -f $cfg_ref->{testscript},
      TRUE, q{Checking } . basename( $cfg_ref->{testscript} ) . q{ exists} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{testscript} )
        . qq{ should exist - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
  }
  else {
    $t_count->{tests} += 3;
    isnt( -f $cfg_ref->{flag_file},
      TRUE,
      q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ doesn't exist} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{flag_file} )
        . qq{ found - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{no_op} )
        . qq{ found - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
    isnt( -f $cfg_ref->{testscript},
      TRUE,
      q{Checking } . basename( $cfg_ref->{testscript} ) . q{ doesn't exist} )
      or diag( qq{$crsr->{bright_red}}
        . basename( $cfg_ref->{testscript} )
        . qq{ found - investigate!}
        . $crsr->{clear} ), $t_count->{failed}++;
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
            or diag( qq{$crsr->{bright_red}}
              . basename($file)
              . qq{ not found for $source - investigate!}
              . $crsr->{clear} ), $t_count->{failed}++;
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
              or diag( qq{$crsr->{bright_red}}
                . qq{Found "global exclude" $host in }
                . basename($file) . q{!}
                . $crsr->{clear} ), $t_count->{failed}++;
          }
          for my $host ( @{ $cfg_ref->{ $area . q{_ex} } } ) {
            my $re = qr{address=[/][.]{0,1}$host[/].*};
            $t_count->{tests}++;
            is( $re ~~ @{$content},
              q{},
              qq{Checking "$area exclude" $host not in } . basename($file) )
              or diag( qq{$crsr->{bright_red}}
                . qq{Found "$area exclude" $host in }
                . basename($file) . q{!}
                . $crsr->{clear} ), $t_count->{failed}++;
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
              or diag( qq{$crsr->{bright_red}}
                . qq{IP address $found_ip found in }
                . basename($file)
                . qq{ doesn't match configured $ip!}
                . $crsr->{clear} ), $t_count->{failed}++;
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
              or diag( qq{$crsr->{bright_red}}
                . qq{"$area include" $host not found in }
                . basename($file)
                . $crsr->{clear} ), $t_count->{failed}++;
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
            diag( qq{$crsr->{bright_red}}
                . qq{"$area include" has additional entries in }
                . basename($file)
                . qq{ investigate the following entries:$crsr->{clear}} );
            my $re_fqdn = qr{address=[/][.]{0,1}(.*)[/].*}o;
            my %found   = ();
            @found{ @{$content} } = ();
            delete @found{@includes};
            my @ufo = keys %found;
            for my $alien (@ufo) {
              $alien =~ s/$re_fqdn/$1/ms;
              say(qq{Found: $crsr->{bright_magenta}$alien$crsr->{clear}});
            }
          }
        }
      }
    }
  }
  done_testing( $t_count->{tests} );
}

# Process a configuration file in memory after get_file() loads it
sub process_cfg {
  my $input = shift;
  my $tmp_ref = get_nodes( { config_data => $input->{data} } );
  my $configured
    = (  $tmp_ref->{blacklist}->{domains}->{source}
      || $tmp_ref->{blacklist}->{hosts}->{source}
      || $tmp_ref->{blacklist}->{zones}->{source} ) ? TRUE : FALSE;

  if ($configured) {
    $input->{config}->{blacklist}->{dns_redirect_ip}
      = $tmp_ref->{blacklist}->{q{dns-redirect-ip}} // q{0.0.0.0};
    $input->{config}->{blacklist}->{disabled}
      = $tmp_ref->{blacklist}->{disabled} eq q{false} ? FALSE : TRUE;
    $input->{config}->{blacklist}->{exclude}
      = exists $tmp_ref->{blacklist}->{exclude}
      ? $tmp_ref->{blacklist}->{exclude}
      : ();

    for my $area (qw{hosts domains zones}) {
      $input->{config}->{blacklist}->{$area}->{dns_redirect_ip}
        = $input->{config}->{blacklist}->{dns_redirect_ip}
        if !exists( $tmp_ref->{blacklist}->{$area}->{'dns-redirect-ip'} );

      @{ $input->{config}->{blacklist}->{$area} }{qw(blklst exclude src)}
        = @{ $tmp_ref->{blacklist}->{$area} }{qw(include exclude source)};

      while ( my ( $key, $value )
        = each %{ $tmp_ref->{blacklist}->{$area}->{exclude} } )
      {
        $input->{config}->{blacklist}->{$area}->{exclude}->{$key} = $value;
      }
    }
    return TRUE;
  }
  return;
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
