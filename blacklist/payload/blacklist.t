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
exit 0;
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

    given ($line) {
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
    tests       => 0,
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
    $cfg_ref->{tests} += 3;
    is( -f $cfg_ref->{flag_file},
      TRUE, q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ exists} )
      or diag(
      basename( $cfg_ref->{flag_file} ) . qq{ should exist - investigate!} );
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( basename( $cfg_ref->{no_op} ) . qq{ found - investigate!} );
    is( -f $cfg_ref->{testscript},
      TRUE, q{Checking } . basename( $cfg_ref->{testscript} ) . q{ exists} )
      or diag(
      basename( $cfg_ref->{testscript} ) . qq{ should exist - investigate!} );
  }
  elsif ( exists $cfg_ref->{blacklist}->{disabled}
    && !$cfg_ref->{blacklist}->{disabled} )
  {
    $cfg_ref->{tests} += 3;
    is( -f $cfg_ref->{flag_file},
      TRUE, q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ exists} )
      or diag(
      basename( $cfg_ref->{flag_file} ) . qq{ should exist - investigate!} );
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( basename( $cfg_ref->{no_op} ) . qq{ found - investigate!} );
    is( -f $cfg_ref->{testscript},
      TRUE, q{Checking } . basename( $cfg_ref->{testscript} ) . q{ exists} )
      or diag(
      basename( $cfg_ref->{testscript} ) . qq{ should exist - investigate!} );
  }
  else {
    $cfg_ref->{tests} += 3;
    isnt( -f $cfg_ref->{flag_file},
      TRUE,
      q{Checking } . basename( $cfg_ref->{flag_file} ) . q{ doesn't exist} )
      or diag( basename( $cfg_ref->{flag_file} ) . qq{ found - investigate!} );
    isnt( -f $cfg_ref->{no_op},
      TRUE, q{Checking } . basename( $cfg_ref->{no_op} ) . q{ doesn't exist} )
      or diag( basename( $cfg_ref->{no_op} ) . qq{ found - investigate!} );
    isnt( -f $cfg_ref->{testscript},
      TRUE,
      q{Checking } . basename( $cfg_ref->{testscript} ) . q{ doesn't exist} )
      or diag( basename( $cfg_ref->{testscript} ) . qq{ found - investigate!} );
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
          $cfg_ref->{tests}++;
          is( -f $file, TRUE, qq{Checking $source has a file} )
            or
            diag( basename($file) . qq{ not found for $source - investigate!} );
        }

        # Test global and area exclusions
        for my $file ( @{ $cfg_ref->{ $area . q{_f} } } ) {
          my $content = get_file( { file => $file } );
          for my $host ( @{ $cfg_ref->{global_ex} } ) {
            my $re = qr{address=[/][.]{0,1}$host[/]$ip};
            $cfg_ref->{tests}++;
            is( $re ~~ @{$content},
              q{},
              qq{Checking 'global exclude' $host not in } . basename($file) )
              or diag(
              qq{Found 'global exclude' $host in } . basename($file) . q{ !} );
          }
          for my $host ( @{ $cfg_ref->{ $area . q{_ex} } } ) {
            my $re = qr{address=[/][.]{0,1}$host[/]$ip};
            $cfg_ref->{tests}++;
            is( $re ~~ @{$content},
              q{},
              qq{Checking '$area exclude' $host not in } . basename($file) )
              or diag(
              qq{Found '$area exclude' $host in } . basename($file) . q{ !} );
          }
        }

        for my $file ( @{ $cfg_ref->{ $area . q{_pre_f} } } ) {
          my $content = get_file( { file => $file } );
          for my $host ( keys %{ $cfg_ref->{blacklist}->{$area}->{blklst} } ) {
            $cfg_ref->{tests}++;
            my $re = qr{address=[/][.]{0,1}$host[/]$ip};
            is(
              $re ~~ @{$content},
              TRUE,
              qq{Checking '$area include' $host is in }
                . basename($file)
                . qq{ with IP: $ip}
              )
              or diag( qq{'$area include' $host not found in }
                . basename($file)
                . qq{ with IP: $ip} );
          }
        }
      }
    }
  }
  done_testing( $cfg_ref->{tests} );
  say;
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
