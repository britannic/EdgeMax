package EdgeOS::DNS::Blacklist;

use v5.14;
use EdgeOS::DNS::Blacklist;
use File::Basename;
use Getopt::Long;
use HTTP::Tiny;
use lib q{/opt/vyatta/share/perl5/};
use POSIX qw{geteuid};
use strict;
use Sys::Syslog qw(:standard :macros);
use Term::ReadKey qw(GetTerminalSize);
use threads;
use URI;
use Vyatta::Config;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration use EdgeOS::DNS::Blacklist ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
# our %EXPORT_TAGS = ( 'all' => [qw()] );
our @EXPORT_OK = (
  qw{
    delete_file
    get_cfg_actv
    get_cfg_file
    get_file
    get_url
    is_admin
    is_configure
    log_msg
    popx
    process_data
    pushx
    usage
    write_file
    }
);
our @EXPORT  = ();
our $VERSION = '1.01';

# Preloaded methods go here.
our $c = {
  off => qq{\033[?25l},
  on  => qq{\033[?25h},
  clr => qq{\033[0m},
  grn => qq{\033[92m},
  mag => qq{\033[95m},
  red => qq{\033[91m},
};

# Process the active (not committed or saved) configuration
sub get_cfg_actv {
  my $config       = new Vyatta::Config;
  my $input        = shift;
  my $exists       = q{existsOrig};
  my $listNodes    = q{listOrigNodes};
  my $returnValue  = q{returnOrigValue};
  my $returnValues = q{returnOrigValues};

  if ( is_configure() ) {
    $exists       = q{exists};
    $listNodes    = q{listNodes};
    $returnValue  = q{returnValue};
    $returnValues = q{returnValues};
  }

# Check to see if blacklist is configured
  $config->setLevel(q{service dns forwarding});
  my $blklst_exists = $config->$exists(q{blacklist}) ? TRUE : FALSE;

  if ($blklst_exists) {
    $config->setLevel(q{service dns forwarding blacklist});
    $input->{config}->{disabled} = $config->$returnValue(q{disabled}) // FALSE;
    $input->{config}->{dns_redirect_ip}
      = $config->$returnValue(q{dns-redirect-ip}) // q{0.0.0.0};

    for my $key ( $config->$returnValues(q{exclude}) ) {
      $input->{config}->{exclude}->{$key} = 1;
    }

    $input->{config}->{disabled}
      = $input->{config}->{disabled} eq q{false} ? FALSE : TRUE;

    for my $area (qw{hosts domains zones}) {
      $config->setLevel(qq{service dns forwarding blacklist $area});
      $input->{config}->{$area}->{dns_redirect_ip}
        = $config->$returnValue(q{dns-redirect-ip})
        // $input->{config}->{dns_redirect_ip};

      for my $key ( $config->$returnValues(q{include}) ) {
        $input->{config}->{$area}->{blklst}->{$key} = 1;
      }

      while ( my ( $key, $value ) = each $input->{config}->{exclude} ) {
        $input->{config}->{$area}->{exclude}->{$key} = $value;
      }

      for my $key ( $config->$returnValues(q{exclude}) ) {
        $input->{config}->{$area}->{exclude}->{$key} = 1;
      }

      if ( !keys %{ $input->{config}->{$area}->{exclude} } ) {
        $input->{config}->{$area}->{exclude} = {};
      }

      if ( !keys %{ $input->{config}->{exclude} } ) {
        $input->{config}->{exclude} = {};
      }

      for my $source ( $config->$listNodes(q{source}) ) {
        $config->setLevel(
          qq{service dns forwarding blacklist $area source $source});
        @{ $input->{config}->{$area}->{src}->{$source} }{qw(prefix url)}
          = ( $config->$returnValue(q{prefix}), $config->$returnValue(q{url}) );
      }
    }
  }
  else {
    $show = TRUE;
    log_msg(
      {
        msg_typ => q{error},
        msg_str =>
          q{[service dns forwarding blacklist is not configured], exiting!},
      }
    );

    return;
  }
  if ( ( !scalar keys %{ $input->{config}->{domains}->{src} } )
    && ( !scalar keys %{ $input->{config}->{hosts}->{src} } )
    && ( !scalar keys %{ $input->{config}->{zones}->{src} } ) )
  {
    $show = TRUE;
    log_msg(
      {
        msg_ref => q{error},
        msg_str => q{At least one domain or host source must be configured},
      }
    );
    return;
  }
  return TRUE;
}

# Process a configuration file in memory after get_file() loads it
sub get_cfg_file {
  my $input = shift;
  my $tmp_ref
    = get_nodes( { config_data => get_file( { file => $cfg_file } ) } );
  my $configured
    = (  $tmp_ref->{domains}->{source}
      || $tmp_ref->{hosts}->{source}
      || $tmp_ref->{zones}->{source} ) ? TRUE : FALSE;

  if ($configured) {
    $input->{config}->{dns_redirect_ip} = $tmp_ref->{q{dns-redirect-ip}}
      // q{0.0.0.0};
    $input->{config}->{disabled}
      = $tmp_ref->{disabled} eq q{false} ? FALSE : TRUE;
    $input->{config}->{exclude}
      = exists $tmp_ref->{exclude} ? $tmp_ref->{exclude} : ();

    for my $area (qw{hosts domains zones}) {
      $input->{config}->{$area}->{dns_redirect_ip}
        = $input->{config}->{dns_redirect_ip}
        if !exists( $tmp_ref->{$area}->{q{dns-redirect-ip}} );

      @{ $input->{config}->{$area} }{qw(blklst exclude src)}
        = @{ $tmp_ref->{$area} }{qw(include exclude source)};

      while ( my ( $key, $value ) = each %{ $tmp_ref->{$area}->{exclude} } ) {
        $input->{config}->{$area}->{exclude}->{$key} = $value;
      }
    }
  }
  else {
    log_msg(
      {
        msg_typ => q{error},
        msg_str =>
          q{[service dns forwarding blacklist] isn't configured, exiting!},
      }
    );
    return;
  }
  return TRUE;
}

# Remove previous configuration files
sub delete_file {
  my $input = shift;

  if ( -f $input->{file} ) {
    log_msg(
      {
        msg_typ => q{info},
        msg_str => sprintf q{Deleting file %s},
        $input->{file},
      }
    );
    unlink $input->{file};
  }

  if ( -f $input->{file} ) {
    log_msg(
      {
        msg_typ => q{warning},
        msg_str => sprintf q{Unable to delete %s},
        $input->{file},
      }
    );
    return;
  }
  return TRUE;
}

# Read a file into memory and return the data to the calling function
sub get_file {
  my $input = shift;
  my @data  = ();
  if ( -f $input->{file} ) {
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

LINE:
  for my $line ( @{ $input->{config_data} } ) {
    $line =~ s/$re->{LSPC}//;
    $line =~ s/$re->{RSPC}//;

    for ($line) {
      when (/$re->{MULT}/) {
        push @nodes, $+{MULT};
        push @nodes, $+{VALU};
        push @nodes, 1;
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( { array => \@nodes, X => 3 } );
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
        popx( { array => \@nodes, X => 2 } );
      }
      when (/$re->{DESC}/) {
        push @nodes, $+{NAME};
        push @nodes, $+{DESC};
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( { array => \@nodes, X => 2 } );
      }
      when (/$re->{MISC}/) {
        pushx( { array => \@nodes, items => \$+{MISC}, X => 2 } );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( { array => \@nodes, X => 2 } );
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
        next LINE;
      }
      default {
        printf q{Parse error: "%s"}, $line;
      }
    }
  }
  return $cfg_ref->{service}->{dns}->{forwarding}->{blacklist};
}

# Get lists from web servers
sub get_url {
  my $input = shift;
  my $ua    = HTTP::Tiny->new;
  $ua->agent(
    q{Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56}
  );

#   $ua->timeout(60);
  $input->{prefix} =~ s/^["](?<UNCMT>.*)["]$/$+{UNCMT}/g;
  my $re = {
    REJECT => qr{\A#|\A\z|\A\n}oms,
    SELECT => qr{\A $input->{prefix} .*\z}xoms,
    SPLIT  => qr{\R|<br \/>}oms,
  };

  my $get = $ua->get( $input->{url} );

  if ( $get->{success} ) {
    $input->{data} = {
      map { my $key = $_; lc($key) => 1 }
        grep { $_ =~ /$re->{SELECT}/ } split /$re->{SPLIT}/,
      $get->{content}
    };
    return $input;
  }
  else {
    $input->{data} = {};
    return $input;
  }
}

# Check to see if we are being run under configure
sub is_configure {
  qx{/bin/cli-shell-api inSession};
  return $? >> 8 != 0 ? FALSE : TRUE;
}

# Make sure script runs as root
sub is_admin {
  return TRUE if geteuid() == 0;
  return;
}

# Log and print (if -v)
sub log_msg {
  my $msg_ref = shift;
  my $log_msg = {
    alert    => LOG_ALERT,
    critical => LOG_CRIT,
    debug    => LOG_DEBUG,
    error    => LOG_ERR,
    info     => LOG_NOTICE,
    warning  => LOG_WARNING,
  };

  return unless ( length $msg_ref->{msg_typ} . $msg_ref->{msg_str} > 2 );

  syslog( $log_msg->{ $msg_ref->{msg_typ} },
    qq{$msg_ref->{msg_typ}: } . $msg_ref->{msg_str} );

  print $c->{off}, qq{\r}, q{ } x $cols, qq{\r} if $show;

  if ( $msg_ref->{msg_typ} eq q{info} ) {
    print $c->{off}, qq{$msg_ref->{msg_typ}: $msg_ref->{msg_str}} if $show;
  }
  else {
    print STDERR $c->{off}, $c->{red},
      qq{$msg_ref->{msg_typ}: $msg_ref->{msg_str}$c->{clr}}
      if $show;
  }

  return TRUE;
}

# pop array x times
sub popx {
  my $input = shift;
  return if !$input->{X};
  for ( 1 .. $input->{X} ) {
    pop @{ $input->{array} };
  }
  return TRUE;
}

# Crunch the data and throw out anything we don't need
sub process_cfg {
  my $input = shift;
  my $re    = {
    FQDOMN =>
      qr{(\b(?:(?![.]|-)[\w-]{1,63}(?<!-)[.]{1})+(?:[a-zA-Z]{2,63})\b)}o,
    LSPACE => qr{\A\s+}oms,
    RSPACE => qr{\s+\z}oms,
    PREFIX => qr{\A $input->{prefix} }xms,
    SUFFIX => qr{(?:#.*\z|\{.*\z|[/[].*\z)}oms,
  };

  # Clear the status lines
  print $c->{off}, qq{\r}, qq{ } x $cols, qq{\r} if $show;

# Process the lines we've been given
LINE:
  for my $line ( keys %{ $input->{data} } ) {
    next LINE if $line eq q{} || !defined $line;
    $line =~ s/$re->{PREFIX}//;
    $line =~ s/$re->{SUFFIX}//;
    $line =~ s/$re->{LSPACE}//;
    $line =~ s/$re->{RSPACE}//;

    # Get all of the FQDNs or domains in the line
    my @elements = $line =~ m/$re->{FQDOMN}/gc;
    next LINE if !scalar @elements;

    # We use map to individually pull 1 to N FQDNs or domains from @elements
    for my $element (@elements) {

      # Break it down into it components
      my @domain = split /[.]/, $element;

      # Create an array of all the subdomains
      my @keys;
      for ( 2 .. @domain ) {
        push @keys, join q{.}, @domain;
        shift @domain;
      }

      # Have we seen this key before?
      my $key_exists = FALSE;
      for my $key (@keys) {
        if ( exists $input->{config}->{ $input->{area} }->{exclude}->{$key} ) {
          $key_exists = TRUE;
          $input->{config}->{ $input->{area} }->{exclude}->{$key}++;
        }
      }

      # Now add the key, convert to .domain.tld if only two elements
      if ( !$key_exists ) {
        $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
          ->{blklst}->{$element} = 1;
      }
      else {
        $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
          ->{duplicates}++;
      }

      # Add to the exclude list, so the next source doesnt duplicate values
      $input->{config}->{ $input->{area} }->{exclude}->{$element} = 1;
    }

    $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }->{icount}
      += scalar @elements;

    printf
      qq{$c->{off}%s: $c->{grn}%s$c->{clr} %s processed, ($c->{red}%s$c->{clr} discarded) from $c->{mag}%s$c->{clr} lines\r},
      $input->{src},
      $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }->{icount},
      $input->{config}->{ $input->{area} }->{type},
      @{ $input->{config}->{ $input->{area} }->{src}->{ $input->{src} } }
      { q{duplicates}, q{records} }
      if $show;
  }

  if (
    scalar $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
    ->{icount} )
  {
    log_msg(
      {
        msg_typ => q{info},
        msg_str => sprintf
          qq{%s: %s %s processed, (%s duplicates) from %s lines\r},
        $input->{src},
        $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
          ->{icount}, $input->{config}->{ $input->{area} }->{type},
        @{ $input->{config}->{ $input->{area} }->{src}->{ $input->{src} } }
          { q{duplicates}, q{records} },
      }
    );
    return TRUE;
  }
  return;
}

# push array x times
sub pushx {
  my $input = shift;
  return if !$input->{X};
  for ( 1 .. $input->{X} ) {
    push @{ $input->{array} }, $input->{items};
  }
  return TRUE;
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
    sudo => sub {
      my $exitcode = shift;
      print STDERR qq{This script must be run as root, use: sudo $0.\n};
      exit $exitcode;
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

# Write the data to file
sub write_file {
  my $input = shift;

  return if !@{ $input->{data} };

  open my $FH, q{>}, $input->{file} or return;
  log_msg(
    {
      msg_typ => q{info},
      msg_str => sprintf q{Saving %s},
      basename( $input->{file} ),
    }
  );

  print {$FH} @{ $input->{data} };

  close $FH;

  return TRUE;
}

1;
__END__

=head1 Blacklist

EdgeOS::DNS::Blacklist - Perl extension for EdgeOS dnsmasq blacklist configuration file generation

=head1 SYNOPSIS

  use EdgeOS::DNS::Blacklist (qw{
  delete_file
  get_cfg_actv
  get_cfg_file
  get_file
  get_url
  is_admin
  is_configure
  log_msg
  popx
  process_data
  pushx
  usage
  write_file});

=head1 DESCRIPTION

Module provides functions for creating dnsmasq configuration files to redirect
dns look ups to alternative IPs (blackholes, pixel servers etc.)

=head2 EXPORT

None by default.

=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.


If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Neil Beadle, E<lt>blacklist@empirecreekcircle.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Neil Beadle

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.23.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
