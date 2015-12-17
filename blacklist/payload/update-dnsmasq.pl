#!/usr/bin/env perl
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# A copy of the GNU General Public License is available as
# '/usr/share/common-licenses/GPL' in the Debian GNU/Linux distribution
# or on the World Wide Web at `http://www.gnu.org/copyleft/gpl.html'.
# You can also obtain it by writing to the Free Software Foundation,
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# Author: Neil Beadle
# Date:   December 2015
# Description: Script for creating dnsmasq configuration files to redirect dns
# look ups to alternative IPs (blackholes, pixel servers etc.)
#
# **** End License ****

# use Data::Dumper;
use feature qw{switch};
use File::Basename;
use Getopt::Long;
use HTTP::Tiny;
use lib q{/opt/vyatta/share/perl5/};
use POSIX qw{geteuid};
use strict;
use Sys::Syslog qw(:standard :macros);
use threads;
use URI;
use v5.14;
use Vyatta::Config;
use warnings;

use constant TRUE  => 1;
use constant FALSE => 0;

my $version = q{3.5};
my $cols    = qx{tput cols};
my $crsr    = {
  off            => qq{\033[?25l},
  on             => qq{\033[?25h},
  clear          => qq{\033[0m},
  reset          => qq{\033[0m},
  bright_green   => qq{\033[92m},
  bright_magenta => qq{\033[95m},
  bright_red     => qq{\033[91m},
};
my ( $cfg_file, $show );

############################### script runs here ###############################
&main();

# Exit normally
exit 0;
################################################################################

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

# Set up command line options
sub get_options {
  my $input = shift;
  my @opts  = (
    [ q{-f <file> # load a configuration file}, q{f=s} => \$cfg_file ],
    [
      q{-help     # show help and usage text},
      q{help} => sub { usage( { option => q{help}, exit_code => 0 } ) }
    ],
    [ q{-v        # verbose output}, q{v} => \$show ],
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
    info     => LOG_INFO,
    warning  => LOG_WARNING,
  };

  return unless ( length $msg_ref->{msg_typ} . $msg_ref->{msg_str} > 2 );

  syslog( $log_msg->{ $msg_ref->{msg_typ} }, $msg_ref->{msg_str} );

  print $crsr->{off}, qq{\r}, q{ } x $cols, qq{\r} if $show;

  if ( $msg_ref->{msg_typ} eq q{info} ) {
    print $crsr->{off}, qq{$msg_ref->{msg_typ}: $msg_ref->{msg_str}} if $show;
  }
  else {
    print STDERR $crsr->{off}, $crsr->{bright_red},
      qq{$msg_ref->{msg_typ}: $msg_ref->{msg_str}$crsr->{reset}}
      if $show;
  }

  return TRUE;
}

# This is the main function
sub main {
  my $dnsmasq_svc = q{/etc/init.d/dnsmasq};
  my $cfg_ref     = {
    disabled    => 0,
    dnsmasq_dir => q{/etc/dnsmasq.d},
    flag_lvl    => 5,
    flag_file   => q{/var/log/update-dnsmasq-flagged.cmds},
    log_name    => q{update-dnsmasq},
    no_op       => q{/tmp/.update-dnsmasq.no-op},
    domains     => {
      duplicates => 0,
      icount     => 0,
      records    => 0,
      target     => q{address},
      type       => q{domains},
      unique     => 0,
    },
    hosts => {
      duplicates => 0,
      icount     => 0,
      records    => 0,
      target     => q{address},
      type       => q{hosts},
      unique     => 0,
    },
    zones => {
      duplicates => 0,
      icount     => 0,
      records    => 0,
      target     => q{server},
      type       => q{zones},
      unique     => 0,
    },
  };

  # Get command line options or print help if no valid options
  get_options() || usage( { option => q{help}, exit_code => 1 } );

  # Find reasons to quit
  # If the no_op file exists, exit.
  exit 0 if ( -f $cfg_ref->{no_op} );

  usage( { option => q{sudo}, exit_code => 1 } ) if not is_admin();
  usage( { option => q{cfg_file}, exit_code => 1 } )
    if defined $cfg_file && !-f $cfg_file;

  # Start logging
  openlog( qq{$cfg_ref->{log_name}}, q{}, LOG_USER );
  log_msg(
    {
      msg_typ => q{info},
      msg_str =>,
      qq{---+++ dnsmasq blacklist $version +++---},
    }
  );

  # Make sure localhost is always in the exclusions whitelist
  $cfg_ref->{hosts}->{exclude}->{localhost} = 1;

  # Now choose which data set will define the configuration
  my $success
    = defined $cfg_file
    ? get_cfg_file( { config => $cfg_ref } )
    : get_cfg_actv( { config => $cfg_ref } );
  die qq{FATAL: Unable to get configuration} if !$success;

  # Now proceed if blacklist is enabled
  if ( !$cfg_ref->{disabled} ) {
    my @areas = ();

    # Add areas to process only if they contain sources
    for my $area (qw{domains zones hosts}) {
      push @areas, $area if scalar keys %{ $cfg_ref->{$area}->{src} };
    }

    # Process each area
    my $area_count = (@areas);
    for my $area (@areas) {
      my ( $prefix, @threads );
      my $max_thrds = 8;
      my @sources   = keys %{ $cfg_ref->{$area}->{src} };
      $cfg_ref->{$area}->{icount}
        = scalar keys %{ $cfg_ref->{$area}->{blklst} } // 0;
      @{ $cfg_ref->{$area} }{ q{records}, q{unique} }
        = @{ $cfg_ref->{$area} }{ q{icount}, q{icount} };

      # Remove any files that no longer have configured sources
      my $sources_ref = {
        map {
          my $key = $_;
          qq{$cfg_ref->{dnsmasq_dir}/$area.$key.blacklist.conf} => 1;
        } @sources
      };
      my $files_ref = { map { my $key = $_; $key => 1; }
          glob qq{$cfg_ref->{dnsmasq_dir}/$area.*blacklist.conf} };

      for my $file ( keys $files_ref ) {
        delete_file( { file => $file } )
          if !exists $sources_ref->{$file} && $file;
      }

      # write each configured areas includes into individual dnsmasq files
      if ( $cfg_ref->{$area}->{icount} > 0 ) {
        my $equals = $area ne q{domains} ? q{=/} : q{=/.};
        write_file(
          {
            data => [
              map {
                my $value = $_;
                sprintf qq{%s%s%s/%s\n}, $cfg_ref->{$area}->{target}, $equals,
                  $value, $cfg_ref->{$area}->{dns_redirect_ip};
              } sort keys %{ $cfg_ref->{$area}->{blklst} }
            ],
            file =>
              qq{$cfg_ref->{dnsmasq_dir}/$area.pre-configured.blacklist.conf},
          }
        );
      }

      for my $source (@sources) {
        my ( $file, $url )
          = @{ $cfg_ref->{$area}->{src}->{$source} }{ q{file}, q{url} };
        my $uri  = new URI($url);
        my $host = $uri->host;

        # Initialize the sources counters
        @{ $cfg_ref->{$area}->{src}->{$source} }
          {qw(duplicates icount records unique)} = ( 0, 0, 0, 0 );

        $prefix
          = $cfg_ref->{$area}->{src}->{$source}->{prefix} ~~ q{http}
          ? qr{(?:\A(?:http:|https:){1}[/]{1,2})}om
          : $cfg_ref->{$area}->{src}->{$source}->{prefix};

        if ( scalar $url ) {
          log_msg(
            {
              msg_typ => q{info},
              msg_str => sprintf q{Downloading %s blacklist from %s},
              $area, $host,
            }
          ) if $show;
          push @threads,
            threads->create(
            { context => q{list}, exit => q{thread_only} },
            \&get_url,
            {
              area   => $area,
              host   => $host,
              prefix => $prefix,
              src    => $source,
              url    => $url
            }
            );
        }
        elsif ($file) {    # get file data
          push @threads,
            threads->create( { context => q{list}, exit => q{thread_only} },
            \&get_file, { file => $file, src => $source } );
        }
        sleep 1 while ( scalar threads->list(threads::running) >= $max_thrds );
      }

      for my $thread (@threads) {
        my $data_ref = $thread->join();
        my $rec_count = scalar keys %{ $data_ref->{data} } // 0;

        $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{records} += $rec_count;

        if ( exists $data_ref->{host} && scalar $rec_count ) {
          log_msg(
            {
              msg_typ => q{info},
              msg_str => sprintf q{%s lines received from: %s },
              $rec_count, $data_ref->{host},
            }
          );

          # Now process what we have received from the web host
          process_data(
            {
              area   => $area,
              data   => \%{ $data_ref->{data} },
              config => $cfg_ref,
              prefix => $data_ref->{prefix},
              src    => $data_ref->{src}
            }
          );

          # Delete $data_ref->{data} key and data
          delete $data_ref->{data};

          if ( $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{icount} > 0 ) {
            my $equals = $area ne q{domains} ? q{=/} : q{=/.};
            write_file(
              {
                data => [
                  map {
                    my $value = $_;
                    sprintf qq{%s%s%s/%s\n}, $cfg_ref->{$area}->{target},
                      $equals, $value, $cfg_ref->{$area}->{dns_redirect_ip};
                    } sort keys %{
                    $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{blklst}
                    }
                ],
                file =>
                  qq{$cfg_ref->{dnsmasq_dir}/$area.$data_ref->{src}.blacklist.conf},
              }
            );


            $cfg_ref->{$area}->{unique}
              += scalar
              keys %{ $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{blklst}
              };
            $cfg_ref->{$area}->{duplicates}
              += $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{duplicates};
            $cfg_ref->{$area}->{icount}
              += $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{icount};
            $cfg_ref->{$area}->{records}
              += $cfg_ref->{$area}->{src}->{ $data_ref->{src} }->{records};

            # Discard the data now its written to file
            delete $cfg_ref->{$area}->{src}->{ $data_ref->{src} };
          }
          else {
            log_msg(
              {
                msg_typ => q{warning},
                msg_str => qq{Zero records processed from $data_ref->{src}!},
              }
            );
          }
        }
      }

      log_msg(
        {
          msg_typ => q{info},
          msg_str => sprintf
            q{Processed %s %s (%s discarded) from %s records (%s orig.)%s},
          @{ $cfg_ref->{$area} }{qw(unique type duplicates icount records)},
          qq{\n},
        }
      );

      my @flagged_domains = ();

      # Now lets report the domains that were seen more than $cfg->{flag_lvl}
      for my $key (
        sort {
          $cfg_ref->{hosts}->{exclude}->{$b}
            <=> $cfg_ref->{hosts}->{exclude}->{$a}
        } keys %{ $cfg_ref->{hosts}->{exclude} }
        )
      {
        my $value = $cfg_ref->{hosts}->{exclude}->{$key};
        if ( $value >= $cfg_ref->{flag_lvl} && length $key > 5 ) {
          log_msg(
            {
              msg_typ => q{info},
              msg_str => sprintf qq{$area blacklisted: domain %s %s times},
              $key, $value,
            }
          );
          push @flagged_domains, qq{$key # $value times};
        }
      }

      if (@flagged_domains) {
        write_file(
          {
            data => [
              map {
                my $value = $_;
                sprintf
                  qq{set service dns forwarding blacklist domains include %s\n},
                  $value;
              } @flagged_domains
            ],
            file => $cfg_ref->{flag_file},
          }
        );

        log_msg(
          {
            msg_typ => q{info},
            msg_str =>
              qq{Flagged domains command set written to:\n $cfg_ref->{flag_file}},
          }
        );
      }

      $area_count--;
      say q{} if $area_count == 1 && $show;    # print a final line feed
    }
  }
  elsif ( $cfg_ref->{disabled} ) {
    for my $file (
      glob qq{$cfg_ref->{dnsmasq_dir}/{domains,hosts,zones}*blacklist.conf} )
    {
      delete_file( { file => $file } ) if $file;
    }
  }

  # Select the appropriate dnsmasq restart for CLI configure or bash shell
  my $cmd
    = is_configure()
    ? q{/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding}
    : qq{$dnsmasq_svc force-reload > /dev/null 2>1&};

  # Clean up the status line
  print $crsr->{off}, qq{\r}, qq{ } x $cols, qq{\r} if $show;

  log_msg(
    { msg_typ => q{info}, msg_str => q{Reloading dnsmasq configuration...}, } );

  # Reload updated dnsmasq conf address redirection files
  qx{$cmd};
  log_msg(
    {
      msg_typ => q{error},
      msg_str => q{Reloading dnsmasq configuration failed},
    }
  ) if ( $? >> 8 != 0 );

  # Close the log
  closelog();

  # Finish with a linefeed if '-v' is selected
  say $crsr->{on}, q{} if $show;
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
sub process_data {
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
  print $crsr->{off}, qq{\r}, qq{ } x $cols, qq{\r} if $show;

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
      qq{$crsr->{off}%s: $crsr->{bright_green}%s$crsr->{reset} %s processed, ($crsr->{bright_red}%s$crsr->{reset} discarded) from $crsr->{bright_magenta}%s$crsr->{reset} lines\r},
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
