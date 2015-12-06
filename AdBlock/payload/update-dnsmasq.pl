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
use POSIX qw{geteuid strftime};
use strict;
use threads;
use URI;
use v5.14;
use Vyatta::Config;
use warnings;

use constant TRUE  => 1;
use constant FALSE => 0;

my $version = q{3.3.4};

my $cols = qx{tput cols};
my $crsr = {
  off               => qq{\033[?25l},
  on                => qq{\033[?25h},
  clear             => qq{\033[0m},
  reset             => qq{\033[0m},
  bright_green      => qq{\033[92m},
  bright_magenta    => qq{\033[95m},
  bright_red        => qq{\033[91m},
};
my ( $cfg_file, $LH, $debug, $show );

############################### script runs here ###############################
say q{Running sub main();} if $debug;

&main();

# Exit normally
say q{Exiting with $? = 0;} if $debug;

exit 0;
################################################################################

# Process the active (not committed or saved) configuration
sub cfg_actv {
  my $input = shift;
  say qq{Running sub cfg_actv($input);} if $debug;

  if ( is_blacklist() ) {
    my $config = new Vyatta::Config;
    my ( $listNodes, $returnValue, $returnValues );

    if ( is_configure() ) {
      $returnValue  = q{returnValue};
      $returnValues = q{returnValues};
      $listNodes    = q{listNodes};
    }
    else {
      $returnValue  = q{returnOrigValue};
      $returnValues = q{returnOrigValues};
      $listNodes    = q{listOrigNodes};
    }

    $config->setLevel(q{service dns forwarding blacklist});
    $input->{'config'}->{'disabled'} = $config->$returnValue(q{disabled})
      // FALSE;
    $input->{'config'}->{'dns_redirect_ip'}
      = $config->$returnValue(q{dns-redirect-ip}) // q{0.0.0.0};

    $input->{'config'}->{'disabled'}
      = $input->{'config'}->{'disabled'} eq q{false} ? FALSE : TRUE;

    for my $area (qw{hosts domains zones}) {
      $config->setLevel(qq{service dns forwarding blacklist $area});
      $input->{'config'}->{$area}->{'dns_redirect_ip'}
        = $config->$returnValue(q{dns-redirect-ip})
        // $input->{'config'}->{'dns_redirect_ip'};
      $input->{'config'}->{$area}->{'blklst'} = {
        map {
          my $key = $_;
          $key => 1;
        } $config->$returnValues('include')
      };
      $input->{'config'}->{$area}->{'exclude'} = {
        map {
          my $key = $_;
          $key => 1;
        } $config->$returnValues(q{exclude})
      };

      for my $source ( $config->$listNodes(q{source}) ) {
        $config->setLevel(
          qq{service dns forwarding blacklist $area source $source});
        @{ $input->{'config'}->{$area}->{'src'}->{$source} }{qw(prefix url)}
          = ( $config->$returnValue('prefix'), $config->$returnValue('url') );
        $input->{'config'}->{$area}->{'src'}->{$source}->{'compress'}
          = $config->$returnValue('compress')
          if $area eq q{domains};
      }
    }
  }
  else {
    $show = TRUE;
    log_msg(
      {
        msg_typ => q{ERROR},
        msg_str =>
          q{[service dns forwarding blacklist is not configured], exiting!},
      }
    );

    return FALSE;
  }
  if ( ( !scalar keys %{ $input->{'config'}->{'domains'}->{'src'} } )
    && ( !scalar keys %{ $input->{'config'}->{'hosts'}->{'src'} } )
    && ( !scalar keys %{ $input->{'config'}->{'zones'}->{'src'} } ) )
  {
    $show = TRUE;
    log_msg(
      {
        msg_ref => q{ERROR},
        msg_str => q{At least one domain or host source must be configured},
      }
    );
    return FALSE;
  }
  return TRUE;
}

# Process a configuration file in memory after get_file() loads it
sub cfg_file {
  my $input = shift;
  say qq{Running sub cfg_file($input->{'config'});} if $debug;
  my $tmp_ref
    = get_nodes( { config_data => get_file( { file => $cfg_file } ) } );
  my $configured
    = (  $tmp_ref->{'domains'}->{'source'}
      || $tmp_ref->{'hosts'}->{'source'}
      || $tmp_ref->{'zones'}->{'source'} ) ? TRUE : FALSE;

  if ($configured) {
    $input->{'config'}->{'dns_redirect_ip'} = $tmp_ref->{'dns-redirect-ip'}
      // q{0.0.0.0};
    $input->{'config'}->{'disabled'}
      = ( $tmp_ref->{'disabled'} eq q{false} ) ? FALSE : TRUE;

    for my $area (qw{hosts domains zones}) {
      $input->{'config'}->{$area}->{'dns_redirect_ip'}
        = $input->{'config'}->{'dns_redirect_ip'}
        if !exists( $tmp_ref->{$area}->{'dns-redirect-ip'} );
      @{ $input->{'config'}->{$area} }{qw(blklst exclude src)}
        = @{ $tmp_ref->{$area} }{qw(include exclude source)};
    }
  }
  else {
    $input->{'config'}->{'debug'} = TRUE;
    log_msg(
      {
        msg_typ => q{ERROR},
        msg_str =>
          q{[service dns forwarding blacklist] isn't configured, exiting!},
      }
    );
    return FALSE;
  }
  return TRUE;
}

# Remove previous configuration files
sub delete_file {
  my $input = shift;
  say qq{Running sub delete_file($input->{'file'});} if $debug;

  if ( -f $input->{'file'} ) {
    log_msg(
      {
        msg_typ => q{INFO},
        msg_str => sprintf q{Deleting file %s},
        $input->{'file'},
      }
    );
    unlink $input->{'file'};
  }

  if ( -f $input->{'file'} ) {
    log_msg(
      {
        msg_typ => q{WARNING},
        msg_str => sprintf q{Unable to delete %s},
        $input->{'file'},
      }
    );
    return FALSE;
  }
  return TRUE;
}

# Determine which type of configuration to get (default, active or saved)
sub get_config {
  my $input = shift;
  say qq{Running sub get_config($input->{'type'});} if $debug;

  given ( $input->{'type'} ) {
    when (/active/) { return cfg_actv( { config => $input->{'config'} } ); }
    when (/file/) { return cfg_file( { config => $input->{'config'} } ); }
  }

  return FALSE;
}

# Read a file into memory and return the data to the calling function
sub get_file {
  my $input = shift;
  say qq{Running sub get_file($input->{'file'});} if $debug;
  my @data = ();
  if ( exists $input->{'file'} ) {
    open my $CF, q{<}, $input->{'file'}
      or die qq{ERROR: Unable to open $input->{'file'}: $!};
    chomp( @data = <$CF> );

    close $CF;
  }
  return $input->{'data'} = \@data;
}

# Build hashes from the configuration file data (called by get_nodes())
sub get_hash {
  my $input    = shift;
  my $hash     = \$input->{'hash_ref'};
  my @nodes    = @{ $input->{'nodes'} };
  my $value    = pop @nodes;
  my $hash_ref = ${$hash};

  say qq{Running sub get_hash($input);} if $debug;

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

  say qq{Running sub get_nodes($input->{'config_data'});} if $debug;

  for my $line ( @{ $input->{'config_data'} } ) {
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
  return $cfg_ref->{'service'}->{'dns'}->{'forwarding'}->{'blacklist'};
}

# Set up command line options
sub get_options {
  my $input = shift;
  my @opts  = (
    [ q{-f <file> # load a configuration file}, q{f=s}   => \$cfg_file ],
    [ q{-debug    # enable debug output},       q{debug} => \$debug ],
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

  say qq{Running sub get_options($input->{'option'});} if $debug;

  return \@opts if $input->{'option'};

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

  say qq{Running sub get_url($input);} if $debug;

#   $ua->timeout(60);
  $input->{'prefix'} =~ s/^["](?<UNCMT>.*)["]$/$+{UNCMT}/g;
  my $re = {
    REJECT => qr{^#|^$|^\n}o,
    SELECT => qr{^$input->{'prefix'}.*$}o,
    SPLIT  => qr{\R|<br \/>}oms,
  };

  my $get = $ua->get( $input->{'url'} );

  if ( $get->{'success'} ) {
    $input->{'data'} = {
      map { my $key = $_; lc($key) => 1 }
        grep { $_ =~ /$re->{SELECT}/ } split /$re->{SPLIT}/,
      $get->{'content'}
    };
    return $input;
  }
  else {
    $input->{'data'} = {};
    return $input;
  }
}

# Check to see if blacklist is configured
sub is_blacklist {
  my $config = new Vyatta::Config;
  say qq{Running sub is_blacklist($config);} if $debug;

  $config->setLevel(q{service dns forwarding});
  my $blklst_exists
    = is_configure()
    ? $config->exists(q{blacklist})
    : $config->existsOrig(q{blacklist});

  return defined $blklst_exists ? TRUE : FALSE;
}

# Check to see if we are being run under configure
sub is_configure () {

  qx{/bin/cli-shell-api inSession};
  my $exit_code = $?;
  say qq{Running sub is_configure(Exit code = $exit_code);} if $debug;

  return $exit_code > 0 ? FALSE : TRUE;
}

# Make sure script runs as root
sub is_sudo {
  say q{Running sub is_sudo();} if $debug;

  return TRUE if geteuid() == 0;
  return FALSE;
}

# Log and print (if -v or debug)
sub log_msg {
  my $msg_ref = shift;
  my $EOL     = scalar($debug) ? qq{\n} : q{};
  my $date    = strftime qq{%b %e %H:%M:%S %Y}, localtime;

  return FALSE
    unless ( length $msg_ref->{'msg_typ'} . $msg_ref->{'msg_str'} > 2 );

  say {$LH} qq{$date: $msg_ref->{'msg_typ'}: $msg_ref->{'msg_str'}};
  print $crsr->{'off'}, qq{\r}, q{ } x $cols, qq{\r} if $show;
  if ( $msg_ref->{'msg_typ'} eq q{INFO} ) {
    print $crsr->{'off'}, qq{$msg_ref->{'msg_typ'}: $msg_ref->{'msg_str'}$EOL} if $show;
  }
  else {
    print STDERR $crsr->{'off'}, $crsr->{'bright_red'}, qq{$msg_ref->{'msg_typ'}: $msg_ref->{'msg_str'}$crsr->{'reset'}$EOL}
      if $show || $debug;
  }

  return TRUE;
}

# This is the main function
sub main {
  my $dnsmasq_svc = q{/etc/init.d/dnsmasq};
  my $cfg_ref     = {
    debug            => 0,
    disabled         => 0,
    dnsmasq_dir      => q{/etc/dnsmasq.d},
    no_op            => q{/tmp/.update-dnsmasq.no-op},
    log_file         => q{/var/log/update-dnsmasq.log},
    flag_dom_level   => 5,
    flagged_dom_file => q{/var/log/update-dnsmasq_flagged_domains.cmds},
    domains          => {
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
  exit 0 if ( -f $cfg_ref->{'no_op'} );

  usage( { option => q{sudo}, exit_code => 1 } ) if not is_sudo();
  usage( { option => q{cfg_file}, exit_code => 1 } )
    if defined $cfg_file && !-f $cfg_file;

  # Start logging
  open $LH, q{>>}, $cfg_ref->{'log_file'}
    or die q{Cannot open log file - this shouldn't happen!};
  log_msg(
    {
      msg_typ => q{INFO},
      msg_str =>,
      qq{---+++ dnsmasq blacklist $version +++---},
    }
  );

  # Make sure localhost is always in the exclusions whitelist
  $cfg_ref->{'hosts'}->{'exclude'}->{'localhost'} = 1;

  # Now choose which data set will define the configuration
  my $cfg_type = defined $cfg_file ? q{file} : q{active};

  exit 1 unless get_config( { type => $cfg_type, config => $cfg_ref } );

  # Now proceed if blacklist is enabled
  if ( !$cfg_ref->{'disabled'} ) {
    my @areas = ();

    # Add areas to process only if they contain sources
    for my $area (qw{domains zones hosts}) {
      push @areas, $area if scalar keys %{ $cfg_ref->{$area}->{'src'} };
    }

    # Process each area
    my $area_count = (@areas);
    for my $area (@areas) {
      my ( $prefix, @threads );
      my $max_thrds = 8;
      my @sources   = keys %{ $cfg_ref->{$area}->{'src'} };
      $cfg_ref->{$area}->{'icount'}
        = scalar keys %{ $cfg_ref->{$area}->{'blklst'} } // 0;
      @{ $cfg_ref->{$area} }{ 'records', 'unique' }
        = @{ $cfg_ref->{$area} }{ 'icount', 'icount' };

      # Remove any files that no longer have configured sources
      my $sources_ref = {
        map {
          my $key = $_;
          qq{$cfg_ref->{'dnsmasq_dir'}/$area.$key.blacklist.conf} => 1;
        } @sources
      };
      my $files_ref = { map { my $key = $_; $key => 1; }
          glob qq{$cfg_ref->{'dnsmasq_dir'}/$area.*blacklist.conf} };

      for my $file ( keys $files_ref ) {
        delete_file( { file => $file } ) if !exists $sources_ref->{$file};
      }

      # write each configured area's includes into individual dnsmasq files
      if ( $cfg_ref->{$area}->{'icount'} > 0 ) {
        my $equals = $area ne q{domains} ? q{=/} : q{=/.};
        my $file
          = qq{$cfg_ref->{'dnsmasq_dir'}/$area.pre-configured.blacklist.conf};
        write_file(
          {
            data => [
              map {
                my $value = $_;
                sprintf qq{%s%s%s/%s\n}, $cfg_ref->{$area}->{'target'},
                  $equals, $value, $cfg_ref->{$area}->{'dns_redirect_ip'};
              } sort keys %{ $cfg_ref->{$area}->{'blklst'} }
            ],
            file => $file,
          }
        ) or die sprintf qq{Could not open file: s% $!}, $file;
      }

      for my $source (@sources) {
        my ( $file, $url )
          = @{ $cfg_ref->{$area}->{'src'}->{$source} }{ 'file', 'url' };
        my $uri  = new URI($url);
        my $host = $uri->host;

        # Initialize the source's counters
        @{ $cfg_ref->{$area}->{'src'}->{$source} }
          {qw(duplicates icount records unique)} = ( 0, 0, 0, 0 );

        $prefix
          = $cfg_ref->{$area}->{'src'}->{$source}->{'prefix'} ~~ 'http'
          ? qr{(?:^(?:http:|https:){1}[/]{1,2})}o
          : $cfg_ref->{$area}->{'src'}->{$source}->{'prefix'};

        if ( scalar $url ) {
          log_msg(
            {
              msg_typ => q{INFO},
              msg_str => sprintf q{Downloading %s blacklist from %s},
              $area, $host,
            }
          ) if $show || $debug;
          push @threads,
            threads->create(
            { context => q{list}, exit => q{thread_only} },
            \&get_url,
            {
              area   => $area,
              debug  => $debug,
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
        my $compress;
        my $data_ref = $thread->join();
        my $rec_count = scalar keys %{ $data_ref->{'data'} } // 0;

        $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }->{'records'}
          += $rec_count;

        $compress
          = (
          exists $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }
            ->{'compress'}
            && $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }->{'compress'}
            eq q{true} ) ? TRUE : FALSE;
        if ( exists $data_ref->{'host'} && scalar $rec_count ) {
          log_msg(
            {
              msg_typ => q{INFO},
              msg_str => sprintf q{%s lines received from: %s },
              $rec_count, $data_ref->{'host'},
            }
          );

          # Now process what we have received from the web host
          process_data(
            {
              area     => $area,
              data     => \%{ $data_ref->{'data'} },
              compress => $compress,
              config   => $cfg_ref,
              prefix   => $data_ref->{'prefix'},
              src      => $data_ref->{'src'}
            }
          );

          # Delete $data_ref->{'data'} key and data
          delete $data_ref->{'data'};

          if (
            $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }->{'icount'} > 0 )
          {
            my $equals = $area ne q{domains} ? q{=/} : q{=/.};
            my $file
              = qq{$cfg_ref->{'dnsmasq_dir'}/$area.$data_ref->{'src'}.blacklist.conf};
            write_file(
              {
                data => [
                  map {
                    my $value = $_;
                    sprintf qq{%s%s%s/%s\n}, $cfg_ref->{$area}->{'target'},
                      $equals, $value, $cfg_ref->{$area}->{'dns_redirect_ip'};
                    } sort keys %{
                    $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }
                      ->{'blklst'}
                    }
                ],
                file => $file,
              }
            ) or die sprintf qq{Could not open file: s% $!}, $file;


            $cfg_ref->{$area}->{'unique'}
              += scalar keys
              %{ $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }->{'blklst'}
              };
            $cfg_ref->{$area}->{'duplicates'}
              += $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }
              ->{'duplicates'};
            $cfg_ref->{$area}->{'icount'}
              += $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }->{'icount'};
            $cfg_ref->{$area}->{'records'}
              += $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }
              ->{'records'};

            # Discard the data now its written to file
            delete $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} };
          }
          else {
            log_msg(
              {
                msg_typ => q{WARNING},
                msg_str => qq{Zero records processed from $data_ref->{'src'}!},
              }
            );
          }
        }
      }

      log_msg(
        {
          msg_typ => q{INFO},
          msg_str => sprintf
            q{Processed %s %s (%s discarded) from %s records (%s orig.)%s},
          @{ $cfg_ref->{$area} }{qw(unique type duplicates icount records)},
          qq{\n},
        }
      );

      my @flagged_domains = ();

 # Now lets report the domains that were seen more than $cfg->{'flag_dom_level'}
      for my $key (
        sort {
          $cfg_ref->{'hosts'}->{'exclude'}->{$b}
            <=> $cfg_ref->{'hosts'}->{'exclude'}->{$a}
        } keys %{ $cfg_ref->{'hosts'}->{'exclude'} }
        )
      {
        my $value = $cfg_ref->{'hosts'}->{'exclude'}->{$key};
        if ( $value >= $cfg_ref->{'flag_dom_level'} && length $key > 5 ) {
          log_msg(
            {
              msg_typ => q{INFO},
              msg_str => sprintf qq{$area blacklisted: domain %s %s times},
              $key, $value,
            }
          );
          push @flagged_domains, qq{$key # $value times};
        }
      }

      if (@flagged_domains) {
        my $file = qq{$cfg_ref->{'flagged_dom_file'}};
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
            file => $file,
          }
        ) or die sprintf qq{Could not open file: s% $!}, $file;

        log_msg(
          {
            msg_typ => q{INFO},
            msg_str =>
              qq{Flagged domain configure command set written to $file},
          }
        );
      }

      $area_count--;
      say q{}
        if ( $area_count == 1 )
        && ( $show || $debug );    # print a final line feed
    }
  }
  elsif ( $cfg_ref->{'disabled'} ) {
    for my $file (
      glob qq{$cfg_ref->{'dnsmasq_dir'}/{domains,hosts,zones}*blacklist.conf} )
    {
      delete_file( { file => $file } );
    }
  }

  # Select the appropriate dnsmasq restart for CLI configure or bash shell
  my $cmd
    = is_configure()
    ? q{/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding}
    : qq{$dnsmasq_svc force-reload > /dev/null 2>1&};

  # Clean up the status line
  print $crsr->{'off'}, qq{\r}, qq{ } x $cols, qq{\r} if $show || $debug;

  log_msg(
    { msg_typ => q{INFO}, msg_str => q{Reloading dnsmasq configuration...}, } );

  # Reload updated dnsmasq conf address redirection files
  qx{$cmd};
  log_msg(
    {
      msg_typ => q{ERROR},
      msg_str => q{Reloading dnsmasq configuration failed},
    }
  ) if ( $? >> 8 != 0 );

  # Close the log
  close $LH;

  # Finish with a linefeed if '-v' or debug is selected
  say $crsr->{on}, q{} if $show || $debug;
}

# Crunch the data and throw out anything we don't need
sub process_data {
  my $input = shift;
  my $re    = {
    FQDOMN =>
      qr{(\b(?:(?![.]|-)[\w-]{1,63}(?<!-)[.]{1})+(?:[a-zA-Z]{2,63})\b)}o,
    LSPACE => qr{^\s+}o,
    RSPACE => qr{\s+$}o,
    PREFIX => qr{^$input->{'prefix'}},
    SUFFIX => qr{(?:#.*$|\{.*$|[/[].*$)}o,
  };

  say qq{Running sub process_data($input);} if $debug;

  # Clear the status lines
  print $crsr->{'off'}, qq{\r}, qq{ } x $cols, qq{\r} if $show || $debug;

# Process the lines we've been given
LINE:
  for my $line ( keys %{ $input->{'data'} } ) {
    next LINE if $line eq q{} || !defined $line;
    $line =~ s/$re->{PREFIX}//;
    $line =~ s/$re->{SUFFIX}//;
    $line =~ s/$re->{LSPACE}//;
    $line =~ s/$re->{RSPACE}//;

    # Get all of the FQDNs or domains in the line
    my @elements = $line =~ m/$re->{FQDOMN}/gc;
    next LINE if !scalar @elements;

    # We use map to individually pull 1 to N FQDNs or domains from @elements
    map {
      # Capture the FQDN or domain
      my $element = $_;

      # Break it down into it components
      my @domain = split /[.]/, $element;
      my $is_domain = FALSE;

      # Convert to a domain if it is more than two elements
      if ( scalar @domain > 2 ) {
        shift @domain;
      }
      else {
        $is_domain = TRUE;
      }
      my $elem_count = scalar @domain;
      my $domain_name = join q{.}, @domain;

      # Create an array of all the subdomains
      my @keys;
      for my $i ( 2 .. $elem_count ) {
        push @keys, join q{.}, @domain;
        shift @domain;
      }

      # Have we seen this key before?
      my $key_exists = FALSE;
      for my $key (@keys) {
        if (
          exists $input->{'config'}->{ $input->{'area'} }->{'exclude'}->{$key} )
        {
          $key_exists = TRUE;
          $input->{'config'}->{ $input->{'area'} }->{'exclude'}->{$key}++;
        }
      }

      # Now add the key, convert to .domain.tld if only two elements
      if ( !$key_exists ) {
        if ( $input->{'compress'} == TRUE ) {
          $input->{'config'}->{ $input->{'area'} }->{'src'}
            ->{ $input->{'src'} }->{'blklst'}->{$domain_name} = 1;
        }
        elsif ( $is_domain && $input->{'area'} ne q{domains} ) {
          $input->{'config'}->{ $input->{'area'} }->{'src'}
            ->{ $input->{'src'} }->{'blklst'}->{qq{.$domain_name}} = 1;
        }
        else {
          $input->{'config'}->{ $input->{'area'} }->{'src'}
            ->{ $input->{'src'} }->{'blklst'}->{$element} = 1;
        }
      }
      else {
        $input->{'config'}->{ $input->{'area'} }->{'src'}->{ $input->{'src'} }
          ->{'duplicates'}++;
      }

      # Add to the exclude list, so the next source doesn't duplicate values
      @{ $input->{'config'}->{ $input->{'area'} }->{'exclude'} }
        { qq{.$domain_name}, $domain_name, $element } = ( 1, 1, 1 );
    } @elements;

    $input->{'config'}->{ $input->{'area'} }->{'src'}->{ $input->{'src'} }
      ->{'icount'} += scalar @elements;

    printf
      qq{%s: $crsr->{'bright_green'}%s$crsr->{'reset'} %s processed, ($crsr->{'bright_red'}%s$crsr->{'reset'} discarded) from $crsr->{'bright_magenta'}%s$crsr->{'reset'} lines\r},
      $input->{'src'},
      $input->{'config'}->{ $input->{'area'} }->{'src'}->{ $input->{'src'} }
      ->{'icount'}, $input->{'config'}->{ $input->{'area'} }->{'type'},
      @{ $input->{'config'}->{ $input->{'area'} }->{'src'}->{ $input->{'src'} }
      }{ 'duplicates', 'records' }
      if $show || $debug;
  }

  if (
    scalar $input->{'config'}->{ $input->{'area'} }->{'src'}
    ->{ $input->{'src'} }->{'icount'} )
  {
    log_msg(
      {
        msg_typ => q{INFO},
        msg_str => sprintf
          qq{%s: %s %s processed, (%s duplicates) from %s lines\r},
        $input->{'src'},
        $input->{'config'}->{ $input->{'area'} }->{'src'}->{ $input->{'src'} }
          ->{'icount'},
        $input->{'config'}->{ $input->{'area'} }->{'type'},
        @{
          $input->{'config'}->{ $input->{'area'} }->{'src'}->{ $input->{'src'} }
        }{ 'duplicates', 'records' },
      }
    );
    return TRUE;
  }
  return FALSE;
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
  $usage->{ $input->{'option'} }->( $input->{'exit_code'} );
}

# Write the data to file
sub write_file {
  my $input = shift;

  say qq{Running sub write_file($input);} if $debug;

  open my $FH, '>', $input->{'file'} or return FALSE;
  log_msg(
    {
      msg_typ => q{INFO},
      msg_str => sprintf q{Saving %s},
      basename( $input->{'file'} ),
    }
  );
  for my $line ( @{ $input->{'data'} } ) {
    print {$FH} $line;
  }

  close $FH;

  return TRUE;
}
