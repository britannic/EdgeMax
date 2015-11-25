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
# Date:   November 2015
# Description: Script for creating dnsmasq configuration files to redirect dns
# look ups to alternative IPs (blackholes, pixel servers etc.)
#
# **** End License ****

my $version = '3.25beta1';

# use Data::Dumper;
use feature qw/switch/;
use File::Basename;
use Getopt::Long;
use lib '/opt/vyatta/share/perl5/';
use LWP::UserAgent;
use POSIX qw{geteuid strftime};
use strict;
use threads;
use URI;
use v5.14;
use Vyatta::Config;
use warnings;

use constant TRUE  => 1;
use constant FALSE => 0;

my $cols = qx( tput cols );
my ( $cfg_file, $LH, $debug, $show );

############################### script runs here ###############################
&main();

# Exit normally
exit(0);
################################################################################

# Process the active (not committed or saved) configuration
sub cfg_actv {
  my $input = shift;
  if ( is_blacklist() ) {
    my $config = new Vyatta::Config;
    my ( $listNodes, $returnValue, $returnValues );

    if ( is_configure() ) {
      $returnValue  = "returnValue";
      $returnValues = "returnValues";
      $listNodes    = "listNodes";
    }
    else {
      $returnValue  = "returnOrigValue";
      $returnValues = "returnOrigValues";
      $listNodes    = "listOrigNodes";
    }

    $config->setLevel('service dns forwarding blacklist');
    $input->{'config'}->{'disabled'} = $config->$returnValue('disabled')
      // FALSE;
    $input->{'config'}->{'dns_redirect_ip'}
      = $config->$returnValue('dns-redirect-ip') // '0.0.0.0';

    $input->{'config'}->{'disabled'}
      = $input->{'config'}->{'disabled'} eq 'false' ? FALSE : TRUE;

    for my $area (qw/hosts domains zones/) {
      $config->setLevel("service dns forwarding blacklist $area");
      $input->{'config'}->{$area}->{'dns_redirect_ip'}
        = $config->$returnValue('dns-redirect-ip')
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
        } $config->$returnValues('exclude')
      };

      for my $source ( $config->$listNodes('source') ) {
        $config->setLevel(
          "service dns forwarding blacklist $area source $source");
        $input->{'config'}->{$area}->{'src'}->{$source}->{'url'}
          = $config->$returnValue('url');
        $input->{'config'}->{$area}->{'src'}->{$source}->{'prefix'}
          = $config->$returnValue('prefix');
        $input->{'config'}->{$area}->{'src'}->{$source}->{'compress'}
          = $config->$returnValue('compress')
          if $area eq 'domains';
      }
    }
  }
  else {
    $show = TRUE;
    log_msg(
      {
        msg_typ => 'ERROR',
        msg_str =>
          '[service dns forwarding blacklist is not configured], exiting!'
      }
    );

    return (FALSE);
  }
  if ( ( !scalar( keys %{ $input->{'config'}->{'domains'}->{'src'} } ) )
    && ( !scalar( keys %{ $input->{'config'}->{'hosts'}->{'src'} } ) )
    && ( !scalar( keys %{ $input->{'config'}->{'zones'}->{'src'} } ) ) )
  {
    say STDERR ('At least one domain or host source must be configured');
    return (FALSE);
  }

  return (TRUE);
}

# Process a configuration file in memory after get_file() loads it
sub cfg_file {
  my $input = shift;
  my $tmp_ref
    = get_nodes( { config_data => get_file( { file => $cfg_file } ) } );
  my $configured
    = (  $tmp_ref->{'domains'}->{'source'}
      || $tmp_ref->{'hosts'}->{'source'}
      || $tmp_ref->{'zones'}->{'source'} ) ? TRUE : FALSE;

  if ($configured) {
    $input->{'config'}->{'dns_redirect_ip'} = $tmp_ref->{'dns-redirect-ip'}
      // '0.0.0.0';
    $input->{'config'}->{'disabled'}
      = ( $tmp_ref->{'disabled'} eq 'false' ) ? FALSE : TRUE;

    for my $area (qw/hosts domains zones/) {
      $input->{'config'}->{$area}->{'dns_redirect_ip'}
        = $input->{'config'}->{'dns_redirect_ip'}
        if !exists( $tmp_ref->{$area}->{'dns-redirect-ip'} );
      $input->{'config'}->{$area}->{'exclude'} = $tmp_ref->{$area}->{'exclude'};
      $input->{'config'}->{$area}->{'blklst'}  = $tmp_ref->{$area}->{'include'};
      $input->{'config'}->{$area}->{'src'}     = $tmp_ref->{$area}->{'source'};
    }
  }
  else {
    $input->{'config'}->{'debug'} = TRUE;
    log_msg(
      {
        msg_typ => 'ERROR',
        msg_str =>
          q{[service dns forwarding blacklist] isn't configured, exiting!}
      }
    );
    return (FALSE);
  }
  return (TRUE);
}

# Remove previous configuration files
sub delete_file {
  my $input = shift;

  if ( -f $input->{'file'} ) {
    log_msg(
      {
        msg_typ => 'INFO',
        msg_str => sprintf( 'Deleting file %s', $input->{'file'} )
      }
    );
    return unlink( $input->{'file'} )
      or log_msg(
      {
        msg_typ => 'WARNING',
        msg_str => sprintf( 'Unable to delete %s', $input->{'file'} )
      }
      );
  }
  return FALSE;
}

# Determine which type of configuration to get (default, active or saved)
sub get_config {
  my $input = shift;

  given ( $input->{'type'} ) {
    when (/active/) { return cfg_actv( { config => $input->{'config'} } ); }
    when (/file/) { return cfg_file( { config => $input->{'config'} } ); }
  }

  return FALSE;
}

# Get directory filtered file lists
sub get_directory {
  my $input = shift;
  my @files = qx{ls $input->{'directory'}/$input->{pattern} 2> /dev/null };
  chomp(@files);
  return @files;
}

# Read a file into memory and return the data to the calling function
sub get_file {
  my $input = shift;
  my @data;
  if ( exists $input->{'file'} ) {
    open( my $CF, '<', $input->{'file'} )
      or die "ERROR: Unable to open $input->{'file'}: $!";
    chomp( @data = <$CF> );
    close($CF);
    return $input->{'data'} = \@data;
  }
  else {
    return $input->{'data'} = [];
  }
}

# Build hashes from the configuration file data (called by get_nodes())
sub get_hash {
  my $input    = shift;
  my $hash     = \$input->{'hash_ref'};
  my @nodes    = @{ $input->{'nodes'} };
  my $value    = pop(@nodes);
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

  for my $line ( @{ $input->{'config_data'} } ) {
    $line =~ s/$re->{LSPC}//;
    $line =~ s/$re->{RSPC}//;

    given ($line) {
      when (/$re->{MULT}/) {
        push( @nodes, $+{MULT} );
        push( @nodes, $+{VALU} );
        push( @nodes, 1 );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop(@nodes);
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{NODE}/) {
        push( @nodes, $+{NODE} );
      }
      when (/$re->{LEAF}/) {
        $level++;
        push( @nodes, $+{LEAF} );
        push( @nodes, $+{NAME} );
      }
      when (/$re->{NAME}/) {
        push( @nodes, $+{NAME} );
        push( @nodes, $+{VALU} );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{DESC}/) {
        push( @nodes, $+{NAME} );
        push( @nodes, $+{DESC} );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{MISC}/) {
        push( @nodes, $+{MISC} );
        push( @nodes, $+{MISC} );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{CMNT}/) {
        next;
      }
      when (/$re->{BRKT}/) {
        pop(@nodes);
        if ( $level > 0 ) {
          pop(@nodes);
          $level--;
        }
      }
      when (/$re->{MPTY}/) {
        next;
      }
      default {
        print( sprintf( 'Parse error: "%s"', $line ) );
      }
    }
  }
  return ( $cfg_ref->{'service'}->{'dns'}->{'forwarding'}->{'blacklist'} );
}

# Set up command line options
sub get_options {
  my $input = shift;
  my @opts  = (
    [ q{-f <file>   # load a configuration file},   'f=s'   => \$cfg_file ],
    [ q{--debug     # enable verbose debug output}, 'debug' => \$debug ],
    [
      q{--help      # show help and usage text},
      'help' => sub { usage( { option => 'help', exit_code => 0 } ) }
    ],
    [ q{-v          # verbose (outside configure session)}, 'v' => \$show ],
    [
      q{--version   # show program version number},
      'version' => sub { usage( { option => 'version', exit_code => 0 } ) }
    ],
  );

  return \@opts if $input->{'option'};

  # Read command line flags and exit with help message if any are unknown
  return GetOptions( map { (@$_)[ 1 .. $#$_ ] } @opts );
}

# Get lists from web servers
sub get_url {
  my $input = shift;
  my $ua    = LWP::UserAgent->new;
  $ua->agent(
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56'
  );
  $ua->timeout(60);
  my $get;
  my $lines = 0;
  $input->{'prefix'} =~ s/^["](?<UNCMT>.*)["]$/$+{UNCMT}/g;
  my $re = {
    REJECT => qr{^#|^$|^\n}o,
    SELECT => qr{^$input->{'prefix'}.*$}o,
    SPLIT  => qr{\R|<br \/>}oms,
  };

  $ua->show_progress(TRUE) if $input->{'debug'};
  $get = $ua->get( $input->{'url'} );

  $input->{'data'} = { map { my $key = $_; lc($key) => 1 }
      grep { $_ =~ /$re->{SELECT}/ } split( /$re->{SPLIT}/, $get->content ) };

  if ( $get->is_success ) {
    return $input;
  }
  else {
    return $input->{'data'} = {};
  }
}

# Check to see if blacklist is configured
sub is_blacklist {
  my $config = new Vyatta::Config;

  $config->setLevel("service dns forwarding");
  my $blklst_exists
    = is_configure()
    ? $config->exists("blacklist")
    : $config->existsOrig("blacklist");

  return defined($blklst_exists) ? TRUE : FALSE;
}

# Check to see if we are being run under configure
sub is_configure () {

  qx(/bin/cli-shell-api inSession);

  return ( $? > 0 ) ? FALSE : TRUE;
}

# Check to see if the script is scheduled
sub is_scheduled {
  my $schedule_exists;

  if ( is_blacklist() ) {
    my $config = new Vyatta::Config;
    $config->setLevel("system task-scheduler task");

    $schedule_exists
      = is_configure()
      ? $config->exists("blacklist")
      : $config->existsOrig("blacklist");
  }

  return my $bool = defined($schedule_exists) ? TRUE : FALSE;
}

# Make sure script runs as root
sub is_sudo {
  return (TRUE) if geteuid() == 0;
  return (FALSE);
}

# Log and print (if -v or debug)
sub log_msg {
  my $msg_ref = shift;
  my $date = strftime "%b %e %H:%M:%S %Y", localtime;
  return (FALSE)
    unless ( length( $msg_ref->{msg_typ} . $msg_ref->{msg_str} ) > 2 );

  my $EOL = scalar($debug) ? qq{\n} : q{};

  say {$LH} ("$date: $msg_ref->{msg_typ}: $msg_ref->{msg_str}");
  print( "\r", " " x $cols, "\r" ) if $show;
  print("$msg_ref->{msg_typ}: $msg_ref->{msg_str}$EOL") if $show;

  return TRUE;
}

# This is the main function
sub main() {
  my $dnsmasq_svc = '/etc/init.d/dnsmasq';
  my $cfg_ref     = {
    debug       => 0,
    disabled    => 0,
    dnsmasq_dir => '/etc/dnsmasq.d',
    log_file    => '/var/log/update-dnsmasq.log',
    domains     => {
      icount  => 0,
      records => 0,
      target  => 'address',
      type    => 'domains',
      unique  => 0,
    },
    hosts => {
      icount  => 0,
      records => 0,
      target  => 'address',
      type    => 'hosts',
      unique  => 0,
    },
    zones => {
      icount  => 0,
      records => 0,
      target  => 'server',
      type    => 'zones',
      unique  => 0,
    },
  };

  # Get command line options or print help if no valid options
  get_options() || usage( { option => 'help', exit_code => 1 } );

  # Find reasons to quit
  usage( { option => 'sudo', exit_code => 1 } ) if not is_sudo();
  usage( { option => 'cfg_file', exit_code => 1 } )
    if defined($cfg_file)
    and not( -f $cfg_file );

  # Start logging
  open( $LH, '>>', $cfg_ref->{'log_file'} )
    or die(q{Cannot open log file - this shouldn't happen!});
  log_msg(
    { msg_typ => 'INFO', msg_str =>, "---+++ blacklist $version +++---" } );

  # Make sure localhost is always in the exclusions whitelist
  $cfg_ref->{'hosts'}->{'exclude'}->{'localhost'} = 1;

  # Now choose which data set will define the configuration
  my $cfg_type = defined($cfg_file) ? 'file' : 'active';

  exit(1) unless get_config( { type => $cfg_type, config => $cfg_ref } );

  # Now proceed if blacklist is enabled
  if ( !$cfg_ref->{'disabled'} ) {
    my @areas;

    # Add areas to process only if they contain sources
    for my $area (qw/domains zones hosts/) {
      push( @areas, $area )
        if ( scalar( keys %{ $cfg_ref->{$area}->{'src'} } ) );
    }

    # Feed all blacklists from the zones and domains into host's exclude list
    for my $list (qw{domains zones}) {
      while ( my ( $key, $value )
        = each( %{ $cfg_ref->{$list}->{'exclude'} } ) )
      {
        $cfg_ref->{'hosts'}->{'exclude'}->{$key} = $value;
      }
    }

    # Process each area
    my $area_count = (@areas);
    for my $area (@areas) {
      my ( $prefix, @threads );
      my $max_thrds = 8;
      my @sources   = keys %{ $cfg_ref->{$area}->{'src'} };
      $cfg_ref->{$area}->{'icount'}
        = scalar( keys %{ $cfg_ref->{$area}->{'blklst'} } ) // 0;
      $cfg_ref->{$area}->{'records'} = $cfg_ref->{$area}->{'icount'};
      $cfg_ref->{$area}->{'unique'}  = $cfg_ref->{$area}->{'icount'};

      # Remove any files that no longer have configured sources
      my $sources_ref = {
        map {
          my $key = $_;
          "$cfg_ref->{'dnsmasq_dir'}/$area.$key.blacklist.conf" => 1;
        } @sources
      };
      my $files_ref = {
        map { my $key = $_; $key => 1; } &get_directory(
          {
            directory => $cfg_ref->{'dnsmasq_dir'},
            pattern   => "$area.*blacklist.conf"
          }
        )
      };

      for my $file ( keys $files_ref ) {
        delete_file( { file => $file } ) if !exists $sources_ref->{$file};
      }

      # write each configured area's includes into individual dnsmasq files
      if ( $cfg_ref->{$area}->{'icount'} > 0 ) {
        my $equals = ( $area ne 'domains' ) ? '=/' : '=/.';
        my $file
          = "$cfg_ref->{'dnsmasq_dir'}/$area.pre-configured.blacklist.conf";
        write_file(
          {
            file   => $file,
            target => $cfg_ref->{$area}->{'target'},
            equals => $equals,
            ip     => $cfg_ref->{$area}->{'dns_redirect_ip'},
            data   => [ sort keys %{ $cfg_ref->{$area}->{'blklst'} } ],
          }
        ) or die( sprintf( "Could not open file: s% $!", $file ) );
      }

      for my $source (@sources) {
        my $url  = $cfg_ref->{$area}->{'src'}->{$source}->{'url'};
        my $file = $cfg_ref->{$area}->{'src'}->{$source}->{'file'};
        my $uri  = new URI($url);
        my $host = $uri->host;

        $prefix
          = $cfg_ref->{$area}->{'src'}->{$source}->{'prefix'} ~~ 'http'
          ? qr{(?:^(?:http:|https:){1}[/]{1,2})}o
          : $cfg_ref->{$area}->{'src'}->{$source}->{'prefix'};

        if ( scalar($url) ) {
          log_msg(
            {
              msg_typ => 'INFO',
              msg_str =>
                sprintf( 'Downloading %s blacklist from %s', $area, $host )
            }
          ) if $show;

          push(
            @threads,
            threads->create(
              { 'context' => 'list', 'exit' => 'thread_only' },
              \&get_url,
              {
                area   => $area,
                host   => $host,
                prefix => $prefix,
                src    => $source,
                url    => $url
              }
            )
          );
        }
        elsif ($file) {    # get file data
          push(
            @threads,
            threads->create(
              { 'context' => 'list', 'exit' => 'thread_only' },
              \&get_file,
              { file => $file, src => $source }
            )
          );
        }
        sleep(1) while ( scalar threads->list(threads::running) >= $max_thrds );
      }

      for my $thread (@threads) {
        my $compress;
        my $data_ref = $thread->join();
        my $rec_count = scalar( keys( %{ $data_ref->{'data'} } ) ) // 0;

        $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'records'} += $rec_count;

        if (
          exists $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }
          ->{'compress'} )
        {
          $compress
            = (
            $cfg_ref->{$area}->{'src'}->{ $data_ref->{'src'} }->{'compress'} eq
              'true' ) ? TRUE : FALSE;
        }
        else {
          $compress = FALSE;
        }

        log_msg(
          {
            msg_typ => 'INFO',
            msg_str => sprintf(
              '%s lines received from: %s ',
              $rec_count, $data_ref->{'host'}
            )
          }
        ) if exists $data_ref->{'host'};

        if (
          process_data(
            {
              area     => $area,
              data     => \%{ $data_ref->{'data'} },
              compress => $compress,
              config   => $cfg_ref,
              prefix   => $prefix,
              src      => $data_ref->{'src'}
            }
          )
          )
        {
          if ( $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'icount'} > 0 ) {
            my $equals = ( $area ne 'domains' ) ? '=/' : '=/.';
            my $file
              = "$cfg_ref->{'dnsmasq_dir'}/$area.$data_ref->{'src'}.blacklist.conf";
            write_file(
              {
                file   => $file,
                target => $cfg_ref->{$area}->{'target'},
                equals => $equals,
                ip     => $cfg_ref->{$area}->{'dns_redirect_ip'},
                data   => [
                  sort keys
                    %{ $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'blklst'} }
                ],
              }
            ) or die( sprintf( "Could not open file: s% $!", $file ) );

            $cfg_ref->{$area}->{'unique'} += scalar(
              keys %{ $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'blklst'} } );
            $cfg_ref->{$area}->{'icount'}
              += $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'icount'};
            $cfg_ref->{$area}->{'records'}
              += $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'records'};

            # Discard the data now its written to file
            $cfg_ref->{$area}->{ $data_ref->{'src'} }->{'blklst'} = ();
          }
        }
        else {
          # Get outta here if no records returned from all area sources
          log_msg(
            {
              msg_typ => 'ERROR',
              msg_str => 'Zero source records returned from $area!'
            }
          );
        }
      }

      log_msg(
        {
          msg_typ => 'INFO',
          msg_str => sprintf(
            'Processed %s unique %s from %s records (%s orig. lines)%s',
            $cfg_ref->{$area}->{'unique'}, $cfg_ref->{$area}->{'type'},
            $cfg_ref->{$area}->{'icount'}, $cfg_ref->{$area}->{'records'},
            qq{\n},
          )
        }
      );

      $area_count--;
      say(q{})
        if ( $area_count == 1 )
        && ( $show || $debug );    # print a final line feed
    }
  }
  elsif ( $cfg_ref->{'disabled'} ) {
    for my $area (qw{domains hosts zones}) {
      for my $file (
        &get_directory(
          {
            directory => $cfg_ref->{'dnsmasq_dir'},
            pattern   => "$area.*.blacklist.conf"
          }
        )
        )
      {
        delete_file( { file => $file } );
      }
    }
  }

  # Select the appropriate dnsmasq restart for CLI configure or bash shell
  my $cmd
    = is_configure()
    ? '/opt/vyatta/sbin/vyatta-dns-forwarding.pl --update-dnsforwarding'
    : "$dnsmasq_svc force-reload > /dev/null 2>1&";

  # Clean up the status line
  print( "\r", " " x $cols, "\r" ) if $show;

  log_msg(
    { msg_typ => 'INFO', msg_str => 'Reloading dnsmasq configuration...' } );

  # Reload updated dnsmasq conf address redirection files
  qx($cmd);

  # Close the log
  close($LH);

  # Finish with a linefeed if '-v' or debug is selected
  say(q{}) if $show || $debug;
}

# Crunch the data and throw anything we don't need
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

  print( "\r", " " x $cols, "\r" ) if $show;

LINE:
  for my $line ( keys %{ $input->{'data'} } ) {
    next LINE if $line eq q{} || !defined($line);
    $line =~ s/$re->{PREFIX}//;
    $line =~ s/$re->{SUFFIX}//;
    $line =~ s/$re->{LSPACE}//;
    $line =~ s/$re->{RSPACE}//;

    my @elements = $line =~ m/$re->{FQDOMN}/gc;
    next LINE if !scalar(@elements);

    map {
      my $element = $_;
      my @domain = split( /[.]/, $element );

      shift(@domain) if ( scalar(@domain) > 2 );
      my $elem_count = scalar(@domain);
      my $domain_name = join( '.', @domain );

      my @keys;
      for my $i ( 2 .. $elem_count ) {
        push(@keys, join( '.', @domain ));
        shift(@domain);
      }

      my $key_exists = FALSE;
      for my $key (@keys) {
        $key_exists = TRUE if exists $input->{'config'}->{'hosts'}->{'exclude'}->{$key}
      }

      if ( !$key_exists )
      {
        ( $input->{'compress'} == TRUE )
          ? $input->{'config'}->{ $input->{'area'} }->{ $input->{'src'} }
          ->{'blklst'}->{$domain_name} = 1
          : $input->{'config'}->{ $input->{'area'} }->{ $input->{'src'} }
          ->{'blklst'}->{$element} = 1;
      }

      # Add to the exclude list, so the next source doesn't duplicate values
      $input->{'config'}->{ $input->{'area'} }->{'exclude'}->{$element}
        = 1;
      $input->{'config'}->{ $input->{'area'} }->{'exclude'}->{$domain_name}
        = 1;
    } @elements;

    $input->{'config'}->{ $input->{'area'} }->{ $input->{'src'} }->{'icount'}
      += scalar(@elements);

    printf(
      "Entries processed from %s: %s %s from: %s lines\r",
      $input->{'src'},
      $input->{'config'}->{ $input->{'area'} }->{ $input->{'src'} }->{'icount'},
      $input->{'config'}->{ $input->{'area'} }->{'type'},
      $input->{'config'}->{ $input->{'area'} }->{ $input->{'src'} }->{'records'}
    ) if $show;

  }

  if (
    scalar(
      $input->{'config'}->{ $input->{'area'} }->{ $input->{'src'} }->{'icount'}
    )
    )
  {
    return $input;
  }
}

# Process command line options and print usage
sub usage {
  my $input    = shift;
  my $progname = basename($0);
  my $usage    = {
    cfg_file => sub {
      my $exitcode = shift;
      print STDERR (
        "$cfg_file not found, check path and file name is correct\n");
      exit($exitcode);
    },
    cli => sub {
      my $exitcode = shift;
      print STDERR (
        "You must run $0 inside of configure when '--cli' is specified!\n");
      exit($exitcode);
    },
    enable => sub {
      my $exitcode = shift;
      print STDERR (
        "\n    ERROR: '--enable' and '--disable' are mutually exclusive options!\n\n"
      );
      usage( { option => 'help', exit_code => $exitcode } );
    },
    default => sub {
      my $exitcode = shift;
      print STDERR (
        "\n    ERROR: '--cfg_file' and '--default' are mutually exclusive options!\n\n"
      );
      usage( { option => 'help', exit_code => $exitcode } );
    },
    help => sub {
      my $exitcode = shift;
      local $, = "\n";
      print STDERR (@_);
      print STDERR ("usage: $progname <options>\n");
      print STDERR (
        'options:',
        map( ' ' x 4 . $_->[0],
          sort { $a->[1] cmp $b->[1] }
          grep ( $_->[0] ne '', @{ get_options( { option => TRUE } ) } ) ),
        "\n"
      );
      $exitcode == 9 ? return (1) : exit($exitcode);
    },
    sudo => sub {
      my $exitcode = shift;
      print STDERR ("This script must be run as root, use: sudo $0.\n");
      exit($exitcode);
    },
    version => sub {
      my $exitcode = shift;
      printf STDERR ( "%s version: %s\n", $progname, $version );
      exit($exitcode);
    },
  };

  # Process option argument
  $usage->{ $input->{'option'} }->( $input->{'exit_code'} );
}

# Write the data to file
sub write_file {
  my $input = shift;
  open( my $FH, '>', $input->{'file'} ) or return FALSE;
  log_msg(
    {
      msg_typ => 'INFO',
      msg_str => sprintf( "Saving %s", basename( $input->{'file'} ) )
    }
  );

  for my $val ( @{ $input->{'data'} } ) {
    printf {$FH} ("%s%s%s/%s\n"), $input->{'target'}, $input->{'equals'}, $val,
      $input->{'ip'};
  }

  close($FH);

  return TRUE;
}
