#!/usr/bin/env perl
#
# **** License ****
# COPYRIGHT AND LICENCE
#
# Copyright (C) 2016 by Neil Beadle
#
# This script is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself, either Perl version 5.23.4 or,
# at your option, any later version of Perl 5 you may have available.
#
# Author: Neil Beadle
# Date:   January 2016
# Description: Script for creating dnsmasq configuration files to redirect dns
# look ups to alternative IPs (blackholes, pixel servers etc.)
#
# **** End License ****

use File::Basename;
use Getopt::Long;
use lib q{/opt/vyatta/share/perl5};
use lib q{/config/lib/perl};
use Sys::Syslog qw(:standard :macros);
use threads;
use v5.14;
# use strict;
# use warnings;
use EdgeOS::DNS::Blacklist (
  qw{
    $c
    $FALSE
    $TRUE
    delete_file
    get_cfg_actv
    get_cfg_file
    get_cols
    get_file
    get_url
    is_admin
    is_configure
    log_msg
    pad_str
    process_data
    write_file
    }
);
delete $ENV{PATH};
my ( $cfg_file, $show );
my $version = q{3.5.3};
my $cols    = get_cols();

############################### script runs here ###############################
exit 0 if &main();
################################################################################

# Set up command line options
sub get_options {
  my $input = shift;
  my @opts = (
               [
                 q{-f <file> # load a configuration file},
                 q{f=s} => \$cfg_file
               ],
               [
                 q{-help     # show help and usage text},
                 q{help} => sub { usage( {option => q{help}, exit_code => 0} ) }
               ],
               [ q{-v        # verbose output}, q{v} => \$show ],
               [
                 q{-version  # show program version number},
                 q{version} =>
                   sub { usage( {option => q{version}, exit_code => 0} ) }
               ],
             );

  return \@opts if $input->{option};

  # Read command line flags and exit with help message if any are unknown
  return GetOptions( map { my $options = $_; (@$options)[ 1 .. $#$options ] }
                     @opts );
  return;
}

# This is the main function
sub main {
  my $dnsmasq_svc = q{/etc/init.d/dnsmasq};
  my $cfg = {
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
  get_options() or usage( {option => q{help}, exit_code => 1} );

  # Find reasons to quit
  exit 0 if ( -f $cfg->{no_op} );    # If the no_op file exists, exit.

  usage( {option => q{sudo}, exit_code => 1} ) if not is_admin();
  usage( {option => q{cfg_file}, exit_code => 1} )
    if defined $cfg_file && !-f $cfg_file;

  # Start logging
  openlog( $cfg->{log_name}, q{}, LOG_DAEMON );
  log_msg(
           {
            cols    => $cols,
            show    => $show,
            msg_typ => q{info},
            msg_str =>,
            qq{---+++ dnsmasq blacklist $version +++---},
           }
         );

  # Make sure localhost is always in the exclusions whitelist
  $cfg->{hosts}->{exclude}->{localhost} = 1;

  # Now choose which data set will define the configuration
  my $success
    = defined $cfg_file
    ? get_cfg_file( {config => $cfg, file => $cfg_file} )
    : get_cfg_actv( {config => $cfg, show => $show} );

  log_msg(
          {
           cols    => $cols,
           show    => $show,
           msg_typ => q{error},
           msg_str => qq{Cannot load dnsmasq blacklist configuration - exiting},
          }
         ),
    return
    if !$success;

  # Now proceed if blacklist is enabled
  if ( !$cfg->{disabled} ) {
    my @areas = ();

    # Add areas to process only if they contain sources and copy global excludes
    for my $area (qw{domains hosts zones}) {
      push @areas => $area if scalar keys %{$cfg->{$area}->{src}};
    }

    # Process each area
    my $area_count = (@areas);
    for my $area (@areas) {
      my ( $prefix, @threads );
      my $max_thrds = 8;
      my @sources   = keys %{$cfg->{$area}->{src}};
      while ( my ( $key, $value ) = each %{$cfg->{exclude}} ) {
        $cfg->{$area}->{exclude}->{$key} = $value;
      }
      $cfg->{$area}->{icount} = scalar keys %{$cfg->{$area}->{blklst}} // 0;
      @{$cfg->{$area}}{q{records}, q{unique}}
        = @{$cfg->{$area}}{q{icount}, q{icount}};

      # Remove any files that no longer have configured sources
      my $sources_ref = {
        map {
          my $key = $_;
          qq{$cfg->{dnsmasq_dir}/$area.$key.blacklist.conf} => 1;
          } @sources
      };

      my $files_ref = {map { my $key = $_; $key => 1; }
                       glob qq{$cfg->{dnsmasq_dir}/$area.*blacklist.conf}};

      for my $file ( keys $files_ref ) {
        delete_file( {file => $file} )
          if !exists $sources_ref->{$file} && $file;
      }

      # write each configured areas includes into individual dnsmasq files
      if ( $cfg->{$area}->{icount} > 0 ) {
        my $equals = $area ne q{domains} ? q{=/} : q{=/.};
        write_file(
          {
           data => [
             map {
               my $value = $_;
               sprintf qq{%s%s%s/%s\n} => $cfg->{$area}->{target},
                 $equals, $value, $cfg->{$area}->{dns_redirect_ip};
               } sort keys %{$cfg->{$area}->{blklst}}
           ],
           file => qq{$cfg->{dnsmasq_dir}/$area.pre-configured.blacklist.conf},
          }
        );
      }

      for my $source (@sources) {
        my ( $file, $url )
          = @{$cfg->{$area}->{src}->{$source}}{q{file}, q{url}};
        my $uri  = new URI($url);
        my $host = $uri->host;

        # Initialize the sources counters
        @{$cfg->{$area}->{src}->{$source}}{qw(duplicates icount records unique)}
          = ( 0, 0, 0, 0 );

        $prefix
          = $cfg->{$area}->{src}->{$source}->{prefix} ~~ q{http}
          ? qr{(?:\A(?:http:|https:){1}[/]{1,2})}om
          : $cfg->{$area}->{src}->{$source}->{prefix};

        if ($url) {
          log_msg(
               {
                cols    => $cols,
                show    => $show,
                msg_typ => q{info},
                msg_str => sprintf q{Downloading %s blacklist from %s} => $area,
                $host,
               }
            )
            if $show;
          push @threads =>
            threads->create(
                             {context => q{list}, exit => q{thread_only}},
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
          push @threads =>
            threads->create( {context => q{list}, exit => q{thread_only}},
                             \&get_file, {file => $file, src => $source} );
        }
        sleep 1 while ( scalar threads->list(threads::running) >= $max_thrds );
      }

      for my $thread (@threads) {
        my $data = $thread->join();
        my $rec_count = scalar keys %{$data->{data}} // 0;

        $cfg->{$area}->{src}->{$data->{src}}->{records} += $rec_count;

        if ( exists $data->{host} && scalar $rec_count ) {
          log_msg(
               {
                cols    => $cols,
                show    => $show,
                msg_typ => q{info},
                msg_str => sprintf q{%s lines received from: %s } => $rec_count,
                $data->{host},
               }
          );

          # Now process what we have received from the web host
          process_data(
                        {
                         area   => $area,
                         cols   => $cols,
                         config => $cfg,
                         data   => \%{$data->{data}},
                         prefix => $data->{prefix},
                         show   => $show,
                         src    => $data->{src}
                        }
                      );

          delete $data->{data};

          # Write blacklist to file, change to domain format if area = domains
          if ( $cfg->{$area}->{src}->{$data->{src}}->{icount} > 0 ) {
            my $equals = $area ne q{domains} ? q{=/} : q{=/.};
            write_file(
              {
               data => [
                 map {
                   my $value = $_;
                   sprintf qq{%s%s%s/%s\n} => $cfg->{$area}->{target},
                     $equals, $value, $cfg->{$area}->{dns_redirect_ip};
                   } sort keys %{$cfg->{$area}->{src}->{$data->{src}}->{blklst}}
               ],
               file =>
                 qq{$cfg->{dnsmasq_dir}/$area.$data->{src}.blacklist.conf},
              }
            );

            # Compute statistics
            $cfg->{$area}->{unique}
              += scalar keys %{$cfg->{$area}->{src}->{$data->{src}}->{blklst}};
            $cfg->{$area}->{duplicates}
              += $cfg->{$area}->{src}->{$data->{src}}->{duplicates};
            $cfg->{$area}->{icount}
              += $cfg->{$area}->{src}->{$data->{src}}->{icount};
            $cfg->{$area}->{records}
              += $cfg->{$area}->{src}->{$data->{src}}->{records};

            # Discard the data now its written to file
            delete $cfg->{$area}->{src}->{$data->{src}};
          }
          else {
            log_msg(
                     {
                      cols    => $cols,
                      show    => $show,
                      msg_typ => q{warning},
                      msg_str => qq{Zero records processed from $data->{src}!},
                     }
                   );
          }
        }
      }

      log_msg(
         {
          cols    => $cols,
          show    => $show,
          msg_typ => q{info},
          msg_str => sprintf(
            qq{Processed $c->{grn}%s$c->{clr} %s ($c->{red}%s$c->{clr} }
              . qq{discarded) from $c->{mag}%s$c->{clr} records (%s orig.)%s} =>
              @{$cfg->{$area}}{qw(unique type duplicates icount records)},
            qq{\n}
          ),
         }
      );

      my @flagged_domains;

      # Now lets report the domains that were seen more than $cfg->{flag_lvl}
      for my $key (
        sort {
          $cfg->{hosts}->{exclude}->{$b} <=> $cfg->{hosts}->{exclude}->{$a}
        } sort keys %{$cfg->{hosts}->{exclude}}
        )
      {
        my $value = $cfg->{hosts}->{exclude}->{$key};
        if ( $value >= $cfg->{flag_lvl} && length $key > 5 ) {
          log_msg(
                {
                 cols    => $cols,
                 show    => $show,
                 msg_typ => q{info},
                 msg_str => sprintf qq{$area blacklisted: domain %s %s times} =>
                   $key,
                 $value,
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
                 qq{set service dns forwarding blacklist domains include %s\n}
                 => $value;
               } @flagged_domains
           ],
           file => $cfg->{flag_file},
          }
        );

        log_msg(
               {
                cols    => $cols,
                show    => $show,
                msg_typ => q{info},
                msg_str =>
                  qq{Flagged domains command set written to: $cfg->{flag_file}},
               }
        );
      }

      $area_count--;
      say q{} if $area_count == 1 && $show;    # print a final line feed
    }
  }
  elsif ( $cfg->{disabled} ) {
    for my $file (
             glob qq{$cfg->{dnsmasq_dir}/{domains,hosts,zones}*blacklist.conf} )
    {
      delete_file( {file => $file} ) if $file;
    }
  }

  # Clean up the status line
  print $c->{off}, qq{\r}, pad_str(), qq{\r} if $show;

  log_msg(
           {
            cols    => $cols,
            show    => $show,
            msg_typ => q{info},
            msg_str => q{Reloading dnsmasq configuration...},
           }
         );

  # Reload updated dnsmasq conf address redirection files
  qx{$dnsmasq_svc force-reload > /dev/null 2>1&};
  log_msg(
           {
            cols    => $cols,
            show    => $show,
            msg_typ => q{error},
            msg_str => q{Reloading dnsmasq configuration failed},
           }
         )
    if ( $? >> 8 != 0 );

  # Close the log
  closelog();

  # Finish with a linefeed if '-v' is selected
  say $c->{on}, q{} if $show;
}

# Process command line options and print usage
sub usage {
  my $input    = shift;
  my $progname = basename($0);
  my $usage = {
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
             @{get_options( {option => $TRUE} )} ),
        qq{\n};
      $exitcode == 9 ? return $TRUE : exit $exitcode;
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
  $usage->{$input->{option}}->( $input->{exit_code} );
}

