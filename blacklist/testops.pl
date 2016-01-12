#!/usr/bin/env perl
#
use strict;
use diagnostics;
use warnings;
use v5.14;
use Text::Balanced qw(extract_bracketed);
use Data::Dumper;
use feature qw/switch/;
no warnings 'experimental::smartmatch';
use List::Util qw(first max maxstr min minstr reduce shuffle sum);

my $cfg_file = '/Users/Neil/EdgeOs/Config.boots/config.boot';
my $cfg_ref = {debug    => 0,
               disabled => 0,
               domains  => {
                           dns_redirect_ip => '0.0.0.0',
                           blacklist       => {},
                           file            => '/etc/dnsmasq.d/domain.blacklist.conf',
                           icount          => 0,
                           records         => 0,
                           target          => 'address',
                           type            => 'domains',
                           unique          => 0,
                          },
               hosts => {dns_redirect_ip => '0.0.0.0',
                         blacklist       => {
                                       'adsrvr.org'         => 1,
                                       'adtechus.net'       => 1,
                                       'advertising.com'    => 1,
                                       'centade.com'        => 1,
                                       'doubleclick.net'    => 1,
                                       'free-counter.co.uk' => 1,
                                       'kiosked.com'        => 1,
                                      },
                         include => {'adobedtm.com'           => 1,
                                     'coremetrics.com'        => 1,
                                     'doubleclick.net'        => 1,
                                     'google.com'             => 1,
                                     'googleadservices.com'   => 1,
                                     'googleapis.com'         => 1,
                                     'hulu.com'               => 1,
                                     'msdn.com'               => 1,
                                     'paypal.com'             => 1,
                                     'storage.googleapis.com' => 1,
                                     'apple.com'              => 1,
                                    },
                         file    => '/etc/dnsmasq.d/host.blacklist.conf',
                         icount  => 0,
                         records => 0,
                         target  => 'address',
                         type    => 'hosts',
                         unique  => 0,
                        },
               zones => {dns_redirect_ip => '0.0.0.0',
                         blacklist       => {},
                         file            => '/etc/dnsmasq.d/zone.blacklist.conf',
                         icount          => 0,
                         records         => 0,
                         target          => 'server',
                         type            => 'zone',
                         unique          => 0,
                        },
               log_file => '/var/log/update-blacklists-dnsmasq.log',
              };

sub get_hash {
  my $input    = shift;
  my $hash     = \$input->{'hash_ref'};
  my @nodes    = @{$input->{'nodes'}};
  my $value    = pop(@nodes);
  my $hash_ref = $$hash;

  for my $key (@nodes) {
    $hash = \$$hash->{$key};
  }

  $$hash = $value if $value;

  return $hash_ref;
}

sub parse_node {
  my $input = shift;
  my (@hasher, @nodes);
  my $cfg_ref = {};
  my $leaf    = 0;
  my $level   = 0;
  my $re = {BRKT => qr/[}]/o,
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

  for my $line (@{$input->{'config_data'}}) {
    $line =~ s/$re->{LSPC}//;
    $line =~ s/$re->{RSPC}//;

    given ($line) {
      when (/$re->{MULT}/) {
        push(@nodes, $+{MULT});
        push(@nodes, $+{VALU});
        my @domain = split(/[.]/, $+{VALU});
        shift(@domain) if scalar(@domain) > 2;
        my $value = join('.', @domain);
        get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{NODE}/) {
        push(@nodes, $+{NODE});
      }
      when (/$re->{LEAF}/) {
        $level++;
        push(@nodes, $+{LEAF});
        push(@nodes, $+{NAME});
      }
      when (/$re->{NAME}/) {
        push(@nodes, $+{NAME});
        push(@nodes, $+{VALU});
        get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{DESC}/) {
        push(@nodes, $+{NAME});
        push(@nodes, $+{DESC});
        get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{MISC}/) {
        push(@nodes, $+{MISC});
        push(@nodes, $+{MISC});
        get_hash({nodes => \@nodes, hash_ref => $cfg_ref});
        pop(@nodes);
        pop(@nodes);
      }
      when (/$re->{CMNT}/) {
        next;
      }
      when (/$re->{BRKT}/) {
        pop(@nodes);
        if ($level > 0) {
          pop(@nodes);
          $level--;
        }
      }
      when (/$re->{MPTY}/) {
        next;
      }
      default {
        print(sprintf('Parse error: "%s"', $line));
      }
    }

  }
  return ($cfg_ref->{'service'}->{'dns'}->{'forwarding'}->{'blacklist'});
}

sub get_file {
  my $input = shift;
  my @cfg_data;

  if ($input->{'cfg_file'}) {
    open(my $CF, '<', $input->{'cfg_file'}) or die "ERROR: Unable to open $cfg_file: $!";
    chomp(@cfg_data = <$CF>);
    close($CF);
    return \@cfg_data;
  }
  else {
    return 0;
  }
}

my $tmp_ref = parse_node({config_data => get_file({cfg_file => $cfg_file})});

my $configured
  = ($tmp_ref->{'domains'}->{'source'} || $tmp_ref->{'hosts'}->{'source'} || $tmp_ref->{'zones'}->{'source'}) ? 1 : 0;

if ($configured) {
  $cfg_ref->{'dns_redirect_ip'} = $tmp_ref->{'dns-redirect-ip'} // '0.0.0.0';
  $cfg_ref->{'disabled'} = $tmp_ref->{'disabled'} eq 'false' ? 0 : 1;

  for my $area (qw/hosts domains zones/) {
    $cfg_ref->{$area}->{'dns_redirect_ip'} = $tmp_ref->{'dns-redirect-ip'}
      if undef($tmp_ref->{$area}->{'dns-redirect-ip'});
    $cfg_ref->{$area}->{'exclude'}   = $tmp_ref->{$area}->{'exclude'};
    $cfg_ref->{$area}->{'blacklist'} = $tmp_ref->{$area}->{'include'};
    $cfg_ref->{$area}->{'source'}    = $tmp_ref->{$area}->{'source'};
  }
}
else {
  die 'Bugger!';
}
print Dumper($cfg_ref);

# my ( $blacklist, $cfg_ref, $domains, $hosts, $zones, $remainder );
# $blacklist = extract_bracketed( $cfg_data, '{}', '\A.*blacklist\s' );
# ( $domains, $remainder )
#     = extract_bracketed( $blacklist, '{}', '\A.*domains\s' );
# ( $hosts, $remainder )
#     = extract_bracketed( $remainder, '{}', '\A                hosts ' );
# ( $zones, $remainder )
#     = extract_bracketed( $remainder, '{}', '\A                zones ' );
#
# say $blacklist;
# say $domains;
# say $hosts;
# say $zones;

my @areas = (qw{neil colin beadle});
for (@areas) {
  pop(@areas);
  if (scalar(@areas) == 1) { say 'It worked'; }    # print a final line feed
}
$cfg_ref = {debug    => 0,
            disabled => 0,
            domains  => {
                        dns_redirect_ip => '0.0.0.0',
                        blacklist       => {},
                        file            => '/etc/dnsmasq.d/domain.blacklist.conf',
                        icount          => 0,
                        records         => 0,
                        target          => 'address',
                        type            => 'domains',
                        unique          => 0,
                       },
            hosts => {dns_redirect_ip => '0.0.0.0',
                      blacklist       => {
                                    'adsrvr.org'         => 1,
                                    'adtechus.net'       => 1,
                                    'advertising.com'    => 1,
                                    'centade.com'        => 1,
                                    'doubleclick.net'    => 1,
                                    'free-counter.co.uk' => 1,
                                    'kiosked.com'        => 1,
                                   },
                      include => {'adobedtm.com'           => 1,
                                  'coremetrics.com'        => 1,
                                  'doubleclick.net'        => 1,
                                  'google.com'             => 1,
                                  'googleadservices.com'   => 1,
                                  'googleapis.com'         => 1,
                                  'hulu.com'               => 1,
                                  'msdn.com'               => 1,
                                  'paypal.com'             => 1,
                                  'storage.googleapis.com' => 1,
                                  'apple.com'              => 1,
                                 },
                      file    => '/etc/dnsmasq.d/host.blacklist.conf',
                      icount  => 0,
                      records => 0,
                      target  => 'address',
                      type    => 'hosts',
                      unique  => 0,
                     },
            zones => {dns_redirect_ip => '0.0.0.0',
                      blacklist       => {},
                      file            => '/etc/dnsmasq.d/zone.blacklist.conf',
                      icount          => 0,
                      records         => 0,
                      target          => 'server',
                      type            => 'zone',
                      unique          => 0,
                     },
            log_file => '/var/log/update-blacklists-dnsmasq.log',
           };

my $element = 'www.60neil.piffle.waffle.dog.doubleclick.net';
my @domain = split(/[.]/, $element);

shift(@domain) if (scalar(@domain) > 2);
my $elem_count = scalar(@domain);
my @value;

for my $i (2 .. $elem_count) {
  push(@value, join('.', @domain));
  shift(@domain);
}
say Dumper(@value) if none { $cfg_ref->{hosts}->{blacklist}->{$_} } @value;

$cfg_ref->{hosts}->{blacklist}->{'beap.gemini.yahoo.com'}

