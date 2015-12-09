#!/usr/bin/env perl
#
use strict;
use warnings;
use v5.14;

my @domains= (
'122.2o7.net/',
'1e100.net/',
'adobedtm.com/',
'akamai.net/',
'amazonaws.com/',
'apple.com/',
'ask.com/',
'cdn.visiblemeasures.com/',
'cloudfront.net/',
'coremetrics.com/',
'doubleclick.net/',
'edgesuite.net/',
'freedns.afraid.org/',
'github.com/',
'githubusercontent.com/',
'google.com/',
'googleadservices.com/',
'googleapis.com/',
'googleusercontent.com/',
'gstatic.com/',
'gvt1.net/',
'hb.disney.go.com/',
'hulu.com/',
'intellitxt.com/',
'msdn.com/',
'paypal.com/',
'schema.org/',
'smacargo.com/',
'ssl-on9.com/',
'ssl-on9.net/',
'static.chartbeat.com/',
'storage.googleapis.com/',
'ytimg.com/',);

for my $domain (@domains) {
  my $found = qx{grep $domain /etc/dnsmasq.d/*};
  say $found if $found;
}
