#!/usr/bin/env perl
#
use diagnostics;
use feature qw{switch};
use strict;
use Text::Wrap;
use v5.14;
use warnings;
no warnings 'experimental::smartmatch';

use constant TRUE  => 1;
use constant FALSE => 0;

my $cols = qx{tput cols};

sub menu {
  my $input = shift;
  chomp( my @menu = @{ $input->{menu_opts} } );
  my $opt;
  while (TRUE) {
    print qq{$menu[0]\n};
    print map { $opt = $_; qq{\t$opt. $menu[$opt]\n} } ( 1 .. $#menu );
    print qq{Select (1 - $#menu) => };
    chomp( $opt = <STDIN> );
    last if ( ( $opt > FALSE ) && ( $opt <= $#menu ) );
    print qq{$opt. is not a valid option.\n\n};
  }
  return qq{$menu[$opt]\n};
}

$Text::Wrap::columns = $cols -= 4;

my $menu_title =  wrap(q{}, q{}, q{Would you like to install, remove or test dnsmasq blacklist }
  . q{functionality (if previously installed)?});
my @menu_opts = ($menu_title, qw(INSTALL REMOVE TEST QUIT));

my $choice = menu( { menu_opts => \@menu_opts } );

given(lc $choice) {
  when (/install/) {}
  when (/remove/) {}
  when (/test/) {}
  when (/quit|q[quit]*/
}
