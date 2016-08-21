#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'UUID::Random::Secure' ) || print "Bail out!\n";
}

diag( "Testing UUID::Random::Secure $UUID::Random::Secure::VERSION, Perl $], $^X" );
