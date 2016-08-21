package UUID::Random::Secure;
use strict;
use warnings;

our $VERSION = '0.01';

use base 'Exporter';
our @EXPORT = qw/generate_uuid/;
my $BYTELEN = 128 / 8;

our $PRNG;

our @models = (
  [ 'Crypt::PRNG' => '_random_bytes_hex_CP'             ],
  [ 'Crypt::OpenSSL::Random' => '_random_bytes_hex_COR' ],
  [ 'Bytes::Random::Secure' => '_random_bytes_hex_BRS'  ],
  [ 'Net::SSLeay' => '_random_bytes_hex_NS'             ],
  [ 'Crypt::Random' => '_random_bytes_hex_CR'           ],
  [ 'Math::Random::Secure' => '_random_bytes_hex_MRS'   ],
);

sub new{ bless {},shift };

sub generate {
  my $hex = _random_bytes_hex();
  return join('-',unpack("A8A4A4A4A12",$hex));
}

*generate_uuid = \&generate;

sub _random_bytes_hex{
  my $length = shift;

  my $impl_name = @{ _detect_prng() }[1];
  my $impl = \&{$impl_name};
  my $out = $impl->($BYTELEN) || _random_bytes_hex_fallback($BYTELEN)
}

sub _random_bytes_hex_CP {
  my $length = shift;
  return Crypt::PRNG::random_bytes_hex($length);
}

sub _random_bytes_hex_COR {
  my $length = shift;
  my $bytes;
  if (Crypt::OpenSSL::Random::random_status()) {
    $bytes = Crypt::OpenSSL::Random::random_bytes($length);
    return unpack( 'H*', $bytes );
  }
  return
}

sub _random_bytes_hex_BRS {
  my $length = shift;
  Bytes::Random::Secure::random_bytes_hex($length)
}

sub _random_bytes_hex_NS {
  my $length = shift;
  my $bytes;
  if (Net::SSLeay::RAND_status() == 1) {
    if (Net::SSLeay::RAND_bytes($bytes, $length) == 1) {
      return unpack( 'H*', $bytes );
    }
  }
  return
}

sub _random_bytes_hex_CR {
  my $length = shift;
  my $bytes =  Crypt::Random::makerandom_octet(Length=>$length);
  return unpack( 'H*', $bytes );
}

sub _random_bytes_hex_fallback {
  my $length = shift;
  my @chars = ('a'..'f',0..9);
  join '', map $chars[ irand(scalar @chars) ], 1 .. $length * 2
}

sub _random_bytes_hex_MRS {
  no warnings 'redefine';
  *irand = \&Math::Random::Secure::rand;
  return
}

sub _is_module_loaded {
  my $module = shift;
  foreach my $i(keys %INC){
    $i =~ s{/}{::}g;
    $i =~ s{.pm}{};
    return 1 if($i eq $module);
  }
  return
}

sub _detect_prng {
  return $PRNG if $PRNG;

  foreach my $m(@models) {
    if (_is_module_loaded($m->[0]) ) {
      return $PRNG = $m;
    }
  }

  foreach my $m(@models){
    if(eval "require @{[ $m->[0] ]}"){
      return $PRNG = $m;
    }
  }
 
  return;
}

sub irand(;$) {
  rand(shift);
}

1;

__END__
=head1 NAME

UUID::Random::Secure - Cryptographically-secure random UUID generator

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

    use UUID::Random::Secure qw(generate_uuid);
    use feature qw(say);

    say generate_uuid();
    say UUID::Random::Secure->generate();
    say UUID::Random::Secure->new->generate();


=head1 DESCRIPTION

UUID::Random::Secure generates cryptographically-secure UUID strings. 
It tries to use one of the following pseudo-random number generators:

=over

=item * L<Crypt::PRNG>

=item * L<Crypt::OpenSSL::Random>

=item * L<Bytes::Random::Secure>

=item * L<Net::SSLeay>

=item * L<Crypt::Random>

=item * L<Math::Random::Secure>


=back

If none of these modules can be loaded or are already loaded
Perl's rand will be used as an unsecure fallback. 


=head1 AUTHOR

Ruben Navarro, C<< <ruben@cpan.org> >>

=head1 SUPPORT

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/rbnx/UUID-Random-Secure/issues>.


=head1 LICENSE AND COPYRIGHT

Copyright 2016 Ruben Navarro.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). 

=cut
