# NAME

UUID::Random::Secure - Cryptographically-secure random UUID generator

# VERSION

version 0.01

# SYNOPSIS
```
use UUID::Random::Secure qw(generate_uuid);
use feature qw(say);

say generate_uuid();
say UUID::Random::Secure->generate();
say UUID::Random::Secure->new->generate();
```

# DESCRIPTION

UUID::Random::Secure generates cryptographically-secure UUID strings. 
It tries to use one of the following pseudo-random number generators:

- Crypt::PRNG
- Crypt::OpenSSL::Random
- Bytes::Random::Secure
- Net::SSLeay
- Crypt::Random
- Math::Random::Secure

If none of these modules can be loaded or are already loaded
Perl’s rand will be used as an unsecure fallback. 

# INSTALLATION

To install this module, run the following commands:

    perl Build.PL
    ./Build
    ./Build test
    ./Build install

# AUTHOR
    Ruben Navarro <ruben@cpan.org>

# COPYRIGHT AND LICENSE


    Copyright 2016 Ruben Navarro.

    This program is free software; you can redistribute it and/or modify it
    under the terms of the the Artistic License (2.0). 
