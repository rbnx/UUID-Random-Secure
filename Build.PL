use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'UUID::Random::Secure',
    license             => 'artistic_2',
    dist_author         => q{Ruben Navarro <ruben@cpan.org>},
    dist_version_from   => 'lib/UUID/Random/Secure.pm',
    release_status      => 'stable',
    configure_requires => {
        'Module::Build' => 0,
    },
    build_requires => {
        'Test::More' => 0,
        'Module::Build' => 0,
    },
    requires => {
        'Exporter'      => 0,
    },
    add_to_cleanup     => [ 'UUID-Random-Secure-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
