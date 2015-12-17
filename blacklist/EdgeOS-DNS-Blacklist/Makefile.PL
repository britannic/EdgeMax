use 5.023004;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'EdgeOS::DNS::Blacklist',
    VERSION_FROM      => 'lib/EdgeOS/DNS/Blacklist.pm', # finds $VERSION, requires EU::MM from perl >= 5.5
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/EdgeOS/DNS/Blacklist.pm', # retrieve abstract from module
    AUTHOR            => 'Neil Beadle <blacklist@empirecreekcircle.com>',
    LICENSE           => 'perl',
    #Value must be from legacy list of licenses here
    #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
);
