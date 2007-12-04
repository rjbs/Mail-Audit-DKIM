use strict;
use warnings;

use inc::Module::Install;

name          ('Mail-Audit-DKIM');
author        ('Ricardo SIGNES <rjbs@cpan.org>');
license       ('perl');
all_from      ('lib/Mail/Audit/DKIM.pm');

requires('Mail::Audit'      => 0.000); # version unknown
requires('Mail::DKIM'       => 0.000); # version unknown
requires('Sub::Exporter'    => 0.900); # almost any version probably okay

WriteAll();
