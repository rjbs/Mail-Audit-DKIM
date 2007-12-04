#!perl
use strict;
use warnings;
use Mail::Audit;
use Mail::Audit::DKIM;

use Test::More tests => 10;

sub test_msg {
  my ($fn) = @_;
  open my $fh, '<', $fn or die "couldn't open $fn: $!";
  my $lines = [ <$fh> ];
  return Mail::Audit->new(data => $lines);
}

my %file = (
  'ignore_1.txt'      => 'invalid',
  'bad_ietf01_1.txt'  => 'fail',
  'good_ietf00_1.txt' => 'pass',
  'mine_ietf01_1.txt' => 'pass',
  'no-sig.t'          => 'none',
);

for my $file (keys %file) {
  my $ma = test_msg("t/corpus/$file");
  can_ok($ma, 'dkim_result'); # Test every time because of MA's insane ISA
  is($ma->dkim_result, $file{$file}, "$file result should be $file{$file}");
}
