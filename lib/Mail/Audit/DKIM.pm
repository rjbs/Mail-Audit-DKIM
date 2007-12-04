use strict;
use warnings;

package Mail::Audit::DKIM;
use Mail::DKIM::Verifier;

use Sub::Exporter -setup => {
  into    => 'Mail::Audit',
  exports => [ qw(result result_detail passes) ],
  groups  => [ default => [ -all => { -prefix => 'dkim_' } ] ],
};

sub _result_detail {
  my ($mail_audit) = @_;

  return $mail_audit->{__PACKAGE__}{result_detail} ||= do {
    my $verifier = Mail::DKIM::Verifier->new;

    my $string = $mail_audit->as_string;
    my @lines = split /\x0d\x0a|\x0a\x0d|\x0a|\x0d/, $string;

    for my $line (@lines) {
      $verifier->PRINT($line . "\x0d\x0a");
    }
    $verifier->CLOSE;

    $verifier->result_detail;
  };
}

sub result_detail {
  my ($mail_audit) = @_;
  return _result_detail($mail_audit);
}

sub result {
  my ($mail_audit) = @_;
  my ($result) = _result_detail($mail_audit) =~ /\A(\w+)(?:\s|$)/;
  return $result;
}

sub passes {
  my ($mail_audit) = @_;
  return _result_detail($mail_audit) =~ /^pass/;
}

1;

__END__

=pod

=head1 NAME

Mail::Audit::DKIM - Mail::Audit plugin for domain key verification

=head1 SYNOPSIS

  use Mail::Audit qw(DKIM);

  my $mail = Mail::Audit->new;
  ...
  if ($mail->dkim_passes) {
    $self->log("dkim verified!");
  }

=head1 DESCRIPTION

This method adds some very simple domain key verification to Mail::Audit.  In
general, consult L<Mail::DKIM> for more information.

=head1 METHODS

=head1 dkim_result

This returns the result of the DKIM verifier.

=head1 dkim_result_detail

This returns not just the one-word result code, but any available details.

=head1 dkim_passes

This method returns true if the signature was verified.

=head1 PERL EMAIL PROJECT

This module is maintained by the Perl Email Project.

  http://emailproject.perl.org/wiki/Mail::Audit::DKIM

=head1 COPYRIGHT

Copyright 2007, Ricardo SIGNES <rjbs@cpan.org>

=head1 SEE ALSO

L<Mail::Audit>, L<Mail::DKIM>
