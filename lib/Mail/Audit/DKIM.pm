use strict;
use warnings;
package Mail::Audit::DKIM;
# ABSTRACT: Mail::Audit plugin for domain key verification
use Mail::DKIM::Verifier;

use Sub::Exporter 0.900 -setup => {
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

=method dkim_result

This returns the result of the DKIM verifier.

=method dkim_result_detail

This returns not just the one-word result code, but any available details.

=method dkim_passes

This method returns true if the signature was verified.

=head1 SEE ALSO

L<Mail::Audit>, L<Mail::DKIM>
