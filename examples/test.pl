use strict;
use warnings;
use POE qw(Component::Server::SimpleSMTP Component::Client::SMTP);
use Email::Simple::Creator;
use Data::Dumper;

my $from = 'chris@bingosnet.co.uk';
my $to = 'chris.williams@staffordshire.gov.uk';

my $email = Email::Simple->create(
      header => [
        From    => $from,
        To      => $to,
        Subject => 'Message in a bottle',
      ],
      body => 'M33p m33p m33p',
);

POE::Session->create(
	package_states => [
		'main' => [ qw(_start _default smtpd_registered _success _failure smtpd_message) ],
	],
	heap => { from => $from, to => $to, email => $email->as_string },
);

$poe_kernel->run();
exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  my $smptd = POE::Component::Server::SimpleSMTP->spawn( alias => 'smtpd', port => 2525, simple => 1 );
  return;
}

sub smtpd_registered {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  POE::Component::Client::SMTP->send(
     From    => $heap->{from},
     To      => $heap->{to},
     Server  =>  'localhost',
     Port    => 2525,
     Body    => $heap->{email},
     Context => 'moo',
     SMTP_Success    =>  '_success',
     SMTP_Failure    =>  '_failure',
  );
  return;
}

sub _default {
  my ($event, $args) = @_[ARG0 .. $#_];
  return 0 unless $event =~ /^smtpd/;
  my @output = ( "$event: " );

  foreach my $arg ( @$args ) {
      if ( ref($arg) eq 'ARRAY' ) {
              push( @output, "[" . join(" ,", @$arg ) . "]" );
      } else {
              push ( @output, "'$arg'" );
      }
  }
  print STDOUT join ' ', @output, "\n";
  return 0;
}

sub _success {
  print "Yay!\n";
  return;
}

sub _failure {
  warn Dumper( $_[ARG1] );
  return;
}

sub smtpd_message {
  my ($mail,$rcpt,$buffer) = @_[ARG1..$#_];
  warn "$mail\n";
  warn Dumper( $rcpt );
  warn Dumper( $buffer );
  return;
}
