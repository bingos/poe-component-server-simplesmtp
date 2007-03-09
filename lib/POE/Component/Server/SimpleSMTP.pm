package POE::Component::Server::SimpleSMTP;

use strict;
use POSIX;
use POE qw(Component::Client::SMTP Component::Client::DNS Wheel::ReadWrite Filter::Line);
use base qw(POE::Component::Pluggable);
use POE::Component::Pluggable::Constants qw(:ALL);
use Email::MessageID;
use Email::Simple;
use Email::Address;
use Socket;
use Data::Dumper;
use vars qw($VERSION);

$VERSION = '0.95';

sub spawn {
  my $package = shift;
  my %opts = @_;
  $opts{lc $_} = delete $opts{$_} for keys %opts;
  my $options = delete $opts{options};
  $opts{simple} = 1 unless defined $opts{simple} and !$opts{simple};
  $opts{handle_connects} = 1 unless defined $opts{handle_connects} and !$opts{handle_connects};
  $opts{hostname} = 'localhost' unless defined $opts{hostname};
  $opts{relay} = 0 unless $opts{relay};
  $opts{version} = join('-', __PACKAGE__, $VERSION ) unless $opts{version};
  my $self = bless \%opts, $package;
  $self->_pluggable_init( prefix => 'smtpd_', types => [ 'SMTPD', 'SMTPC' ], debug => 1 );
  $self->{session_id} = POE::Session->create(
	object_states => [
	   $self => { shutdown       => '_shutdown',
		      send_event     => '__send_event',
		      send_to_client => '_send_to_client',
	            },
	   $self => [ qw(_start register unregister _accept_client _accept_failed _conn_input _conn_error _conn_flushed _conn_alarm _send_to_client __send_event _process_queue _smtp_send_relay _smtp_send_mx _smtp_send_success _smtp_send_failure _process_dns_mx) ],
	],
	heap => $self,
	( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();
  return $self;
}

sub session_id {
  return $_[0]->{session_id};
}

sub _conn_exists {
  my ($self,$wheel_id) = @_;
  return 0 unless $wheel_id and defined $self->{clients}->{ $wheel_id };
  return 1; 
}

sub _valid_cmd {
  my $self = shift;
  my $cmd = shift || return;
  $cmd = lc $cmd;
  return 0 unless grep { $_ eq $cmd } @{ $self->{cmds} };
  return 1;
}

sub shutdown {
  my $self = shift;
  $poe_kernel->post( $self->{session_id}, 'shutdown' );
}

sub _start {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];
  $self->{session_id} = $_[SESSION]->ID();
  if ( $self->{alias} ) {
	$kernel->alias_set( $self->{alias} );
  } 
  else {
	$kernel->refcount_increment( $self->{session_id} => __PACKAGE__ );
  }
  if ( $kernel != $sender ) {
    my $sender_id = $sender->ID;
    $self->{events}->{'smtpd_all'}->{$sender_id} = $sender_id;
    $self->{sessions}->{$sender_id}->{'ref'} = $sender_id;
    $kernel->refcount_increment($sender_id, __PACKAGE__);
    $kernel->post( $sender, 'smtpd_registered', $self );
  }

  $self->{filter} = POE::Filter::Line->new();

  $self->{cmds} = [ qw(ehlo helo mail rcpt data rset expn help quit) ];

  $self->{listener} = POE::Wheel::SocketFactory->new(
      ( defined $self->{address} ? ( BindAddress => $self->{address} ) : () ),
      ( defined $self->{port} ? ( BindPort => $self->{port} ) : ( BindPort => 25 ) ),
      SuccessEvent   => '_accept_client',
      FailureEvent   => '_accept_failed',
      SocketDomain   => AF_INET,             # Sets the socket() domain
      SocketType     => SOCK_STREAM,         # Sets the socket() type
      SocketProtocol => 'tcp',               # Sets the socket() protocol
      Reuse          => 'on',                # Lets the port be reused
  );

  $self->{resolver} = POE::Component::Client::DNS->spawn()
    unless $self->{resolver} and $self->{resolver}->isa('POE::Component::Client::DNS');
  return;
}

sub _accept_client {
  my ($kernel,$self,$socket,$peeraddr,$peerport) = @_[KERNEL,OBJECT,ARG0..ARG2];
  my $sockaddr = inet_ntoa( ( unpack_sockaddr_in ( getsockname $socket ) )[1] );
  my $sockport = ( unpack_sockaddr_in ( getsockname $socket ) )[0];
  $peeraddr = inet_ntoa( $peeraddr );

  my $wheel = POE::Wheel::ReadWrite->new(
	Handle => $socket,
	Filter => $self->{filter},
	InputEvent => '_conn_input',
	ErrorEvent => '_conn_error',
	FlushedEvent => '_conn_flushed',
  );

  return unless $wheel;
  
  my $id = $wheel->ID();
  $self->{clients}->{ $id } = 
  { 
				wheel    => $wheel, 
				peeraddr => $peeraddr,
				peerport => $peerport,
				sockaddr => $sockaddr,
				sockport => $sockport,
  };
  $self->_send_event( 'smtpd_connection', $id, $peeraddr, $peerport, $sockaddr, $sockport );

  $self->{clients}->{ $id }->{alarm} = $kernel->delay_set( '_conn_alarm', $self->{time_out} || 300, $id );
  return;
}


sub _accept_failed {
  my ($kernel,$self,$operation,$errnum,$errstr,$wheel_id) = @_[KERNEL,OBJECT,ARG0..ARG3];
  warn "Wheel $wheel_id generated $operation error $errnum: $errstr\n";
  delete $self->{listener};
  $self->_send_event( 'smtpd_listener_failed', $operation, $errnum, $errstr );
  return;
}

sub _conn_input {
  my ($kernel,$self,$input,$id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  return unless $self->_conn_exists( $id );
  $kernel->delay_adjust( $self->{clients}->{ $id }->{alarm}, $self->{time_out} || 300 );
  if ( $self->{clients}->{ $id }->{buffer} ) {
    if ( $input eq '.' ) {
	my $mail = delete $self->{clients}->{ $id }->{mail};
	my $rcpt = delete $self->{clients}->{ $id }->{rcpt};
	my $buffer = delete $self->{clients}->{ $id }->{buffer};
	$self->_send_event( 'smtpd_message', $id, $mail, $rcpt, $buffer );
	return;
    }
    $input =~ s/^\.\.$/./;
    push @{ $self->{clients}->{ $id }->{buffer} }, $input;
    return;
  }
  $input =~ s/^\s+//g;
  $input =~ s/\s+$//g;
  my @args = split /\s+/, $input, 2;
  my $cmd = shift @args;
  return unless $cmd;
  unless ( $self->_valid_cmd( $cmd ) ) {
    $self->send_to_client( $id, "500 Syntax error, command unrecognized" );
    return;
  }
  $cmd = lc $cmd;
  if ( $cmd eq 'quit' ) {
    $self->{clients}->{ $id }->{quit} = 1;
    $self->send_to_client( $id, '221 closing connection - goodbye!' );
    return;
  }
  $self->_send_event( 'smtpd_cmd_' . $cmd, $id, @args );
  return;
}

sub _conn_error {
  my ($self,$errstr,$id) = @_[OBJECT,ARG2,ARG3];
  return unless $self->_conn_exists( $id );
  delete $self->{clients}->{ $id };
  $self->_send_event( 'smtpd_disconnected', $id );
  return;
}

sub _conn_flushed {
  my ($self,$id) = @_[OBJECT,ARG0];
  return unless $self->_conn_exists( $id );
  return unless $self->{clients}->{ $id }->{quit};
  delete $self->{clients}->{ $id };
  $self->_send_event( 'smtpd_disconnected', $id );
  return;
}

sub _conn_alarm {
  my ($kernel,$self,$id) = @_[KERNEL,OBJECT,ARG0];
  return unless $self->_conn_exists( $id );
  delete $self->{clients}->{ $id };
  $self->_send_event( 'smtpd_disconnected', $id );
  return;
}

sub _shutdown {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  delete $self->{listener};
  delete $self->{clients};
  $kernel->alarm_remove_all();
  $kernel->alias_remove( $_ ) for $kernel->alias_list();
  $kernel->refcount_decrement( $self->{session_id} => __PACKAGE__ ) unless $self->{alias};
  $self->_pluggable_destroy();
  $self->_unregister_sessions();
  $self->{resolver}->shutdown();
  undef;
}

sub register {
  my ($kernel, $self, $session, $sender, @events) =
    @_[KERNEL, OBJECT, SESSION, SENDER, ARG0 .. $#_];

  unless (@events) {
    warn "register: Not enough arguments";
    return;
  }

  my $sender_id = $sender->ID();

  foreach (@events) {
    $_ = "smtpd_" . $_ unless /^_/;
    $self->{events}->{$_}->{$sender_id} = $sender_id;
    $self->{sessions}->{$sender_id}->{'ref'} = $sender_id;
    unless ($self->{sessions}->{$sender_id}->{refcnt}++ or $session == $sender) {
      $kernel->refcount_increment($sender_id, __PACKAGE__);
    }
  }

  $kernel->post( $sender, 'smtpd_registered', $self );
  return;
}

sub unregister {
  my ($kernel, $self, $session, $sender, @events) =
    @_[KERNEL,  OBJECT, SESSION,  SENDER,  ARG0 .. $#_];

  unless (@events) {
    warn "unregister: Not enough arguments";
    return;
  }

  $self->_unregister($session,$sender,@events);
  undef;
}

sub _unregister {
  my ($self,$session,$sender) = splice @_,0,3;
  my $sender_id = $sender->ID();

  foreach (@_) {
    $_ = "smtpd_" . $_ unless /^_/;
    my $blah = delete $self->{events}->{$_}->{$sender_id};
    unless ( $blah ) {
	warn "$sender_id hasn't registered for '$_' events\n";
	next;
    }
    if (--$self->{sessions}->{$sender_id}->{refcnt} <= 0) {
      delete $self->{sessions}->{$sender_id};
      unless ($session == $sender) {
        $poe_kernel->refcount_decrement($sender_id, __PACKAGE__);
      }
    }
  }
  undef;
}

sub _unregister_sessions {
  my $self = shift;
  my $smtpd_id = $self->session_id();
  foreach my $session_id ( keys %{ $self->{sessions} } ) {
     if (--$self->{sessions}->{$session_id}->{refcnt} <= 0) {
        delete $self->{sessions}->{$session_id};
	$poe_kernel->refcount_decrement($session_id, __PACKAGE__) 
		unless ( $session_id eq $smtpd_id );
     }
  }
}

sub __send_event {
  my( $self, $event, @args ) = @_[ OBJECT, ARG0, ARG1 .. $#_ ];
  $self->_send_event( $event, @args );
  return;
}

sub _pluggable_event {
  my $self = shift;
  $poe_kernel->post( $self->{session_id}, '__send_event', @_ );
}

sub send_event {
  my $self = shift;
  $poe_kernel->post( $self->{session_id}, '__send_event', @_ );
}

sub _send_event  {
  my $self = shift;
  my ($event, @args) = @_;
  my $kernel = $POE::Kernel::poe_kernel;
  my $session = $kernel->get_active_session()->ID();
  my %sessions;

  my @extra_args;

  return 1 if $self->_pluggable_process( 'SMTPD', $event, \( @args ), \@extra_args ) == PLUGIN_EAT_ALL;

  push @args, @extra_args if scalar @extra_args;

  $sessions{$_} = $_ for (values %{$self->{events}->{'smtpd_all'}}, values %{$self->{events}->{$event}});

  $kernel->post( $_ => $event => @args ) for values %sessions;
  undef;
}

sub send_to_client {
  my $self = shift;
  $poe_kernel->call( $self->{session_id}, '_send_to_client', @_ );
}

sub _send_to_client {
  my ($kernel,$self,$id,$output) = @_[KERNEL,OBJECT,ARG0..ARG1];
  return unless $self->_conn_exists( $id );
  return unless $output;

  return 1 if $self->_pluggable_process( 'SMTPC', 'response', $id, \$output ) == PLUGIN_EAT_ALL;

  $self->{clients}->{ $id }->{wheel}->put($output);
  return 1;
}

sub _process_queue {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my $item = shift @{ $self->{_mail_queue} };
  $kernel->delay( '_process_queue', 120 );
  return unless $item;
  # Process Recipient Handlers here
  if ( $self->{relay} ) {
    $kernel->yield( '_smtp_send_relay', $item );
    return;
  }
  foreach my $recipient ( @{ $item->{rcpt} } ) {
    my $copy = { %{ $item } };
    $copy->{rcpt} = [ $recipient ];
    my $host = Email::Address->new(undef,$recipient,undef)->host();
    my $response = $self->{resolver}->resolve(
	event   => '_process_dns_mx',
	type    => 'MX',
	host    => $host,
	context => $copy,
    );
    $kernel->yield( '_process_dns_mx', $response ) if $response;
  }
  return;
}

sub _process_dns_mx {
  my ($kernel,$self,$response) = @_[KERNEL,OBJECT,ARG0];
  my @answers = $response->{response}->answer();
  my $item = $response->{context};
  my %mx = map { ( $_->exchange(), $_->preference() ) } 
	   grep { $_->type() eq 'MX' } @answers;
  my @mx = sort { $mx{$a} <=> $mx{$b} } keys %mx;
  push @mx, $response->{host} unless scalar @mx;
  $item->{mx} = \@mx;
  $kernel->yield( '_smtp_send_mx', $item );
  return;
}

sub _smtp_send_mx {
  my ($kernel,$self,$item) = @_[KERNEL,OBJECT,ARG0];
  $item->{count}++;
  my $exchange = shift @{ $item->{mx} };
  push @{ $item->{mx} }, $exchange;
  POE::Component::Client::SMTP->send(
	From => $item->{from},
	To   => $item->{rcpt},
	Body => $item->{msg},
	Server => $exchange,
	Context => $item,
	MyHostname => $self->{hostname},
	SMTP_Success => '_smtp_send_success',
	SMTP_Failure => '_smtp_send_failure',
  );
  return;
}

sub _smtp_send_relay {
  my ($kernel,$self,$item) = @_[KERNEL,OBJECT,ARG0];
  $item->{count}++;
  POE::Component::Client::SMTP->send(
	From => $item->{from},
	To   => $item->{rcpt},
	Body => $item->{msg},
	Server => $self->{relay},
	Context => $item,
	MyHostname => $self->{hostname},
	SMTP_Success => '_smtp_send_success',
	SMTP_Failure => '_smtp_send_failure',
  );
  return;
}

sub _smtp_send_success {
  my ($kernel,$self,$item) = @_[KERNEL,OBJECT,ARG0];
  warn $item->{uid}, " sent successfully.\n";
  return if $self->{relay};
  return;
}

sub _smtp_send_failure {
  my ($kernel,$self,$item) = @_[KERNEL,OBJECT,ARG0];
  warn $item->{uid}, " failed.\n";
  warn Dumper( $_[ARG1] );
  push @{ $self->{_mail_queue} }, $item;
  return;
}

sub SMTPD_connection {
  my ($self,$smtpd) = splice @_, 0, 2;
  my $id = ${ $_[0] };
  return PLUGIN_EAT_NONE unless $self->{handle_connects};
  $self->send_to_client( $id, join ' ', '220', $self->{hostname}, $self->{version}, 'ready' );
  return PLUGIN_EAT_NONE;
}

sub SMTPD_cmd_helo {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  $self->send_to_client( $id, '250 OK' );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_ehlo {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  $self->send_to_client( $id, '250-' . $self->{hostname} );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_mail {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  my $args = ${ $_[1] };
  my $response;
  if ( $self->{clients}->{ $id }->{mail} ) {
     $response = '503 Sender already specified';
  }
  elsif ( my ($from) = $args =~ /^from:\s*<(.+)>/i ) {
     $response = "250 <$from>... Sender OK";
     $self->{clients}->{ $id }->{mail} = $from;
  }
  else {
     $args = '' unless $args;
     $response = "501 Syntax error in parameters scanning '$args'";
  }
  $self->send_to_client( $id, $response );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_rcpt {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  my $args = ${ $_[1] };
  my $response;
  if ( !$self->{clients}->{ $id }->{mail} ) {
     $response = '503 Need MAIL before RCPT';
  }
  elsif ( my ($to) = $args =~ /^to:\s*<(.+)>/i ) {
     $response = "250 <$to>... Recipient OK";
     push @{ $self->{clients}->{ $id }->{rcpt} }, $to;
  }
  else {
     $args = '' unless $args;
     $response = "501 Syntax error in parameters scanning '$args'";
  }
  $self->send_to_client( $id, $response );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_data {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  my $response;
  if ( !$self->{clients}->{ $id }->{mail} ) {
     $response = '503 Need MAIL command';
  }
  elsif ( !$self->{clients}->{ $id }->{rcpt} ) {
     $response = '503 Need RCPT (recipient)';
  }
  else {
     $response = '354 Enter mail, end with "." on a line by itself';
     $self->{clients}->{ $id }->{buffer} = [ ];
  }
  $self->send_to_client( $id, $response );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_noop {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  $self->send_to_client( $id, '250 OK' );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_rset {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  delete $self->{clients}->{$id}->{$_} for qw(mail rcpt buffer);
  $self->send_to_client( $id, '250 Reset state' );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_message {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  my $from = ${ $_[1] };
  my $rcpt = ${ $_[2] };
  my $buf = ${ $_[3] };
  my $msg_id = Email::MessageID->new;
  my $uid = $msg_id->user();
  unshift @{ $buf }, "Received: from Unknown [" . $self->{clients}->{ $id }->{peeraddr} . "] by mail " . __PACKAGE__ . "-$VERSION with SMTP id $uid; " . strftime("%a, %d %b %Y %H:%M:%S %z", localtime); 
  $self->send_to_client( $id, "250 $uid Message accepted for delivery" );
  my $email = Email::Simple->new( join "\r\n", @{ $buf } );
  push @{ $self->{_mail_queue} }, { uid => $uid, from => $from, rcpt => $rcpt, msg => $email->as_string };
  $poe_kernel->post( $self->{session_id}, '_process_queue' );
  $self->send_event( 'smtpd_message_queued', $id, $from, $rcpt, $uid, scalar @{ $buf } );
  return PLUGIN_EAT_NONE;
}

1;
__END__
