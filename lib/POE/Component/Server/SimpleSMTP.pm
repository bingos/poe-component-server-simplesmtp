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
use vars qw($VERSION);

$VERSION = '1.00';

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
	   $self => [ qw(_start register unregister _accept_client _accept_failed _conn_input _conn_error _conn_flushed _conn_alarm _send_to_client __send_event _process_queue _smtp_send_relay _smtp_send_mx _smtp_send_success _smtp_send_failure _process_dns_mx _fh_buffer _buffer_error _buffer_flush) ],
	],
	heap => $self,
	( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();
  return $self;
}

sub session_id {
  return $_[0]->{session_id};
}

sub data_mode {
  my $self = shift;
  my $id = shift || return;
  return unless $self->_conn_exists( $id );
  my $handle = shift;
  if ( $handle and $^O ne 'MSWin32' ) {
	$poe_kernel->call( $self->{session_id}, '_fh_buffer', $id, $handle );
  } 
  else {
  	$self->{clients}->{ $id }->{buffer} = [ ];
  }
  return 1;
}

sub getsockname {
  return unless $_[0]->{listener};
  return $_[0]->{listener}->getsockname();
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

  $self->{filter} = POE::Filter::Line->new( Literal => "\015\012" );

  $self->{cmds} = [ qw(ehlo helo mail rcpt data noop vrfy rset expn help quit) ];

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
    if ( $input eq '.' and $self->{simple} ) {
	my $mail = delete $self->{clients}->{ $id }->{mail};
	my $rcpt = delete $self->{clients}->{ $id }->{rcpt};
	my $buffer = delete $self->{clients}->{ $id }->{buffer};
	$self->_send_event( 'smtpd_message', $id, $mail, $rcpt, $buffer );
	return;
    }
    elsif ( $input eq '.' and ref( $self->{clients}->{ $id }->{buffer} ) eq 'ARRAY' ) {
	my $buffer = delete $self->{clients}->{ $id }->{buffer};
	$self->_send_event( 'smtpd_data', $id, $buffer );
	return;
    }
    elsif ( $input eq '.' ) {
	my $wheel_id = delete $self->{clients}->{ $id }->{buffer};
	$self->{buffers}->{ $wheel_id }->{shutdown} = 1;
	return;
    }
    $input =~ s/^\.\.$/./;
    if ( ref( $self->{clients}->{ $id }->{buffer} ) eq 'ARRAY' ) {
    	push @{ $self->{clients}->{ $id }->{buffer} }, $input;
    }
    else {
	my $buffer = $self->{clients}->{ $id }->{buffer};
	$self->{buffers}->{ $buffer }->{wheel}->put( $input );
    }
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
  delete $self->{buffers};
  $kernel->alarm_remove_all();
  $kernel->alias_remove( $_ ) for $kernel->alias_list();
  $kernel->refcount_decrement( $self->{session_id} => __PACKAGE__ ) unless $self->{alias};
  $self->_pluggable_destroy();
  $self->_unregister_sessions();
  $self->{resolver}->shutdown();
  undef;
}

sub _fh_buffer {
  my ($kernel,$self,$id,$handle) = @_[KERNEL,OBJECT,ARG0,ARG1];
  return unless $self->_conn_exists( $id );
  my $wheel = POE::Wheel::ReadWrite->new(
	Handle => $handle,
	FlushedEvent => '_buffer_flush',
	ErrorEvent => '_buffer_error',
  );
  my $wheel_id = $wheel->ID();
  $self->{clients}->{ $id }->{buffer} = $wheel_id;
  $self->{buffers}->{ $wheel_id } = { wheel => $wheel, id => $id };
  return;
}

sub _buffer_flush {
  my ($self,$wheel_id) = @_[OBJECT,ARG0];
  return unless $self->{buffers}->{ $wheel_id }->{shutdown};
  my $data = delete $self->{buffers}->{ $wheel_id };
  my $id = delete $data->{id};
  $self->send_event( 'smtpd_data_fh', $id );
  return;
}

sub _buffer_error {
  my ($kernel,$self,$error,$wheel_id) = @_[KERNEL,OBJECT,ARG1,ARG3];
  return;
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
  my %domains;
  foreach my $recipient ( @{ $item->{rcpt} } ) {
	my $host = Email::Address->new(undef,$recipient,undef)->host();
	push @{ $domains{ $host } }, $recipient;
  }
  foreach my $domain ( keys %domains ) {
    my $copy = { %{ $item } };
    $copy->{rcpt} = $domains{ $domain };
    my $response = $self->{resolver}->resolve(
	event   => '_process_dns_mx',
	type    => 'MX',
	host    => $domain,
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
	Timeout => $self->{time_out} || 300,
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
	Timeout => $self->{time_out} || 300,
	MyHostname => $self->{hostname},
	SMTP_Success => '_smtp_send_success',
	SMTP_Failure => '_smtp_send_failure',
  );
  return;
}

sub _smtp_send_success {
  my ($kernel,$self,$item) = @_[KERNEL,OBJECT,ARG0];
  $self->send_event( 'smtpd_send_success', $item->{uid} );
  return;
}

sub _smtp_send_failure {
  my ($kernel,$self,$item,$error) = @_[KERNEL,OBJECT,ARG0,ARG1];
  $self->send_event( 'smtpd_send_failed', $item->{uid}, $error );
  if ( $error->{SMTP_Server_Error} and $error->{SMTP_Server_Error} =~ /^5/ ) {
	return;
  }
  if ( time() - $item->{ts} > 345600 ) {
	return;
  }
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
  $self->send_to_client( $id, '250 ' . $self->{hostname} . ' Hello [' . $self->{clients}->{ $id }->{peeraddr} . '], pleased to meet you' );
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

sub SMTPD_cmd_expn {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  $self->send_to_client( $id, '502 Command not implemented; unsupported operation (EXPN)' );
  return PLUGIN_EAT_ALL;
}

sub SMTPD_cmd_vrfy {
  my ($self,$smtpd) = splice @_, 0, 2;
  return PLUGIN_EAT_NONE unless $self->{simple};
  my $id = ${ $_[0] };
  $self->send_to_client( $id, '252 Cannot VRFY user, but will accept message for delivery' );
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
  unshift @{ $buf }, "Message-ID: <$uid\@" . $self->{hostname} . '>';
  unshift @{ $buf }, "Received: from Unknown [" . $self->{clients}->{ $id }->{peeraddr} . "] by " . $self->{hostname} . " " . __PACKAGE__ . "-$VERSION with SMTP id $uid; " . strftime("%a, %d %b %Y %H:%M:%S %z", localtime); 
  $self->send_to_client( $id, "250 $uid Message accepted for delivery" );
  my $email = Email::Simple->new( join "\r\n", @{ $buf } );
  push @{ $self->{_mail_queue} }, { uid => $uid, from => $from, rcpt => $rcpt, msg => $email->as_string, ts => time() };
  $poe_kernel->post( $self->{session_id}, '_process_queue' );
  $self->send_event( 'smtpd_message_queued', $id, $from, $rcpt, $uid, scalar @{ $buf } );
  return PLUGIN_EAT_ALL;
}

1;
__END__

=head1 NAME

POE::Component::Server::SimpleSMTP - A simple to use POE SMTP Server.

=head1 SYNOPSIS

  # A simple SMTP Server 
  use strict;
  use POE;
  use POE::Component::Server::SimpleSMTP;

  my $hostname = 'mymailserver.local';
  my $relay; # specify a smart 'relay' server if required
  
  POE::Component::Server::SimpleSMTP->spawn(
	hostname => $hostname,
	relay    => $relay,
  );

  $poe_kernel->run();
  exit 0;

=head1 DESCRIPTION

POE::Component::Server::SimpleSMTP is a L<POE> component that provides an ease to
use, but fully extensible SMTP mail server, that is reasonably compliant with 
RFC 2821 L<http://www.faqs.org/rfcs/rfc2821.html>.

In its simplest form it provides SMTP services, accepting mail from clients and
either relaying the mail to a smart host for further delivery or delivering the
mail itself by querying DNS MX records.

One may also disable simple functionality and implement one's own SMTP handling 
and mail queuing. This can be done via a POE state interface or via L<POE::Component::Pluggable> plugins.

=head1 CONSTRUCTOR

=over

=item spawn

Takes a number of optional arguments:

  'alias', set an alias on the component;
  'address', bind the listening socket to a particular address;
  'port', listen on a particular port, default is 25;
  'options', a hashref of POE::Session options;
  'hostname', the name that the server will identify as in 'EHLO';
  'version', change the version string reported in 220 responses;
  'relay', specify a 'smart host' to send received mail to, default is
	   to deliver direct after determining MX records;

These optional arguments can be used to enable your own SMTP handling:

  'simple', set this to a false value and the component will no 
	    longer handle SMTP processing; 
  'handle_connects', set this to a false value to stop the component sending
	    220 responses on client connections;

Returns a POE::Component::Server::SimpleSMTP object.

=back

=head1 METHODS

=over

=item session_id

Returns the POE::Session ID of the component.

=item shutdown

Terminates the component. Shuts down the listener and disconnects connected clients.

=item send_event

Sends an event through the component's event handling system.

=item send_to_client

Send some output to a connected client. First parameter must be a valid client id. Second parameter is a string of text to send.

=item data_mode

Takes one argument a valid client ID. Switches the client connection to data mode for receiving 
an mail message. This should be done in response to a valid DATA command from a client if
you are doing your own SMTP handling.

You will receive an 'smtpd_data' event when the client has finished sending data. See below.

Optionally, you may supply a filehandle as a second argument. Any data received from the client 
will be written to the filehandle. You will receive an 'smtpd_data_fh' event when the client
has finished sending data.

=item getsockname

Access to the L<POE::Wheel::SocketFactory> method of the underlying listening socket.

=back

=head1 INPUT EVENTS

These are events that the component will accept:

=over

=item register

Takes N arguments: a list of event names that your session wants to listen for, minus the 'smtpd_' prefix, ( this is 
similar to L<POE::Component::IRC> ). 

Registering for 'all' will cause it to send all SMTPD-related events to you; this is the easiest way to handle it.

=item unregister

Takes N arguments: a list of event names which you don't want to receive. If you've previously done a 'register' for a particular event which you no longer care about, this event will tell the SMTPD to stop sending them to you. (If you haven't, it just ignores you. No big deal).

=item shutdown

Terminates the component. Shuts down the listener and disconnects connected clients.

=item send_event

Sends an event through the component's event handling system. 

=item send_to_client

Send some output to a connected client. First parameter must be a valid client ID. 
Second parameter is a string of text to send.

=back

=head1 OUTPUT EVENTS

The component sends the following events to registered sessions:

=over

=item smtpd_registered

This event is sent to a registering session. ARG0 is POE::Component::Server::SimpleSMTP
object.

=item smtpd_listener_failed

Generated if the component cannot either start a listener or there is a problem
accepting client connections. ARG0 contains the name of the operation that failed. 
ARG1 and ARG2 hold numeric and string values for $!, respectively.

=item smtpd_connection

Generated whenever a client connects to the component. ARG0 is the client ID, ARG1
is the client's IP address, ARG2 is the client's TCP port. ARG3 is our IP address and
ARG4 is our socket port.

If 'handle_connects' is true ( which is the default ), the component will automatically
send a 220 SMTP response to the client.

=item smtpd_disconnected

Generated whenever a client disconnects. ARG0 is the client ID.

=item smtpd_cmd_*

Generated for each SMTP command that a connected client sends to us. ARG0 is the 
client ID. ARG1 .. ARGn are any parameters that are sent with the command. Check 
the RFC L<http://www.faqs.org/rfcs/rfc2821.html> for details.

If 'simple' is true ( which is the default ), the component deals with client
commands itself.

=item smtpd_data

Generated when a client sends an email.

  ARG0 will be the client ID;
  ARG1 an arrayref of lines sent by the client, stripped of CRLF line endings;

If 'simple' is true ( which is the default ), the component will deal with 
receiving data from the client itself.

=item smtpd_data_fh

Generated when a client sends an email and a filehandle has been provided.

  ARG0 will be the client ID;

If 'simple' is true ( which is the default ), the component will deal with 
receiving data from the client itself.

=back

In 'simple' mode these events will be generated:

=over

=item smtpd_message_queued

Generated whenever a mail message is queued. 

  ARG0 is the client ID;
  ARG1 is the mail from address;
  ARG2 is an arrayref of recipients;
  ARG3 is the email unique idenitifer;
  ARG4 is the number of lines of the message;

=item smtpd_send_success

Generated whenever a mail message is successfully delivered.

  ARG0 is the email unique identifier;

=item smtpd_send_failed

Generated whenever a mail message is unsuccessfully delivered. This can be for a variety of reasons. The poco
will attempt to resend the message on non-fatal errors ( such as an explicit denial of delivery by the SMTP peer ), for up to 4 days.

  ARG0 is the email unique identifier;
  ARG1 is a hashref as returned by POE::Component::Client::SMTP via 'SMTP_Failure'

=back

=head1 PLUGINS

POE::Component::Server::SimpleSMTP utilises L<POE::Component::Pluggable> to enable a
L<POE::Component::IRC> type plugin system. 

=head2 PLUGIN HANDLER TYPES

There are two types of handlers that can registered for by plugins, these are 

=over

=item SMTPD

These are the 'smtpd_' prefixed events that are generated. In a handler arguments are
passed as scalar refs so that you may mangle the values if required.

=item SMTPC

These are generated whenever a response is sent to a client. Again, any 
arguments passed are scalar refs for manglement. There is really on one type
of this handler generated 'SMTPC_response'

=back

=head2 PLUGIN EXIT CODES

Plugin handlers should return a particular value depending on what action they wish
to happen to the event. These values are available as constants which you can use 
with the following line:

  use POE::Component::Server::SimpleSMTP::Constants qw(:ALL);

The return values have the following significance:

=over 

=item SMTPD_EAT_NONE

This means the event will continue to be processed by remaining plugins and
finally, sent to interested sessions that registered for it.

=item SMTP_EAT_CLIENT

This means the event will continue to be processed by remaining plugins but
it will not be sent to any sessions that registered for it. This means nothing
will be sent out on the wire if it was an SMTPC event, beware!

=item SMTPD_EAT_PLUGIN

This means the event will not be processed by remaining plugins, it will go
straight to interested sessions.

=item SMTPD_EAT_ALL

This means the event will be completely discarded, no plugin or session will see it. This
means nothing will be sent out on the wire if it was an SMTPC event, beware!

=back

=head2 PLUGIN METHODS

The following methods are available:

=over

=item pipeline

Returns the L<POE::Component::Pluggable::Pipeline> object.

=item plugin_add

Accepts two arguments:

  The alias for the plugin
  The actual plugin object

The alias is there for the user to refer to it, as it is possible to have multiple
plugins of the same kind active in one POE::Component::Server::SimpleSMTP object.

This method goes through the pipeline's push() method.

 This method will call $plugin->plugin_register( $nntpd )

Returns the number of plugins now in the pipeline if plugin was initialized, undef
if not.

=item plugin_del

Accepts one argument:

  The alias for the plugin or the plugin object itself

This method goes through the pipeline's remove() method.

This method will call $plugin->plugin_unregister( $nntpd )

Returns the plugin object if the plugin was removed, undef if not.

=item plugin_get

Accepts one argument:

  The alias for the plugin

This method goes through the pipeline's get() method.

Returns the plugin object if it was found, undef if not.

=item plugin_list

Has no arguments.

Returns a hashref of plugin objects, keyed on alias, or an empty list if there are no
plugins loaded.

=item plugin_order

Has no arguments.

Returns an arrayref of plugin objects, in the order which they are encountered in the
pipeline.

=item plugin_register

Accepts the following arguments:

  The plugin object
  The type of the hook, SMTPD or SMTPC
  The event name(s) to watch

The event names can be as many as possible, or an arrayref. They correspond
to the prefixed events and naturally, arbitrary events too.

You do not need to supply events with the prefix in front of them, just the names.

It is possible to register for all events by specifying 'all' as an event.

Returns 1 if everything checked out fine, undef if something's seriously wrong

=item plugin_unregister

Accepts the following arguments:

  The plugin object
  The type of the hook, SMTPD or SMTPC
  The event name(s) to unwatch

The event names can be as many as possible, or an arrayref. They correspond
to the prefixed events and naturally, arbitrary events too.

You do not need to supply events with the prefix in front of them, just the names.

It is possible to register for all events by specifying 'all' as an event.

Returns 1 if all the event name(s) was unregistered, undef if some was not found.

=back

=head2 PLUGIN TEMPLATE

The basic anatomy of a plugin is:

        package Plugin;

        # Import the constants, of course you could provide your own 
        # constants as long as they map correctly.
        use POE::Component::Server::SimpleSMTP::Constants qw( :ALL );

        # Our constructor
        sub new {
                ...
        }

        # Required entry point for plugins
        sub plugin_register {
                my( $self, $smtpd ) = @_;

                # Register events we are interested in
                $smtpd->plugin_register( $self, 'SMTPD', qw(all) );

                # Return success
                return 1;
        }

        # Required exit point for pluggable
        sub plugin_unregister {
                my( $self, $smtpd ) = @_;

                # Pluggable will automatically unregister events for the plugin

                # Do some cleanup...

                # Return success
                return 1;
        }

        sub _default {
                my( $self, $smtpd, $event ) = splice @_, 0, 3;

                print "Default called for $event\n";

                # Return an exit code
                return SMTPD_EAT_NONE;
        }

=head1 CAVEATS

This module shouldn't be used C<as is>, as a production SMTP server, as the 
message queue is implemented in memory. *ouch*

=head1 TODO

Design a better message queue so that messages are stored on disk.

=head1 KUDOS

George Nistoric for L<POE::Component::Client::SMTP>

Rocco Caputo for L<POE::Component::Client::DNS>

=head1 AUTHOR

Chris C<BinGOs> Williams <chris@bingosnet.co.uk>

=head1 SEE ALSO

L<POE::Component::Pluggable>

L<POE::Component::Client::DNS>

L<POE::Component::Client::SMTP>

RFC 2821 L<http://www.faqs.org/rfcs/rfc2821.html>
