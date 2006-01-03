package POE::Component::Client::Whois;

use strict;
use warnings;
use Socket;
use Carp;
use POE qw(Filter::Line Wheel::ReadWrite Wheel::SocketFactory);
use POE::Component::Client::Whois::TLDList;
use POE::Component::Client::Whois::IPBlks;
use vars qw($VERSION);

$VERSION = '1.02';

sub whois {
  my $package = shift;
  my %args = @_;

  foreach my $key ( keys %args ) {
	$args{lc $key} = delete $args{$key};
  }

  unless ( $args{query} and $args{event} ) {
	warn "You must provide a query string and a response event\n";
	return undef;
  }

  unless ( $args{host} ) {
	my $whois_server;
	my $tld = POE::Component::Client::Whois::TLDList->new();
	my $blk = POE::Component::Client::Whois::IPBlks->new();
	SWITCH: {
	  if ( $args{query} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ and scalar ( grep $_>=0&&$_<=255, split/\./, $args{query} ) == 4 ) {
		$whois_server = ( $blk->get_server( $args{query} ) )[0];
		unless ( $whois_server ) {
			warn "Couldn\'t determine correct whois server, falling back on arin\n";
			$whois_server = 'whois.arin.net';
		}
		last SWITCH;
	  }
	  if ( $args{query} =~ /:/ ) {
		warn "IPv6 detected, defaulting to 6bone\n";
		$whois_server = 'whois.6bone.net';
		last SWITCH;
	  }
	  $whois_server = ( $tld->tld( $args{query} ) )[0];
	  unless ( $whois_server ) {
		warn "Could not automagically determine whois server from query string, defaulting to internic \n";
		$whois_server = 'whois.internic.net';
	  }
	}
	$args{host} = $whois_server;
  }

  $args{session} = $poe_kernel->get_active_session() unless ( $args{session} );

  my $self = bless { request => \%args }, $package;

  $self->{session_id} = POE::Session->create(
	object_states => [ 
		$self => [ qw(_start _sock_input _sock_down _sock_up _sock_failed _time_out) ],
	],
	options => { trace => 0 },
  )->ID();

  return $self;
}

sub _start {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  $self->{session_id} = $_[SESSION]->ID();

  $self->{factory} = POE::Wheel::SocketFactory->new(
	SocketDomain   => AF_INET,
	SocketType     => SOCK_STREAM,
	SocketProtocol => 'tcp',
	RemoteAddress  => $self->{request}->{host},
	RemotePort     => $self->{request}->{port} || 43,
	SuccessEvent   => '_sock_up',
	FailureEvent   => '_sock_failed',
  );
  undef;
}

sub _sock_failed {
  my ($kernel, $self, $op, $errno, $errstr) = @_[KERNEL, OBJECT, ARG0..ARG2];

  delete $self->{factory};
  $self->{request}->{error} = "$op error $errno: $errstr";
  my $request = delete $self->{request};
  my $session = delete $request->{session};

  $kernel->post( $session => $request->{event} => $request );
  undef;
}

sub _sock_up {
  my ($kernel, $self, $session, $socket) = @_[KERNEL, OBJECT, SESSION, ARG0];
  delete $self->{factory};

  $self->{'socket'} = new POE::Wheel::ReadWrite
    ( Handle     => $socket,
      Driver     => POE::Driver::SysRW->new(),
      Filter     => POE::Filter::Line->new( InputRegexp => '\015?\012',
					    OutputLiteral => "\015\012" ),
      InputEvent => '_sock_input',
      ErrorEvent => '_sock_down',
    );

  unless ( $self->{'socket'} ) {
	my $request = delete $self->{request};
	my $session = delete $request->{session};
	$request->{error} = "Couldn\'t create a Wheel::ReadWrite on socket for whois";
	$kernel->post( $session => $request->{event} => $request );
	return undef;
  }

  $self->{'socket'}->put( $self->{request}->{query} );
  $kernel->delay( '_time_out' => 30 );
  undef;
}

sub _sock_down {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  delete $self->{socket};
  my $request = delete $self->{request};
  my $session = delete $request->{session};

  if ( defined ( $request->{reply} ) and ref( $request->{reply} ) eq 'ARRAY' ) {
	delete $request->{error};
  } else {
	$request->{error} = "No information received from remote host";
  }
  $kernel->post( $session => $request->{event} => $request );
  $kernel->delay( '_time_out' => undef );
  undef;
}

sub _sock_input {
  my ($kernel,$self,$line) = @_[KERNEL,OBJECT,ARG0];
  push( @{ $self->{request}->{reply} }, $line );
  undef;
}

sub _time_out {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  delete $self->{'socket'};
  undef;
}

1;
__END__

=head1 NAME

POE::Component::Client::Whois - A one shot non-blocking RFC 812 WHOIS query.

=head1 SYNOPSIS

   use strict; 
   use warnings;
   use POE qw(Component::Client::Whois);
   use Data::Dumper;

   POE::Session->create(
	package_states => [
		'main' => [ qw(_start _response) ],
	],
   );

   $poe_kernel->run();
   exit 0;

   sub _start {
     my ($kernel,$heap) = @_[KERNEL,HEAP];

     POE::Component::Client::Whois->whois( host => "whois.nic.uk", 
					   query => 'bingosnet.co.uk', 
					   event => '_response',
					   _arbitary => [ qw(moo moo moo) ] );
     undef;
   }

   sub _response {
  	print STDERR Dumper( $_[ARG0] );
   }

=head1 DESCRIPTION

POE::Component::Client::Whois provides a lightweight one shot non-blocking RFC 812 WHOIS query to other POE sessions and components. The component will attempt to guess the appropriate whois server to connect to based on the query string passed.

If no guess can be made it will connect to whois.internic.net for
domains, whois.arin.net for IPv4 addresses and whois.6bone.net for IPv6  addresses.

=head1 CONSTRUCTOR

=over

=item whois

Creates a POE::Component::Client::Whois session. Takes two mandatory arguments and a number of optional:

  'query', the string query to send to the whois server; # Mandatory
  'event', the event name to emit on success/failure; # Mandatory
  'port', the port on the whois server to connect to, defaults to 43;
  'session', a session or alias to send the above 'event' to, defaults to calling session;
  'host', the whois server to query; # Automagically determined by the component

One can also pass arbitary data to whois() which will be passed back in the response event. It is advised that one uses
an underscore prefix to avoid clashes with future versions.

=back

=head1 OUTPUT

ARG0 will be a hashref, which contains the original parameters passed to whois() ( including any arbitary data ), plus either one of the following two keys:

  'response', an arrayref of response lines from the whois server, assuming no error occurred;
  'error', in lieu of a valid response, this will be defined with a brief description of what went wrong;

No parsing is undertaken on the returned data, this is an exercise left to the reader >;]

=head1 AUTHOR

Chris "BinGOs" Williams <chris@bingosnet.co.uk>

This module is based on the linux whois client from L<http://www.linux.it/~md/software/>.

=head1 KUDOS

ketas, for first suggesting this module;
buu, decay and hazard from #perl @ freenode, for helpful suggestions;

=head1 SEE ALSO

RFC 812 L<http://www.faqs.org/rfcs/rfc812.html>.
