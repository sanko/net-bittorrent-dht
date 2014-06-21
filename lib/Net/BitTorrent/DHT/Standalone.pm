package Net::BitTorrent::DHT::Standalone;
use Moose::Role;
use Socket qw[/SOCK_/ /F_INET/ SOL_SOCKET SO_REUSEADDR inet_ntoa];
use lib '../../../../lib';
use Net::BitTorrent::Protocol qw[:bencode];
our $VERSION = 'v1.0.0';
eval $VERSION;
#
has 'port' => (is      => 'ro',
               isa     => 'Int|ArrayRef[Int]',
               builder => '_build_port',
               writer  => '_set_port'
);

sub _build_port {
    my $s = shift;
    $s->has_client ? $s->client->port : 0;
}
my %_sock_types = (4 => '0.0.0.0', 6 => '::');
for my $ipv (keys %_sock_types) {
    has 'udp'
        . $ipv => (is         => 'ro',
                   init_arg   => undef,
                   isa        => 'Maybe[Object]',
                   lazy_build => 1,
                   writer     => '_set_udp' . $ipv
        );
    has 'udp'
        . $ipv
        . '_sock' => (is         => 'ro',
                      init_arg   => undef,
                      isa        => 'GlobRef',
                      lazy_build => 1,
                      weak_ref   => 1,
                      writer     => '_set_udp' . $ipv . '_sock'
        );
    has 'udp'
        . $ipv
        . '_host' => (is      => 'ro',
                      isa     => 'Str',
                      default => $_sock_types{$ipv},
                      writer  => '_set_udp' . $ipv . '_host'
        );
}
#
has 'ip_filter' => (is       => 'ro',
                    isa      => 'Maybe[Config::IPFilter]',
                    init_arg => undef,
                    builder  => '_build_ip_filter'
);

sub _build_ip_filter {
    return eval('require Config::IPFilter;') ? Config::IPFilter->new() : ();
}

sub _build_udp6 {
    my $s = shift;
    my ($server, $actual_socket, $actual_host, $actual_port);
    for my $port (ref $s->port ? @{$s->port} : $s->port) {
        $server = server(
            $s->udp6_host,
            $port,
            sub { $s->_on_udp6_in(@_); },
            sub {
                ($actual_socket, $actual_host, $actual_port) = @_;

                #if ($self->port != $port) { ...; }
                $s->_set_udp6_sock($actual_socket);
                $s->_set_udp6_host($actual_host);
                $s->_set_port($actual_port);
            },
            'udp'
        );
        last if defined $server;
    }
    if ($server) {
        $s->trigger_listen_success(
                      {port     => $actual_port,
                       protocol => 'udp6',
                       severity => 'debug',
                       event    => 'listen_success',
                       message  => sprintf
                           'Bound UDP port %d to the outside world over IPv6',
                       $actual_port
                      }
        );
    }
    else {
        $s->trigger_listen_failure(
                {port     => $s->port,
                 protocol => 'udp6',
                 severity => 'fatal',
                 event    => 'listen_failure',
                 message =>
                     'Failed to bind UDP port for the outside world over IPv6'
                }
        );
    }
    return $server;
}

sub _build_udp4 {
    my $s = shift;
    my ($server, $actual_socket, $actual_host, $actual_port);
    for my $port (ref $s->port ? @{$s->port} : $s->port) {
        $server = server(
            $s->udp4_host,
            $port,
            sub { $s->_on_udp4_in(@_); },
            sub {
                ($actual_socket, $actual_host, $actual_port) = @_;

                #if ($self->port != $port) { ...; }
                $s->_set_udp4_sock($actual_socket);
                $s->_set_udp4_host($actual_host);
                $s->_set_port($actual_port);
            },
            'udp'
        );
        last if defined $server;
    }
    if ($server) {
        $s->trigger_listen_success(
                      {port     => $actual_port,
                       protocol => 'udp4',
                       severity => 'debug',
                       event    => 'listen_success',
                       message  => sprintf
                           'Bound UDP port %d to the outside world over IPv4',
                       $actual_port
                      }
        );
    }
    else {
        $s->trigger_listen_failure(
                {port     => $s->port,
                 protocol => 'udp4',
                 severity => 'fatal',
                 event    => 'listen_failure',
                 message =>
                     'Failed to bind UDP port for the outside world over IPv4'
                }
        );
    }
    return $server;
}
around '_on_udp4_in' => sub {
    my ($c, $s, $sock, $sockaddr, $host, $port, $data, $flags) = @_;
    if (defined $s->ip_filter) {
        my $rule = $s->ip_filter->is_banned($host);
        if (defined $rule) {
            $s->trigger_ip_filter(
                           {protocol => 'udp4',
                            severity => 'debug',
                            event    => 'ip_filter',
                            address  => [$host, $port],
                            rule     => $rule,
                            message => 'Incoming data was blocked by ipfilter'
                           }
            );
            return;
        }
    }
    $c->($s, $sock, $sockaddr, $host, $port, $data, $flags);
};
around '_on_udp6_in' => sub {
    my ($c, $s, $sock, $sockaddr, $host, $port, $data, $flags) = @_;
    my $rule = $s->ip_filter->is_banned($host);
    if (defined $rule) {
        $s->trigger_ip_filter(
                           {protocol => 'udp6',
                            severity => 'debug',
                            event    => 'ip_filter',
                            address  => [$host, $port],
                            rule     => $rule,
                            message => 'Incoming data was blocked by ipfilter'
                           }
        );
        return;
    }
    $c->($s, $sock, $sockaddr, $host, $port, $data, $flags);
};

# Callback system
sub _build_callback_no_op {
    sub {1}
}
has "on_$_" => (isa        => 'CodeRef',
                is         => 'ro',
                traits     => ['Code'],
                handles    => {"trigger_$_" => 'execute_method'},
                lazy_build => 1,
                builder    => '_build_callback_no_op',
                clearer    => "_no_$_",
                weak_ref   => 1
    )
    for qw[
    listen_failure listen_success
];

sub server ($$&;&$) {
    my ($host, $port, $callback, $prepare, $proto) = @_;
    $proto //= 'tcp';
    my $sockaddr = Net::BitTorrent::DHT::sockaddr($host, $port) or return;
    my $type = length $sockaddr == 16 ? PF_INET : PF_INET6;
    socket my ($socket), $type,
        $proto eq 'udp' ? SOCK_DGRAM : SOCK_STREAM, getprotobyname($proto)
        or return;

    # - What is the difference between SO_REUSEADDR and SO_REUSEPORT?
    #    [http://www.unixguide.net/network/socketfaq/4.11.shtml]
    # SO_REUSEPORT is undefined on Win32 and pre-2.4.15 Linux distros.
    setsockopt $socket, SOL_SOCKET, SO_REUSEADDR, pack('l', 1)
        or return
        if $^O !~ m[Win32];
    return if !bind $socket, $sockaddr;
    my $listen = 8;
    if (defined $prepare) {
        my ($_port, $packed_ip)
            = Net::BitTorrent::DHT::unpack_sockaddr(getsockname $socket);
        my $return = $prepare->($socket, paddr2ip($packed_ip), $_port);
        $listen = $return if defined $return;
    }
    require AnyEvent::Util;
    AnyEvent::Util::fh_nonblocking $socket, 1;
    listen $socket, $listen or return if $proto ne 'udp';
    return AE::io(
        $socket, 0,
        $proto eq 'udp' ?
            sub {
            my $flags = 0;
            if ($socket
                && (my $peer = recv $socket, my ($data), 16 * 1024, $flags))
            {   my ($service, $host) = Net::BitTorrent::DHT::unpack_sockaddr( $peer);
                $callback->($socket, $peer, paddr2ip($host), $service,
                            $data, $flags
                );
            }
            }
        : sub {
            while ($socket
                   && (my $peer = accept my ($fh), $socket))
            {   my ($service, $host) = Net::BitTorrent::DHT::unpack_sockaddr( $peer);
                $callback->($fh, $peer, paddr2ip($host), $service);
            }
        }
    );
}

sub paddr2ip ($) {
    return inet_ntoa($_[0]) if length $_[0] == 4;    # ipv4
    return inet_ntoa($1)
        if length $_[0] == 16
        && $_[0] =~ m[^\0{10}\xff{2}(.{4})$];        # ipv4
    return unless length($_[0]) == 16;
    my @hex = (unpack('n8', $_[0]));
    $hex[9] = $hex[7] & 0xff;
    $hex[8] = $hex[7] >> 8;
    $hex[7] = $hex[6] & 0xff;
    $hex[6] >>= 8;
    my $return = sprintf '%X:%X:%X:%X:%X:%X:%D:%D:%D:%D', @hex;
    $return =~ s|(0+:)+|:|x;
    $return =~ s|^0+    ||x;
    $return =~ s|^:+    |::|x;
    $return =~ s|::0+   |::|x;
    $return =~ s|^::(\d+):(\d+):(\d+):(\d+)|$1.$2.$3.$4|x;
    return $return;
}
1;

=pod

=head1 NAME

Net::BitTorrent::DHT::Standalone

=head1 Description

This role is applied automatically when the Net::BitTorrent::DHT constructor
is called without a blessed Net::BitTorrent object in the C<client> parameter.
For API documentation, see L<Net::BitTorrent::DHT>.

Standalone DHT nodes may be useful for statistical purposes.

=head1 Methods

Aside from the public L<constructor|/"Net::BitTorrent::DHT->new( )">, the API
L<Net::BitTorrent::DHT::Standalone|Net::BitTorrent::DHT::Standalone> is
exactly the same as the L<Net::BitTorrent::DHT|Net::BitTorrent::DHT>.

=head2 Net::BitTorrent::DHT->new( )

This creates a new standalone DHT node. Random ports will be opened to
incoming UDP connections via IPv4 and IPv6.

    use Net::BitTorrent::DHT;
    my $node = Net::BitTorrent::DHT->new( );

=head1 Author

Sanko Robinson <sanko@cpan.org> - http://sankorobinson.com/

CPAN ID: SANKO

=head1 License and Legal

Copyright (C) 2008-2014 by Sanko Robinson <sanko@cpan.org>

This program is free software; you can redistribute it and/or modify it under
the terms of
L<The Artistic License 2.0|http://www.perlfoundation.org/artistic_license_2_0>.
See the F<LICENSE> file included with this distribution or
L<notes on the Artistic License 2.0|http://www.perlfoundation.org/artistic_2_0_notes>
for clarification.

When separated from the distribution, all original POD documentation is
covered by the
L<Creative Commons Attribution-Share Alike 3.0 License|http://creativecommons.org/licenses/by-sa/3.0/us/legalcode>.
See the
L<clarification of the CCA-SA3.0|http://creativecommons.org/licenses/by-sa/3.0/us/>.

Neither this module nor the L<Author|/Author> is affiliated with BitTorrent,
Inc.

=cut
