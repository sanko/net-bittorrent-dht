requires 'AnyEvent';
requires 'AnyEvent::Util';
requires 'Bit::Vector';
requires 'Moose';
requires 'Moose::Role';
requires 'Moose::Util::TypeConstraints';
requires 'Net::BitTorrent::Protocol';
requires 'Scalar::Util';
requires 'Socket';
requires 'feature';
requires 'perl', '5.010';
recommends 'Config::IPFilter';

on 'test' => sub {
    requires 'Test::More', '0.98';
    requires 'Test::Class';
    requires 'Test::Moose';
};
