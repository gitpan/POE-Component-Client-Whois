package POE::Component::Client::Whois::IPBlks;

use strict;
use warnings;
use Net::Netmask;

sub new {
  my ($self) = bless { }, shift;
  while(<DATA>) {
	chomp;
	next if (/^#/);
	my ($range,$server) = ( split(/\s+/) )[0..1];
	if ( $server !~ /\./ ) {
		$server = "whois.$server.net";
	}
	$self->{data}->{ $range } = $server;
  }
  return $self;
}

sub get_server {
  my $self = shift;
  my $ip = shift || return undef;

  foreach my $range ( keys %{ $self->{data} } ) {
	if ( $range eq '0.0.0.0/2' ) {
		foreach my $cls_a ( 1 .. 126 ) {
		  my $block2 = Net::Netmask->new( "$cls_a.0.0.0/8" );
		  if ( $block2->match( $ip ) ) {
			return ( $self->{data}->{ $range }, $range );
		  }
		}
	}
	my $block = Net::Netmask->new( $range );
	if ( $block->match( $ip ) ) {
		return ( $self->{data}->{ $range }, $range );
	}
  }
  return undef;
}

1;
__DATA__
24.192.0.0/14	apnic
24.132.0.0/14	ripe
61.112.0.0/12	whois.nic.ad.jp
61.192.0.0/12	whois.nic.ad.jp		# => 61.207
61.208.0.0/13	whois.nic.ad.jp		# => 61.215
61.0.0.0/8	apnic
62.0.0.0/8	ripe
# broken?
# 63.208.0.0/13	rr.level3.net
80.0.0.0/7	ripe
0.0.0.0/2	arin	# all other A classes are managed by ARIN
## The B class space is a mess :-( - something could still be missing
## I add here only netblocks allocated to multiple LIRs by the RIRs.
133.0.0.0/8	whois.nic.ad.jp
139.20.0.0/14	ripe
139.24.0.0/14	ripe
139.28.0.0/15	ripe
141.0.0.0/10	ripe
141.64.0.0/12	ripe
141.80.0.0/14	ripe
141.84.0.0/15	ripe
145.224.0.0/12	ripe
145.240.0.0/13	ripe
145.248.0.0/14	ripe
145.252.0.0/15	ripe
145.254.0.0/16	ripe
146.48.0.0/16	ripe
149.202.0.0/15	ripe
149.204.0.0/16	ripe
149.206.0.0/15	ripe
149.208.0.0/12	ripe
149.224.0.0/12	ripe
149.240.0.0/13	ripe
149.248.0.0/14	ripe
150.254.0.0/16	ripe
151.0.0.0/10	ripe
151.64.0.0/11	ripe
151.96.0.0/14	ripe
151.100.0.0/16	ripe
160.216.0.0/14	ripe
160.220.0.0/16	ripe
160.44.0.0/14	ripe
160.48.0.0/12	ripe
163.156.0.0/14	ripe
163.160.0.0/12	ripe
164.0.0.0/11	ripe
164.32.0.0/13	ripe
164.40.0.0/16	ripe
164.128.0.0/12	ripe
169.208.0.0/12	apnic
171.16.0.0/12	ripe
171.32.0.0/15	ripe
## The C class space is cleanly delegated and the data here should be complete
192.71.0.0/16	ripe
192.72.0.0/16	whois.seed.net.tw	# NETBLK-SEED-NETS
192.106.0.0/16	ripe
192.162.0.0/16	ripe
192.164.0.0/14	ripe
192.0.0.0/8	arin	# the swamp
193.0.0.0/8	ripe
194.0.0.0/7	ripe
198.17.117.0/24	ripe
196.0.0.0/6	arin
200.17.0.0/16	whois.nic.br
200.18.0.0/15	whois.nic.br
200.20.0.0/16	whois.nic.br
200.128.0.0/9	whois.nic.br
200.0.0.0/7	arin
202.11.0.0/16	whois.nic.ad.jp
202.13.0.0/16	whois.nic.ad.jp
202.15.0.0/16	whois.nic.ad.jp
202.16.0.0/14	whois.nic.ad.jp
202.23.0.0/16	whois.nic.ad.jp
202.24.0.0/15	whois.nic.ad.jp
202.26.0.0/16	whois.nic.ad.jp
202.30.0.0/15	whois.nic.or.kr
202.32.0.0/14	whois.nic.ad.jp
202.48.0.0/16	whois.nic.ad.jp
202.39.128.0/17	twnic
202.208.0.0/12	whois.nic.ad.jp
202.224.0.0/11	whois.nic.ad.jp		# => 202.255
203.27.128.0/18	telstra
203.35.0.0/16	telstra
203.36.0.0/14	telstra
203.40.0.0/13	telstra
203.48.0.0/14	telstra
203.52.0.0/15	telstra
203.54.0.0/16	telstra
203.58.128.0/17	telstra
203.58.32.0/19	telstra
203.58.64.0/19	telstra
# 203.0.0.0/10 has been moved from aunic to apnic, but the records in
# the telstra database appears to be more detailed.
# See http://www.apnic.net/db/aunic/ for details.
203.0.0.0/10	apnic
203.66.0.0/16	twnic
203.69.0.0/16	twnic
203.74.0.0/15	twnic
203.136.0.0/14	whois.nic.ad.jp
203.140.0.0/15	whois.nic.ad.jp
203.178.0.0/15	whois.nic.ad.jp
203.180.0.0/14	whois.nic.ad.jp
203.232.0.0/13	whois.nic.or.kr
202.0.0.0/7	apnic
204.0.0.0/6	arin
208.0.0.0/7	arin
210.59.128.0/17	twnic
210.61.0.0/16	twnic
210.62.252.0/22	twnic
210.65.0.0/16	twnic
210.71.128.0/16	twnic
210.90.0.0/15	whois.nic.or.kr
210.92.0.0/14	whois.nic.or.kr
210.96.0.0/13	whois.nic.or.kr
210.104.0.0/13	whois.nic.or.kr
210.112.0.0/13	whois.nic.or.kr
210.120.0.0/14	whois.nic.or.kr	# => 210.123.255.255	
210.128.0.0/11	whois.nic.ad.jp
210.160.0.0/12	whois.nic.ad.jp
210.178.0.0/15	whois.nic.or.kr
210.180.0.0/14	whois.nic.or.kr
210.188.0.0/14	whois.nic.ad.jp
210.196.0.0/14	whois.nic.ad.jp
210.204.0.0/14	whois.nic.or.kr
210.216.0.0/13	whois.nic.or.kr	# => 210.223.255.255
210.224.0.0/12	whois.nic.ad.jp	# => 210.239.255.255
# some more TWNIC blocks are scattered here
210.240.0.0/16	twnic
210.241.0.0/15	twnic
210.241.224.0/19 twnic
210.242.0.0/15	twnic
210.248.0.0/13	whois.nic.ad.jp
211.0.0.0/12	whois.nic.ad.jp
211.16.0.0/14	whois.nic.ad.jp
211.20.0.0/15	twnic
211.22.0.0/16	twnic
211.32.0.0/11	whois.nic.or.kr	# => 211.63.255.255
211.75.0.0/16	twnic
211.72.0.0/16	twnic
211.104.0.0/13	whois.nic.or.kr
211.112.0.0/13	whois.nic.or.kr	# => 211.119.255.255
211.120.0.0/13	whois.nic.ad.jp
211.128.0.0/13	whois.nic.ad.jp
211.168.0.0/13	whois.nic.or.kr
211.176.0.0/12	whois.nic.or.kr
211.192.0.0/10  whois.nic.or.kr # => 211.255.255.255
210.0.0.0/7	apnic
212.0.0.0/7	ripe
214.0.0.0/7	arin	# DoD
216.0.0.0/8	arin
217.0.0.0/8	ripe
218.216.0.0/13	apnic
218.224.0.0/13	apnic
218.40.0.0/13	whois.nic.ad.jp
218.47.0.0/13	whois.nic.or.kr
218.0.0.0/7	apnic
220.0.0.0/8	apnic
