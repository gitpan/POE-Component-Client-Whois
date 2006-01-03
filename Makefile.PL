# $Id: Makefile.PL,v 3.9 2005/04/14 19:23:16 chris Exp $

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
			  'NAME'	=> 'POE::Component::Client::Whois',
			  'PREREQ_PM' => {
							  'POE'    => 0.3202,
							  'Carp'   => 0,
							  'Socket' => 0,
							  'Net::Netmask' => 1.9012,
							 },
			  'VERSION_FROM' => 'lib/POE/Component/Client/Whois.pm', # finds $VERSION
			  'dist' => { 'COMPRESS' => 'gzip --best' },
			 );

