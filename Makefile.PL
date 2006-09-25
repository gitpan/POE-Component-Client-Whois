#use ExtUtils::MakeMaker;
use inc::Module::Install;

author 'Chris Williams <chris@bingosnet.co.uk>';
license 'perl';

WriteMakefile(
			  'NAME'	=> 'POE::Component::Client::Whois',
			  'PREREQ_PM' => {
							  'warnings' => 0,
							  'POE'    => 0.3202,
							  'Carp'   => 0,
							  'Socket' => 0,
							  'Net::Netmask' => 1.9012,
							 },
			  'VERSION_FROM' => 'lib/POE/Component/Client/Whois.pm',
			  'dist' => { 'COMPRESS' => 'gzip --best' },
			 );

