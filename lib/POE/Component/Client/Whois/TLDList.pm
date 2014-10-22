package POE::Component::Client::Whois::TLDList;

use strict;
use warnings;
use Data::Dumper;

our %data;

while (<DATA>) {
	chomp;
	next if ( /^#/ );
	my ($tld,@values) = split(/\s+/);
	$data{ $tld } = \@values;
}


sub new {
  my $self = bless { data => \%data }, shift;
  return $self;
}

sub dump_tlds {
  my $self = shift;
  print STDERR Dumper( $self->{data} );
  return 1;
}

sub tld {
  my $self = shift;
  my $lookup = shift || return;

  foreach my $tld ( keys %{ $self->{data} } ) {
	if ( $lookup =~ /\Q$tld\E$/ ) {
		return @{ $self->{data}->{ $tld } };
	}
  }
  return;
}

1;

__DATA__
# NIC? means I have not been able to find the registry
# NIC-FR means the TLD is managed by AFNIC, but I could not find any info
# UPR means the TLD is managed by UPR, but I could not find any info
#
.br.com	whois.centralnic.net
.cn.com	whois.centralnic.net
.eu.com	whois.centralnic.net
.gb.com	whois.centralnic.net
.gb.net	whois.centralnic.net
.hu.com	whois.centralnic.net
.no.com	whois.centralnic.net
.qc.com	whois.centralnic.net
.sa.com	whois.centralnic.net
.se.com	whois.centralnic.net
.se.net	whois.centralnic.net
.uk.com	whois.centralnic.net
.uk.net	whois.centralnic.net
.us.com	whois.centralnic.net
.uy.com	whois.centralnic.net
.za.com	whois.centralnic.net
.eu.org	whois.eu.org
.com	whois.internic.net
.net	whois.internic.net
.org	whois.publicinterestregistry.net
.edu	whois.educause.net
.gov	whois.nic.gov
.int	whois.icann.org
.mil	whois.nic.mil
# whois server not yet available, see also http://www.nic.aero/whoswho.php
.aero	whois.nic.aero
.biz	whois.nic.biz
.coop	whois.nic.coop
.info	whois.afilias.info
.museum	whois.museum
.name	whois.nic.name
# not yet delegated, I hope they will not screw up the hostname
.pro	whois.nic.pro
.ac	whois.nic.ac
.ad	NONE		# www.nic.ad
.ae	WEB http://cc.emirates.net.ae/Customer_care/cc_card/check_domains.choose_domains/
.af	NONE		# was whois.nic.af
.ag	WEB http://www.nic.ag/domain_search.htm
.ai	NONE		# http://www.offshore.com.ai/domain_names/
.al	NONE		# http://www.inima.al/Domains.html
.am	whois.amnic.net		# down?
.am	WEB https://www.amnic.net/whois/
.an	NONE		# http://www.una.net/an_domreg/
.ao	NONE		# www.dns.ao
.aq	NONE		# 2day.com
.ar	WEB http://www.nic.ar/consultas/consdom.htm
.as	whois.nic.as
.at	whois.aco.net
.net.au	whois.connect.com.au
.au	whois.aunic.net
#.aw			# NIC? www.setarnet.aw
.az	NONE		# www.nic.az
.ba	NONE		# http://www.utic.net.ba/domen/
.bb	WEB http://domains.org.bb/regsearch/
.bd	NONE		# NIC?
.be	whois.dns.be
.bf	NONE		# http://www.onatel.bf/domaine.htm
.bg	whois.ripe.net
#.bh	NONE		# NIC? www.inet.com.bh
.bi	WEB http://www.nic.bi/cgi-bin/whoisbi.pl
#.bj			# NIC? www.opt.bj
.bm	WEB http://www.bermudanic.bm/cgi-bin/BermudaNIC/rwhois_query.pl	# rwhois.bermudanic.bm:4321
#.bn	NONE		# NIC? www.brunet.bn
.bo	NONE		# www.nic.bo
.br	whois.nic.br
.bs	WEB http://www.nic.bs/cgi-bin/search.pl
.bt	whois.nic.tm
.bv	NONE		# http://www.uninett.no/navn/bv-sj.html
#.bw			# NIC? www.botsnet.bw btc.bw
.by	WEB http://www.tld.by/indexeng.html
.bz	NONE		# www.nic.nz
.ca	whois.cira.ca
.cc	whois.nic.cc
.cd	whois.nic.cd
.cf	WEB http://www.nic.cf/whois.php3
.cg	WEB http://www.nic.cg/cgi-bin/whoiscg.pl
.ch	whois.nic.ch
.ci	www.nic.ci
.ck	whois.nic.ck
.cl	whois.nic.cl
.cm	NONE		# http://info.intelcam.cm
.ac.cn	whois.cnc.ac.cn
.edu.cn	whois.edu.cn
.cn	whois.cnnic.net.cn
.uk.co	whois.uk.co
.co	WEB http://daimon.uniandes.edu.co:8890/dominio/plsql/PConsulta.ConsultarDominio
.cr	WEB http://www.nic.cr/consulta-dns.html
.cu	WEB http://www.nic.cu/consultas/consult.html
#.cv			# NIC? dns.cv?
.cx	whois.nic.cx
.cy	NONE		# www.nic.cy
.cz	whois.nic.cz
.de	whois.denic.de
.dj	NONE		# www.nic.dj (NOT YET)
.dk	WEB http://www.dk-hostmaster.dk/dkwhois.php?lang=eng
.dm	NONE		# www.domains.dm ?
.do	WEB http://www.nic.do
.dz	NONE
.ec	WEB http://www.nic.ec
#.ee	WEB http://www.eenet.ee/info/index.html
.ee	whois.eenet.ee
#.eg	NONE		# NIC? http://www.frcu.eun.eg
#.eh
#.er	NONE		# NIC? www.noc.net.er (recently connected!)
.es	WEB http://www.nic.es/whois/
#.et	NONE		# NIC? www.telecom.net.et
.fi	WEB http://cgi.ficora.fi/wwwbin/domains.pl?language=eng
.fj	whois.usp.ac.fj
.fk	NONE		# http://www.fidc.org.fk/domain-registration/home.htm
.fm	WEB http://www.nic.fm/register.html
.fo	whois.ripe.net	# www.nic.fo
.fr	whois.nic.fr
#.fx
#.ga			# NIC? www.inet.ga
.gb	NONE
#.gd			# NO NIC (UPR)
.ge	WEB http://www.nic.net.ge
.gf	whois.nplus.gf
.gg	NONE		# http://www.isles.net
.gh	NONE		# http://www.ghana.com/domreg.html
.gi	NONE		# http://www.gibnet.gi/nic/
.gl	whois.ripe.net
.gm	whois.ripe.net	# www.nic.gm
.gn	NONE		# http://www.psg.com/dns/gn/
#.gp			# www.nic.gp - broken like mq
#.gq			# NO NIC http://www.intnet.gq
.gr	WEB http://www.hostmaster.gr/cgi-bin/webwhois
.gs	whois.adamsnames.tc
.gt	WEB http://www.gt/whois.htm
.gu	WEB http://gadao.gov.gu/Scripts/wwsquery/wwsquery.dll?hois=guamquery
#.gw			# no NIC?
#.gy			# NIC? (UPR)
.hk	whois.hkdnr.net.hk
.hm	whois.registry.hm
.hn	NONE		# www.nic.hn
.hr	WEB http://noc.srce.hr/web-eng/searchdomain.htm
#.ht			# NIC? http://www.haitiworld.com/
.hu	whois.nic.hu
.id	whois.idnic.net.id
.ie	whois.domainregistry.ie
.il	whois.isoc.org.il
.im	WEB http://www.nic.im/exist.html
.in	whois.ncst.ernet.in
.io	WEB http://www.io.io/whois.html
#.iq			# NIC?
.ir	WEB http://aria.nic.ir/forms/whois.html
.is	whois.isnet.is
.it	whois.nic.it
.je	NONE 		# http://www.isles.net
#.jm			# NIC? uwimona.edu.jm http://nic.jm
.jo	WEB http://amon.nic.gov.jo/dns/
.jp	whois.nic.ad.jp
.ke	NONE		# http://www.nbnet.co.ke/domain.htm
.kg	whois.domain.kg
.kh	NONE		# http://www.mptc.gov.kh/Reculation/DNS.htm
#.ki			# NIC? www.tsk.net.ki
.km	NONE		# NO NIC
#.kn			# NO NIC (UPR)
#.kp
.kr	whois.krnic.net
.kw	WEB http://www.domainname.net.kw
.ky	NONE		# www.nic.ky
.kz	whois.domain.kz
.la	whois.nic.la
.lb	WEB http://www.aub.edu.lb/lbdr/search.html
.lc	NONE		# http://www.isisworld.lc/domains/
.li	whois.nic.li
.lk	whois.nic.lk
.lr	NONE		# http://www.psg.com/dns/lr/
.ls	NONE
.lt	whois.ripe.net
.lu	whois.restena.lu
.lv	whois.ripe.net
.ly	WEB http://www.lydomains.com/whois.asp
#.ma			# NIC? http://www.anrt.net.ma/
.mc	whois.ripe.net
.md	WEB http://www.nic.md/search.html
.mg	NONE		# www.nic.mg
.mh	NONE		# www.nic.net.mh
#.mk			# NIC? http://www.mpt.com.mk
#.ml			# NIC? www.sotelma.ml
.mm	whois.nic.mm
.mn	WEB http://whois.nic.mn
.mo	WEB http://www.monic.net.mo	# whois.umac.mo
.mp	NONE		# www.marketplace.mp
#.mq			# www.nic.mq broken like gp
.mr	NONE		# http://www.univ-nkc.mr/nic_mr.html
.ms	whois.adamsnames.tc
.mt	WEB http://www.um.edu.mt/nic/dir/
.mu	WEB http://www.nic.mu/cgi-bin/mu_whois.cgi
#.mv			# NIC? dhiraagu.com.mv
.mw	WEB http://www.tarsus.net/whois/
.mx	whois.nic.mx
.my	NONE		# http://www.mynic.net
#.mz			# NIC? www.uem.mz
.na	WEB http://www.lisse.na/cgi-bin/whois.cgi
.nc	whois.cctld.nc
#.ne			# NIC? http://www.intnet.ne
.nf	NONE		# http://www.names.nf
.ng	whois.rg.net
.ni	NONE		# www.nic.ni
.nl	whois.domain-registry.nl
.no	whois.norid.no
.np	WEB http://www.mos.com.np/domsearch.html
#.nr			# NIC? www.cenpan.net.nr
.nu	whois.nic.nu
.nz	whois.domainz.net.nz
#.om	NONE		# NIC? http://www.gto.net.om
.pa	WEB http://www.nic.pa
.pe	whois.rcp.net.pe
#.pf			# NIC? mana.pf
.pg	NONE	# http://www.unitech.ac.pg/Unitech_General/ITS/ITS_Dns.htm
.ph	WEB http://www.names.ph/search.html
#.pk	whois.pknic.net.pk	# the host does not exist anymore
.pl	whois.dns.pl
.pm	whois.nic.fr
.pn	NONE		# www.nic.pn
.pr	NONE		# http://www.uprr.pr/main.html
.ps	WEB http://www.nic.ps/whois/
.pt	NONE		# www.dns.pt
.pw	whois.nic.pw
.py	WEB http://www.nic.py/consultas/
.qa	NONE		# http://www.qatar.net.qa/services/virtual.htm
.re	whois.nic.fr
.ro	whois.rotld.ro
.ru	whois.ripn.net
.rw	WEB http://www.nic.rw/cgi-bin/whoisrw.pl
.sa	WEB http://www.saudinic.net.sa/domain/whois.htm
.sb	WEB http://www.sbnic.net.sb/search.html
.sc	NONE		# www.nic.sc
#.sd			# NIC? http://www.sudatel.sd
.se	whois.nic-se.se
.sg	whois.nic.net.sg
.sh	whois.nic.sh
.si	whois.arnes.si
.sj	NONE		# http://www.uninett.no/navn/bv-sj.html
.sk	whois.ripe.net
#.sl			# NIC? http://www.sierratel.sl/
.sm	whois.ripe.net
.sn	NONE		# www.nic.sn
.so	NONE		# www.nic.so - no country, no NIC
.sr	whois.register.sr
.st	whois.nic.st
.su	whois.ripn.net
.sv	WEB http://www.uca.edu.sv/dns/	# http://www.svnet.org.sv/
#.sy			# NIC? (usually offline?)
.sz	NONE		# http://www.iafrica.sz/domreg/
.tc	whois.adamsnames.tc
#.td			# NIC? http://www.tit.td
.tf	whois.adamsnames.tc
.tg	WEB http://www.nic.tg
.th	whois.thnic.net
.tj	whois.nic.tj
.tk	NONE		# 2day.com
.tm	whois.nic.tm
.tn	NONE		# http://www.ati.tn/Nic/
.to	whois.tonic.to
.tp	NONE		# www.nic.tp
.tr	whois.metu.edu.tr
.tt	WEB http://www.nic.tt/cgi-bin/whois.cgi
.tv	NONE		# http://internet.tv
.tw	whois.twnic.net
.tz	NONE		# http://www.psg.com/dns/tz/
.ua	whois.com.ua
.ug	www.registry.co.ug
.gov.uk	whois.ja.net
.ac.uk	whois.ja.net
.uk	whois.nic.uk
.um	NONE		# see .us
.fed.us	whois.nic.gov
.us	NONE		# for info: usdomreg@nic.us
.com.uy	WEB http://dns.antel.net.uy/clientes/consultar.htm
.uy	WEB http://www.rau.edu.uy/rau/dom/reg.htm
#.uz			# www.noc.uz (broken)
.va	whois.ripe.net
.vc	whois.opensrs.net
.ve	WEB http://www.nic.ve/nicwho01.html	# rwhois.reacciun.ve:4321
.vg	whois.adamsnames.tc
.vi	WEB http://208.30.96.227/whoisform.htm
.vn	WEB http://www.vnnic.net.vn/english/reg_domain/
.vu	WEB http://www.vunic.vu/whois
#.wf			# NIC-FR!
.ws	whois.samoanic.ws
#.ye			# NIC? www.y.net.ye
#.yt			# NIC-FR!
.yu	NONE		# www.nic.yu
.ac.za	whois.ac.za
#.bourse.za	whois.bourse.za	# broken
.co.za	WEB http://whois.co.za/
.net.za	whois.net.za
.org.za	WEB http://www.org.za/	# rwhois.org.za:4321
.za	NONE		# http://www2.frd.ac.za/uninet/zadomains.html
.zm	NONE		# http://www.zamnet.zm/domain.shtml
.zr	NONE		# obsoleted by cd
#.zw			# NIC? zptc.co.zw http://www.zispa.co.zw/
-au-dom	whois.aunic.net
-dom	whois.networksolutions.com
-org	whois.networksolutions.com
-hst	whois.networksolutions.com
-arin	whois.arin.net
-ripe	whois.ripe.net
-mnt	whois.ripe.net
-gandi	whois.gandi.net
-ap	whois.apnic.net
-au	whois.aunic.net
-cn	whois.cnnic.net.cn
-dk	whois.dk-hostmaster.dk
-ti	whois.telstra.net
-is	whois.isnet.is
-6bone	whois.6bone.net
-norid	whois.norid.no
-ripn	whois.ripn.net
-sgnic	whois.nic.net.sg
-metu	whois.metu.edu.tr
-cknic	whois.nic.ck
-cz	whois.nic.cz
-kg	whois.domain.kg
-rotld	whois.rotld.ro
-itnic	whois.nic.it
-frnic	whois.nic.fr
-nicat	whois.nic.at
-il	whois.isoc.org.il
-lrms	whois.afilias.net
-tw	whois.twnic.net
