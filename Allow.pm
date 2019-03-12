package CGI::Allow;

# Author Nigel Horne: njh@bandsman.co.uk
# Copyright (C) 2014-2019, Nigel Horne

# Usage is subject to licence terms.
# The licence terms of this software are as follows:
# Personal single user, single computer use: GPL2
# All other users (including Commercial, Charity, Educational, Government)
#	must apply in writing for a licence for use from Nigel Horne at the
#	above e-mail.

# Decide if we're going to allow this client to view the website
# Usage:
# unless(CGI::Allow::allow({info => $info, lingua => $lingua})) {

use Carp;

our %blacklist = (
	'BY' => 1,
	'MD' => 1,
	'RU' => 1,
	'CN' => 1,
	'BR' => 1,
	'UY' => 1,
	'TR' => 1,
	'MA' => 1,
	'VE' => 1,
	'SA' => 1,
	'CY' => 1,
	'CO' => 1,
	'MX' => 1,
	'IN' => 1,
	'RS' => 1,
	'PK' => 1,
	'UA' => 1,
);

our %blacklist_agents = (
	'Barkrowler' => 'Barkrowler',
	'masscan' => 'Masscan',
	'WBSearchBot' => 'Warebay',
	'MJ12' => 'Majestic',
	'Mozilla/4.0 (compatible; Vagabondo/4.0; webcrawler at wise-guys dot nl; http://webagent.wise-guys.nl/; http://www.wise-guys.nl/)' => 'wise-guys',
	'Mozilla/5.0 zgrab/0.x' => 'zgrab',
	'Mozilla/5.0 (compatible; IODC-Odysseus Survey 21796-100-051215155936-107; +https://iodc.co.uk)' => 'iodc',
	'Mozilla/5.0 (compatible; adscanner/)' => 'adscanner',
	'ZoominfoBot (zoominfobot at zoominfo dot com)' => 'zoominfobot',
);

our %status;

sub allow {
	my $addr = $ENV{'REMOTE_ADDR'};

	if(!defined($addr)) {
		# Not running as a CGI
		return 1;
	}

	if(defined($status{$addr})) {
		# Cache the value
		return $status;
	}

	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	my $info = $args{'info'};
	my $logger = $args{'logger'};

	if($logger) {
		$logger->trace('In ', __PACKAGE__);
	}

	if($ENV{'HTTP_USER_AGENT'}) {
		if(my $blocked = $blacklist_agents{$ENV{'HTTP_USER_AGENT'}}) {
			if($logger) {
				$logger->info("$blocked blacklisted");
			}
			$status = 0;
			return 0;
		}
	}

	if(!defined($info)) {
		if($logger) {
			$logger->warn('Info not given');
		} else {
			carp('Info not given');
		}
		$status = 1;
		return 1;
	}

	unless($info->is_search_engine()) {
		require Data::Throttler;
		Data::Throttler->import();

		# Handle YAML Errors
		my $db_file = $info->tmpdir() . '/throttle';
		eval {
			my $throttler = Data::Throttler->new(
				max_items => 15,
				interval => 90,
				backend => 'YAML',
				backend_options => {
					db_file => $db_file
				}
			);

			unless($throttler->try_push(key => $addr)) {
				if($logger) {
					$logger->warn("$addr throttled");
				}
				$status = 0;
				return 0;
			}
		};
		if($@) {
			if($logger) {
				$logger->debug("removing $db_file");
			}
			unlink($db_file);
		}

		unless($addr =~ /^192\.168\./) {
			my $lingua = $args{'lingua'};
			if(defined($lingua) && $blacklist{uc($lingua->country())}) {
				if($logger) {
					$logger->warn("$addr blocked connexion from ", $lingua->country());
				}
				$status = 0;
				return 0;
			}
		}

		my $params = $info->params();
		if(defined($params) && keys(%{$params})) {
			require CGI::IDS;
			CGI::IDS->import();

			my $ids = CGI::IDS->new();
			$ids->set_scan_keys(scan_keys => 1);
			if($ids->detect_attacks(request => $params) > 0) {
				if($logger) {
					$logger->warn("$addr: IDS blocked connexion for ", $info->as_string());
				}
				$status = 0;
				return 0;
			}
		}

		if(defined($ENV{'HTTP_REFERER'})) {
			# Protect against Shellshocker
			require Data::Validate::URI;
			Data::Validate::URI->import();

			$v = Data::Validate::URI->new();
			unless($v->is_uri($ENV{'HTTP_REFERER'})) {
				if($logger) {
					$logger->warn("Blocked shellshocker for $ENV{HTTP_REFERER}");
				}
				$status = 0;
				return 0;
			}
		}
	}

	require DateTime;
	DateTime->import();

	my $cache = $args{'cache'};
	my @ips;
	my $today = DateTime->today()->ymd();
	my $readfromcache;

	if(defined($cache)) {
		my $cachecontent = $cache->get($today);
		if($cachecontent) {
			if($logger) {
				$logger->debug("read from cache $cachecontent");
			}
			@ips = split(/,/, $cachecontent);
			$readfromcache = 1;
		}
	}

	unless($ips[0]) {
		require LWP::Simple;
		LWP::Simple->import();
		require XML::LibXML;
		XML::LibXML->import();

		if($logger) {
			$logger->trace('Downloading DShield signatures');
		}
		my $xml;
		eval {
			$xml = XML::LibXML->load_xml(string => get('https://secure.dshield.org/api/sources/attacks/100/2012-03-08'));
		};
		unless($@ || !defined($xml)) {
			foreach my $source ($xml->findnodes('/sources/data')) {
				my $lastseen = $source->findnodes('./lastseen')->to_literal();
				next unless($lastseen eq $today);  # FIXME: Should be today or yesterday to avoid midnight rush
				my $ip = $source->findnodes('./ip')->to_literal();
				$ip =~ s/0*(\d+)/$1/g;	# Perl interprets numbers leading with 0 as octal
				push @ips, $ip;
			}
			if(defined($cache) && !$readfromcache) {
				my $cachecontent = join(',', @ips);
				if($logger) {
					$logger->debug("setting DShield cache to $cachecontent");
				}
				$cache->set($today, $cachecontent, '1 day');
			}
		}
	}

	# FIXME: Doesn't realise 1.2.3.4 is the same as 001.002.003.004
	if(grep($_ eq $addr, @ips)) {
		if($logger) {
			$logger->warn("Dshield blocked connexion from $addr");
		}
		$status = 0;
		return 0;
	}

	if($info->get_cookie(cookie_name => 'mycustomtrackid')) {
		if($logger) {
			$logger->warn('Blocking possible jqic');
		}
		$status = 0;
		return 0;
	}

	if($logger) {
		$logger->trace("Allowing connexion from $addr");
	}

	$status = 1;
	return 1;
}

1;
