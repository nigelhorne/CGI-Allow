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

use strict;
use warnings;
use Carp;
use File::Spec;

our %blacklist_countries = (
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
	'Mozilla/5.0 (compatible; SemrushBot/6~bl; +http://www.semrush.com/bot.html)' => 'SemrushBot',
	'ZoominfoBot (zoominfobot at zoominfo dot com)' => 'zoominfobot',
);

our %status;

sub allow {
	my $addr = $ENV{'REMOTE_ADDR'};

	if(!defined($addr)) {
		# Not running as a CGI
		return 1;
	}

	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	my $logger = $args{'logger'};

	if(defined($status{$addr})) {
		# Cache the value
		if($logger) {
			$logger->debug("$addr: cached value ", $status{$addr});
		}
		return $status{$addr};
	}
	if($logger) {
		$logger->trace('In ', __PACKAGE__);
	}

	if($ENV{'HTTP_USER_AGENT'}) {
		if(my $blocked = $blacklist_agents{$ENV{'HTTP_USER_AGENT'}}) {
			if($logger) {
				$logger->info("$blocked blacklisted");
			}
			$status{$addr} = 0;
			return 0;
		}
	}

	my $info = $args{'info'};
	if(!defined($info)) {
		if($logger) {
			$logger->warn('Info not given');
		} else {
			carp('Info not given');
		}
		$status{$addr} = 1;
		return 1;
	}

	unless($info->is_search_engine()) {
		require Data::Throttler;
		Data::Throttler->import();

		# Handle YAML Errors
		my $db_file = File::Spec->catfile($info->tmpdir(), 'throttle');
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
					$logger->warn("$addr has been throttled");
				}
				$status{$addr} = 0;
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
			if(defined($lingua) && $blacklist_countries{uc($lingua->country())}) {
				if($logger) {
					$logger->warn("$addr blocked connexion from ", $lingua->country());
				}
				$status{$addr} = 0;
				return 0;
			}
			if(($ENV{'HTTP_REFERER'} =~ /^http:\/\/keywords-monitoring-your-success.com\/try.php/) ||
			   ($ENV{'HTTP_REFERER'} =~ /^http:\/\/www.tcsindustry\.com\//) ||
			   ($ENV{'HTTP_REFERER'} =~ /^http:\/\/free-video-tool.com\//)) {
				if($logger) {
					$logger->warn("$addr blocked connexion from ", $lingua->country());
				}
				$status{$addr} = 0;
				return 0;
			}
		}

		if(defined($ENV{'REQUEST_METHOD'}) && ($ENV{'REQUEST_METHOD'} eq 'GET')) {
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
					$status{$addr} = 0;
					return 0;
				}
			}
		}

		if(my $referer = $ENV{'HTTP_REFERER'}) {
			$referer =~ tr/ /+/;	# FIXME - this shouldn't be happening

			# Protect against Shellshocker
			require Data::Validate::URI;
			Data::Validate::URI->import();

			unless(Data::Validate::URI->new()->is_uri($referer)) {
				if($logger) {
					$logger->warn("$addr: Blocked shellshocker for $ENV{HTTP_REFERER}");
				}
				$status{$addr} = 0;
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
			if($ips[0]) {
				$readfromcache = 1;
			} else {
				if($logger) {
					$logger->info("DShield cache for $today is empty, deleting to force reread");
				}
				$cache->remove($today);
			}
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
				next if($readfromcache && ($lastseen ne $today));  # FIXME: Should be today or yesterday to avoid midnight rush
				my $ip = $source->findnodes('./ip')->to_literal();
				$ip =~ s/0*(\d+)/$1/g;	# Perl interprets numbers leading with 0 as octal
				push @ips, $ip;
			}
			if(defined($cache) && $ips[0] && !$readfromcache) {
				my $cachecontent = join(',', @ips);
				if($logger) {
					$logger->info("Setting DShield cache for $today to $cachecontent");
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
		$status{$addr} = 0;
		return 0;
	}

	if($info->get_cookie(cookie_name => 'mycustomtrackid')) {
		if($logger) {
			$logger->warn('Blocking possible jqic');
		}
		$status{$addr} = 0;
		return 0;
	}

	if($logger) {
		$logger->trace("Allowing connexion from $addr");
	}

	$status{$addr} = 1;
	return 1;
}

1;
