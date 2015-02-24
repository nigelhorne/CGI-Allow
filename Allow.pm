package CGI::Allow;

# Author Nigel Horne: njh@bandsman.co.uk
# Copyright (C) 2014-2015, Nigel Horne

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

our $status = -1;

sub allow {
	unless($status == -1) {
		# Cache the value
		return $status;
	}
	if(!defined($ENV{'REMOTE_ADDR'})) {
		# Not running as a CGI
		$status = 1;
		return 1;
	}

	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	my $info = $args{'info'};
	my $logger = $args{'logger'};

	if($logger) {
		$logger->trace('In ' . __PACKAGE__);
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

			unless($throttler->try_push(key => $ENV{'REMOTE_ADDR'})) {
				if($logger) {
					$logger->info("$ENV{REMOTE_ADDR} throttled");
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

		my $lingua = $args{'lingua'};
		if(defined($lingua) && $blacklist{uc($lingua->country())}) {
			if($logger) {
				$logger->info('blocked connexion from ' . $lingua->country());
			}
			$status = 0;
			return 0;
		}

		my $params = $info->params();
		if(defined($params) && keys(%{$params})) {
			require CGI::IDS;
			CGI::IDS->import();

			my $ids = CGI::IDS->new();
			$ids->set_scan_keys(scan_keys => 1);
			if($ids->detect_attacks(request => $params) > 0) {
				if($logger) {
					$logger->info('IDS blocked connexion for ' . $info->as_string());
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
					$logger->info("Blocked shellshocker for $ENV{HTTP_REFERER}");
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
					$logger->debug("setting cache to $cachecontent");
				}
				$cache->set($today, $cachecontent, '1 day');
			}
		}
	}

	foreach my $ip (@ips) {
		# FIXME: Doesn't realise 1.2.3.4 is the same as 001.002.003.004
		if($ip eq $ENV{'REMOTE_ADDR'}) {
			if($logger) {
				$logger->info("Dshield blocked connexion from $ENV{REMOTE_ADDR}");
			}
			$status = 0;
			return 0;
		}
	}

	if($logger) {
		$logger->trace("Allowing connexion from $ENV{REMOTE_ADDR}");
	}

	$status = 1;
	return 1;
}

1;
