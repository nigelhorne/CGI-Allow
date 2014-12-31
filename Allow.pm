package CGI::Allow;

# Author Nigel Horne: njh@bandsman.co.uk
# Copyright (C) 2014, Nigel Horne

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

	unless($info->is_search_engine() || !defined($ENV{'REMOTE_ADDR'})) {
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
	if($logger) {
		$logger->debug('Allowing connexion');
	}
	$status = 1;
	return 1;
}

1;
