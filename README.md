CGI-Allow
=========

Decide whether to allow a client to run a CGI script.
Clearly this should not be your only line of defence,
but then neither should iptables, mod_security, etc.

Install the package in some path.  The prerequesits are:

CGI::Info
CGI::Lingua
Data::Throttler
Carp
CGI::IDS
DateTime;
LWP::Simple::WithCache;
XML::LibXML;

You can pass a logger argument for tracing what's going on.  logger should point to an object which takes methods such as trace,
debug, warn, info.  Log4perl is a good example.

Daily DShield signatures are downloaded.  To speed things up a *lot* you should use give the cache argument, otherwise each
call will result in a data download from dshield.org and you really don't want that. The cache object is an object which
takes get and set as methods.  I use CHI.

The run the code:

my $info = CGI::Info->new();
my $lingua = CGI::Lingua->new();
my $cache = $CHI->new(driver => 'BerkeleyDB', root_dir => $info->tmpdir(), namespace => $info->script_name());

unless(CGI::Allow::allow({ info => $info, lingua => $lingua, cache => $cache }) {
	print "403: Forbidden\n\n",
		"Go away!\n";

	die 'Disallow access';
}
