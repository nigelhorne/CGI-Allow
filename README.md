CGI-Allow
=========

Decide whether to allow a client to run a CGI script

Install the package in some path.  The prerequesits are:

CGI::Info
CGI::Lingua
Data::Throttler
Carp
CGI::IDS

The run the code:

my $info = CGI::Info->new();
my $lingua = CGI::Lingua->new();

unless(CGI::Allow::allow({ info => $info, lingua => $lingua }) {
	print "403: Forbidden\n\n";
	print "Go away!\n";
	die "Disallow access";
}
