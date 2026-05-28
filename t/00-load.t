use strict;
use warnings;
use lib '.';
use Test::More tests => 3;

require_ok('Allow.pm');

# Without REMOTE_ADDR, allow() returns 1 immediately (not running as CGI)
delete local $ENV{REMOTE_ADDR};
is(CGI::Allow::allow(), 1, 'allow returns 1 when REMOTE_ADDR is unset');

ok(do { no warnings 'once'; scalar(keys %CGI::Allow::blacklist_agents) } > 0, 'blacklist_agents is populated');
