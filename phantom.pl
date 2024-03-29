#!/usr/bin/perl -w

use strict;
use warnings;

use lib qw(.);
use lib qw(/opt/qradar/lib/perl);

use Syslog;
use Time::HiRes qw( time sleep usleep );
use Getopt::Std;
use IO::Socket;

# create log entries at a fixed rate (n per sec)
# Option defautls

my $me = $0;
$me =~ s|.*/||;

my %options = (
	d	=>	"127.0.0.1",	 # host
	p	=>	514,		 # port
	f	=>	"readme.syslog", # filename
	b	=>	0,		 # burst
	v	=>	0,		 # verbose
	t	=>	0,		 # tcp vs. udp
	l	=>	0,		 # loop option
#	u	=>	"127.0.0.2",	 # new IP to send
);

my $theProto='udp';

# Help
sub HELP_MESSAGE {
	print <<EOF;
$me [-d <host>] [-p <port>] [-f filename] [-u <IP>] [-l] [-t] [-b] [-n NAME] [-v] <messages per second>
Options:
-d : destination syslog host (default 127.0.0.1)
-p : destination port (default 514)
-f : filename to read (default readme.syslog)
-b : burst the same message for 20% of the delay time
-t : use TCP instead of UDP for sending syslogs
-v : verbose, display lines read in from file
-n : use NAME for object name in syslog header
-l : loop indefinately
-u : use this IP as spoofed sender (default is NOT to send IP header)
EOF
}

getopts('vbtlu:d:p:n:f:', \%options);

unless (@ARGV) {
	print STDERR "Need an event rate.\n";
	HELP_MESSAGE;
	exit 1;
}

my $nmsg = shift @ARGV;

if (!($nmsg =~ /^\d+$/)) { 
	print "Invalid number of messages per second.\n";
	HELP_MESSAGE; 
	exit 1;
}

if ($options{t}) { $theProto='tcp'; }

my $syslog = new Syslog(
	name     => '',	# prog name for syslog header
	facility => '',
	priority => '',
	loghost  => $options{d},
	port     => $options{p},
	proto	 => $theProto,
);

my $sock = IO::Socket::INET->new(
    Proto    => 'udp',
    PeerPort => 514,
    PeerAddr => 'qradar',
) or die "Could not create socket: $!\n";

sub doitall() { # for purpose of infinate looping

open(F,$options{f}) or die("Unable to open file: $options{f}\n");

print STDERR "generating $nmsg messages per second to $options{d}:$options{p}\n";
print STDERR "Ctrl-c to stop\n";

# delay in milliseconds
my $delay = 1.0/$nmsg;
my $resolution = 0.2;
my $burst = $nmsg * $resolution;

my $lineRead;

if ($options{b}) {
    print "Sending $burst messages every ", int ($delay * 1000), "ms\n";
} 

while (<F>) {
	$lineRead=$_;
	    if ($options{u}) { $sock->send("This is a test syslog", host=> 10.0.0.1); }
	    else { $syslog->send($lineRead); }
}

close(F);
} # end of the subroutine
 
if ($options{l}) {
	while (1) { doitall(); }
} else { doitall(); }
exit 0;

