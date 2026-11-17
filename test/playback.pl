# playback.pl REC PORT CLIENTOUT - plays a recorded RDP server to one client.
# Runs inside the nt31sdk image (it has perl, not python); winetest.py starts it.
# Sends each recorded chunk once the client has sent as many packets as when
# it was recorded. Saves all client bytes to CLIENTOUT. Closes 5 s after the end.
use strict; use IO::Socket::INET; use IO::Select;
my ($rec, $port, $cout) = @ARGV;
open(my $rf, '<:raw', $rec) or die "playback: $rec: $!";
my $all = do { local $/; <$rf> }; close $rf;
my @recs; my $o = 0;
while ($o < length $all) {
	my ($t, $n) = unpack('VV', substr($all, $o, 8));
	push @recs, [$t, substr($all, $o + 8, $n)];
	$o += 8 + $n;
}
my $ls = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port,
	Listen => 1, ReuseAddr => 1) or die "playback: listen: $!";
print "playback: listening, ", scalar(@recs), " chunks\n";
my $c = $ls->accept or die "playback: accept: $!";
binmode $c;
open(my $co, '>:raw', $cout) or die "playback: $cout: $!";
my ($buf, $npkt, $closed) = ('', 0, 0);
my $sel = IO::Select->new($c);
sub pump {
	return unless $sel->can_read(shift);
	my $d;
	if (!sysread($c, $d, 65536)) { $closed = 1; return; }
	print $co $d;
	$buf .= $d;
	while (length($buf) >= 4) {
		my $n = unpack('n', substr($buf, 2, 2));
		last if $n < 4 || length($buf) < $n;
		$buf = substr($buf, $n);
		$npkt++;
	}
}
for my $r (@recs) {
	my $t0 = time;
	pump(1) while $npkt < $r->[0] && !$closed && time - $t0 < 20;
	if ($npkt < $r->[0]) { print "playback: stalled at $npkt client packets, needed $r->[0]\n"; last; }
	syswrite($c, $r->[1]);
}
print "playback: all sent at $npkt client packets\n";
my $t0 = time;
pump(1) while !$closed && time - $t0 < 5;
print "playback: client packets $npkt, client closed: $closed\n";
close $co;
close $c;
