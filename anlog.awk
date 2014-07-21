#!/usr/bin/awk

###########################
# anlog.awk is a awk script to analysis the iptables log.
#
# It creates the file output in the directory /usr/local/iptreport
#
# contact : ride_online@hotmail.fr
###########################

# BEGIN : get the arguments passed by ipt_analysis and initialize the variables
BEGIN {
	if ( ARGC == 4 ){
		nbday=ARGV[1]
		FREPORT=ARGV[2]

		delete ARGV[1]
		delete ARGV[2]
	}
	else if ( ARGC == 3 ) {
		"date '+%d'" |getline nbday 
		close("getline")

		FREPORT=ARGV[1]
		delete ARGV[1]
	}
	else {		
		print "Error of syntax"
		exit 1
	}

# Counters
	ind_in=0
	ind_in_tcp=0
	ind_in_udp=0
	ind_warn=0
	ind_warn_tcp=0
	ind_warn_udp=0
	ind_syn=0
	ind_syn_tcp=0
	ind_syn_udp=0
}

# We get back the lines writed by iptables and fill the arrays
$2 == nbday && $8 ~ /IPT/ {

	if($9 ~ /INPUT/) {
		if($23 ~ /UDP/) {
			ind_in_udp++
			tin_udp[ind_in_udp]=$0
		}
		else if($23 ~ /TCP/) {
			ind_in_tcp++
			tin_tcp[ind_in_tcp]=$0
		}
		else {
			ind_in++
			tin[ind_in]=$0
		}
	}

	if($9 ~ /New/) {
		if($23  ~ /UDP/) {
			ind_syn_udp++
			tsyn_udp[ind_syn_udp]=$0
		}
		else if($23 ~ /TCP/) {
			ind_syn_tcp++
			tsyn_tcp[ind_syn_tcp]=$0
		}
		else {
			ind_syn++
			tsyn[ind_syn]=$0
		}
	}

	if($9 ~ /Warn/) {
		if($23 ~ /UDP/) {
			ind_warn_udp++
			twarn_udp[ind_warn_udp]=$0
		}
		else if($23 ~ /TCP/) {
			ind_warn_tcp++
			twarn_tcp[ind_warn_tcp]=$0
		}
		else {
			ind_warn++
			twarn[ind_warn]=$0
		}
	}
}

# END : we shape the data collected
END {
	print "---------- Analysis of iptables.log  -----------" > FREPORT

	print "-------------- WARNING REPORT ------------------" > FREPORT
print "TCP packets :	", ind_warn_tcp," packets" > FREPORT
	for (i = 1 ; i <= ind_warn_tcp ; i++)
	{
		split(twarn_tcp[i],vtwarn_tcp," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtwarn_tcp[1], vtwarn_tcp[2], vtwarn_tcp[3], vtwarn_tcp[12], vtwarn_tcp[15],vtwarn_tcp[16],vtwarn_tcp[17],vtwarn_tcp[18],vtwarn_tcp[20],vtwarn_tcp[21],vtwarn_tcp[23],vtwarn_tcp[24],vtwarn_tcp[25],vtwarn_tcp[28]) > FREPORT
	}
print "UDP packets :	", ind_warn_udp," packets" > FREPORT
	for (i = 1 ; i <= ind_warn_udp ; i++)
	{
		split(twarn_udp[i],vtwarn_udp," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtwarn_udp[1], vtwarn_udp[2], vtwarn_udp[3], vtwarn_udp[12], vtwarn_udp[15],vtwarn_udp[16],vtwarn_udp[17],vtwarn_udp[18],vtwarn_udp[20],vtwarn_udp[21],vtwarn_udp[23],vtwarn_udp[24],vtwarn_udp[25],vtwarn_udp[28]) > FREPORT
	}

print "Other packets :	", ind_warn," packets" > FREPORT
	for (i = 1 ; i <= ind_warn ; i++)
	{
		split(twarn[i],vtwarn," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtwarn[1], vtwarn[2], vtwarn[3], vtwarn[12], vtwarn[15],vtwarn[16],vtwarn[17],vtwarn[18],vtwarn[20],vtwarn[21],vtwarn[23],vtwarn[24],vtwarn[25],vtwarn[28]) > FREPORT
	}

	print "--------------- INPUT REPORT -------------------" > FREPORT

print "TCP packets :	", ind_in_tcp," packets" > FREPORT
	for (k = 1 ; k <= ind_in_tcp ; k++)
	{
		split(tin_tcp[k],vtin_tcp," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtin_tcp[1], vtin_tcp[2], vtin_tcp[3], vtin_tcp[12], vtin_tcp[15],vtin_tcp[16],vtin_tcp[17],vtin_tcp[18],vtin_tcp[20],vtin_tcp[21],vtin_tcp[23],vtin_tcp[24],vtin_tcp[25],vtin_tcp[28]) > FREPORT
	}
print "UDP packets :	", ind_in_udp," packets" > FREPORT
	for (k = 1 ; k <= ind_in_udp ; k++)
	{
		split(tin_udp[k],vtin_udp," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtin_udp[1], vtin_udp[2], vtin_udp[3], vtin_udp[12], vtin_udp[15],vtin_udp[16],vtin_udp[17],vtin_udp[18],vtin_udp[20],vtin_udp[21],vtin_udp[23],vtin_udp[24],vtin_udp[25],vtin_udp[28]) > FREPORT
	}

print "Other packets :	", ind_in," packets" > FREPORT
	for (k = 1 ; k <= ind_in ; k++)
	{
		split(tin[k],vtin," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtin[1], vtin[2], vtin[3], vtin[12], vtin[15],vtin[16],vtin[17],vtin[18],vtin[20],vtin[21],vtin[23],vtin[24],vtin[25],vtin[28]) > FREPORT
	}

	print "------------- NEW NOT SYN REPORT ---------------" > FREPORT

print "TCP packets :	", ind_syn_tcp," packets" > FREPORT
	for (j = 1 ; j <= ind_syn_tcp ; j++)
	{
		split(tsyn_tcp[j],vtsyn_tcp," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtsyn_tcp[1], vtsyn_tcp[2], vtsyn_tcp[3], vtsyn_tcp[12], vtsyn_tcp[15],vtsyn_tcp[16],vtsyn_tcp[17],vtsyn_tcp[18],vtsyn_tcp[20],vtsyn_tcp[21],vtsyn_tcp[23],vtsyn_tcp[24],vtsyn_tcp[25],vtsyn_tcp[28]) > FREPORT
	}
print "UDP packets :	", ind_syn_udp," packets" > FREPORT
	for (j = 1 ; j <= ind_syn_udp ; j++)
	{
		split(tsyn_udp[j],vtsyn_udp," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtsyn_udp[1], vtsyn_udp[2], vtsyn_udp[3], vtsyn_udp[12], vtsyn_udp[15],vtsyn_udp[16],vtsyn_udp[17],vtsyn_udp[18],vtsyn_udp[20],vtsyn_udp[21],vtsyn_udp[23],vtsyn_udp[24],vtsyn_udp[25],vtsyn_udp[28]) > FREPORT
	}

print "Other packets :	",ind_syn," packets" > FREPORT
	for (j = 1 ; j <= ind_syn ; j++)
	{
		split(tsyn[j],vtsyn," ")
		printf("%s %s %s  %s %s %s %s %s %s %s %s %s %s %s\n", vtsyn[1], vtsyn[2], vtsyn[3], vtsyn[12], vtsyn[15],vtsyn[16],vtsyn[17],vtsyn[18],vtsyn[20],vtsyn[21],vtsyn[23],vtsyn[24],vtsyn[25],vtsyn[28]) > FREPORT
	}

	print "-------------- END of analysis -----------------" > FREPORT 
	close(FREPORT)

	exit 0
}
