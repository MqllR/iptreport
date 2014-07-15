#!/usr/bin/awk

BEGIN {
	if ( ARGC == 4 ){
		nbday=ARGV[1]
		FREPORT=ARGV[2]
	}
	else if ( ARGC == 3 ) {
		"date '+%d'" |getline nbday 
		close("getline")

		FREPORT=ARGV[1]
	}
	else {		
		print "Error with syntax"
		exit 1
	}

	ind_in=0
	ind_syn=0
	ind_out=0
}

$1 == nbday && NF == 25 && $7 ~ /^IPT/ {
	if($8 ~ /^INPUT/) {
		if ( ind_in != 0 ) ind_in++
		tin[ind_in]=$0
	}

	if($8 ~ /^syn/) {
		if ( ind_syn != 0 ) ind_syn++
		tsyn[ind_syn]=$0
	}

	if($8 ~ /^OUTPUT/) {
		if ( ind_out != 0 ) ind_out++
		tout[ind_out]=$0
	}
}

END {
	print "---------- Analysis of iptables.log ", tdate[1], tdate[2], tdate[3], tdate[4], tdate[5] ," -----------" > FREPORT

	print "-------------------------- INPUT REPORT -------------------------" > FREPORT
	for (i = 0 ; i <= ind_input ; i++)
	{
		split(tin[i],vtin," ")
		printf("%s %s ...\n", vtin[0], vtin[1])
	}

	print "-------------------------- NOT SYN REPORT -------------------------" > FREPORT
	for (j = 0 ; j <= ind_syn ; j++)
	{
		split(tsyn[i],vtsyn," ")
		printf("%s %s ...\n", vtsyn[0], vtsyn[1])
	}

	print "-------------------------- OUTPUT REPORT -------------------------" > FREPORT
	for (k = 0 ; k <= ind_out ; k++)
	{
		split(tout[i],vtout," ")
		printf("%s %s ...\n", vtout[0], vtout[1])
	}
	print "-------------------------- END of analysis -----------------------" > report
	close(FREPORT)

	exit 0
}
