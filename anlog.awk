#!/usr/bin/awk

########################################################################
# anlog.awk is a awk script to analysis the iptables log. It shape the #
# logs into three fields : WARNING, INPUT and NEW NOT SYN. Each field  #
# match with the target of iptables rules. So, be carefull of changes  #
# that you do in the ipt_rules script.                                 #
#                                                                      #
# It creates the output file in the directory /usr/local/iptreport     #
#                                                                      #
# contact : ride_online@hotmail.fr                                     #
########################################################################

function shape_udp(ind,tab_udp) {
	for (i = 1 ; i <= ind ; i++)
	{
		in_int=substr(tab_udp[i],index(tab_udp[i],"IN="),8)
		src_addr=substr(tab_udp[i],index(tab_udp[i],"SRC="),20)
		dst_addr=substr(tab_udp[i],index(tab_udp[i],"DST="),20)
		tos=substr(tab_udp[i],index(tab_udp[i],"TOS="),8)
		ttl=substr(tab_udp[i],index(tab_udp[i],"TTL="),7)
		spt=substr(tab_udp[i],index(tab_udp[i],"SPT="),9)
		dpt=substr(tab_udp[i],index(tab_udp[i],"DPT="),9)

		split(in_int,tin," ")
		split(src_addr,tsrc," ")
		split(dst_addr,tdst," ")
		split(tos,ttos," ")
		split(ttl,tttl," ")
		split(spt,tspt," ")
		split(dpt,tdpt," ")

		split(tab_udp[i],vtab_udp," ")

		printf("%s %s %s  : %s %s %s %s %s %s %s\n", vtab_udp[1],\
						vtab_udp[2],vtab_udp[3],tin[1],tsrc[1],tdst[1] \
						,ttos[1],tttl[1],tspt[1],tdpt[1]) > FREPORT
	}
}

function shape_tcp(ind,tab_tcp) {
	for (i = 1 ; i <= ind ; i++)
	{
		in_int=substr(tab_tcp[i],index(tab_tcp[i],"IN="),8)
		src_addr=substr(tab_tcp[i],index(tab_tcp[i],"SRC="),20)
		dst_addr=substr(tab_tcp[i],index(tab_tcp[i],"DST="),20)
		tos=substr(tab_tcp[i],index(tab_tcp[i],"TOS="),8)
		ttl=substr(tab_tcp[i],index(tab_tcp[i],"TTL="),7)
		spt=substr(tab_tcp[i],index(tab_tcp[i],"SPT="),9)
		dpt=substr(tab_tcp[i],index(tab_tcp[i],"DPT="),9)

		split(in_int,tin," ")
		split(src_addr,tsrc," ")
		split(dst_addr,tdst," ")
		split(tos,ttos," ")
		split(ttl,tttl," ")
		split(spt,tspt," ")
		split(dpt,tdpt," ")

		split(tab_tcp[i],vtab_tcp," ")
		
		j=1
		tcp_flag=""

		while(vtab_tcp[j]) {
			if(vtab_tcp[j] ~ /SYN|RST|ACK|FIN|URG|PSH/) {
				flag=vtab_tcp[j]
				tcp_flag=tcp_flag flag
			}

			j++
		}

		printf("%s %s %s  : %s %s %s %s %s %s %s FLAG : %s \n", vtab_tcp[1],\
						vtab_tcp[2], vtab_tcp[3],tin[1],tsrc[1],\
						tdst[1],ttos[1],tttl[1],tspt[1],tdpt[1],\
						tcp_flag) > FREPORT
	}
}

function shape_icmp(ind,tab_icmp) {
	for (i = 1 ; i <= ind ; i++)
	{
		in_int=substr(tab_icmp[i],index(tab_icmp[i],"IN="),8)
		src_addr=substr(tab_icmp[i],index(tab_icmp[i],"SRC="),20)
		dst_addr=substr(tab_icmp[i],index(tab_icmp[i],"DST="),20)
		tos=substr(tab_icmp[i],index(tab_icmp[i],"TOS="),8)
		ttl=substr(tab_icmp[i],index(tab_icmp[i],"TTL="),7)
		type=substr(tab_icmp[i],index(tab_icmp[i],"TYPE="),7)
		code=substr(tab_icmp[i],index(tab_icmp[i],"CODE="),7)

		split(in_int,tin," ")
		split(src_addr,tsrc," ")
		split(dst_addr,tdst," ")
		split(tos,ttos," ")
		split(ttl,tttl," ")
		split(type,ttype," ")
		split(code,tcode," ")
	
		split(tab_icmp[i],vtab_icmp," ")

		printf("%s %s %s  : %s %s %s %s %s %s %s\n", vtab_icmp[1],\
						vtab_icmp[2], vtab_icmp[3],\
						tin[1],tsrc[1],tdst[1],ttos[1],\
						tttl[1],ttype[1],tcode[1])	> FREPORT
	}
}

function shape_other(ind,tab) {
	for (i = 1 ; i <= ind ; i++)
	{
		in_int=substr(tab[i],index(tab[i],"IN="),8)
		src_addr=substr(tab[i],index(tab[i],"SRC="),20)
		dst_addr=substr(tab[i],index(tab[i],"DST="),20)
		tos=substr(tab[i],index(tab[i],"TOS="),8)
		ttl=substr(tab[i],index(tab[i],"TTL="),7)
		proto=substr(tab[i],index(tab[i],"PROTO="),9)

		split(in_int,tin," ")
		split(src_addr,tsrc," ")
		split(dst_addr,tdst," ")
		split(tos,ttos," ")
		split(ttl,tttl," ")
		split(proto,tproto," ")

		split(tab[i],vtab," ")

		printf("%s %s %s  : %s %s %s %s %s %s \n", vtab[1],\
						vtab[2], vtab[3],\
						tin[1],tsrc[1],tdst[1],\
						ttos[1],tttl[1],tproto[1]) > FREPORT
	}

}

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
	ind_in_icmp=0
	ind_warn=0
	ind_warn_tcp=0
	ind_warn_udp=0
	ind_warn_icmp=0
	ind_syn=0
	ind_syn_tcp=0
	ind_syn_udp=0
	ind_syn_icmp=0

}

# We get back the lines writed by iptables and fill the arrays
$2 == nbday && index($0,"IPT") {

	if(index($0,"INPUT")) {
		if(index($0,"UDP")) {
			ind_in_udp++
			tin_udp[ind_in_udp]=$0
		}
		else if(index($0,"TCP")) {
			ind_in_tcp++
			tin_tcp[ind_in_tcp]=$0
		}
		else if(index($0,"ICMP")) {
			ind_in_icmp++
			tin_icmp[ind_in_icmp]=$0
		}
		else {
			ind_in++
			tin[ind_in]=$0
		}
	}

	if(index($0,"New")) {
		if(index($0,"UDP")) {
			ind_syn_udp++
			tsyn_udp[ind_syn_udp]=$0
		}
		else if(index($0,"TCP")) {
			ind_syn_tcp++
			tsyn_tcp[ind_syn_tcp]=$0
		}
		else if(index($0,"ICMP")) {
			ind_syn_icmp++
			tsyn_icmp[ind_syn_icmp]=$0
		}
		else {
			ind_syn++
			tsyn[ind_syn]=$0
		}
	}

	if(index($0,"Warn")) {
		if(index($0,"UDP")) {
			ind_warn_udp++
			twarn_udp[ind_warn_udp]=$0
		}
		else if(index($0,"TCP")) {
			ind_warn_tcp++
			twarn_tcp[ind_warn_tcp]=$0
		}
		else if(index($0,"ICMP")) {
			ind_warn_icmp++
			twarn_icmp[ind_warn_icmp]=$0
		}
		else {
			ind_warn++
			twarn[ind_warn]=$0
		}
	}
}

# END : we shape the data collected
END {
print "+-------------------------------------------------------------+" > FREPORT
print "|                Analysis of iptables.log                     |" > FREPORT
print "+-------------------------------------------------------------+" > FREPORT
printf("\n---------------------- WARNING REPORT -------------------------\n\n") > FREPORT

print "TCP packets :	", ind_warn_tcp," packets" > FREPORT
print "UDP packets :	", ind_warn_udp," packets" > FREPORT
print "ICMP packets :	", ind_warn_icmp," packets" > FREPORT
print "Other packets :	", ind_warn," packets" > FREPORT

printf("\nTCP packets :\n\n") > FREPORT

shape_tcp(ind_warn_tcp,twarn_tcp)

printf("\nUDP packets :\n\n") > FREPORT

shape_udp(ind_warn_udp,twarn_udp)

printf("\nICMP packets :\n\n") > FREPORT

shape_icmp(ind_warn_icmp,twarn_icmp)

printf("\nOther packets :\n\n") > FREPORT

shape_other(ind_warn,twarn)

printf("\n----------------------- INPUT REPORT ---------------------------\n\n") > FREPORT

print "TCP packets :	", ind_in_tcp," packets" > FREPORT
print "UDP packets :	", ind_in_udp," packets" > FREPORT
print "ICMP packets :	", ind_in_icmp," packets" > FREPORT
print "Other packets :	", ind_in," packets" > FREPORT
print("\nTCP packets :\n\n") > FREPORT

shape_tcp(ind_in_tcp,tin_tcp)

printf("\nUDP packets :\n\n") > FREPORT

shape_udp(ind_in_udp,tin_udp)

printf("\nICMP packets :\n\n") > FREPORT

shape_icmp(ind_in_icmp,tin_icmp)

printf("\nOther packets :\n\n") > FREPORT

shape_other(ind_in,tin)

printf("\n--------------------- NEW NOT SYN REPORT -----------------------\n\n") > FREPORT

print "TCP packets :	", ind_syn_tcp," packets" > FREPORT
print "UDP packets :	", ind_syn_udp," packets" > FREPORT
print "ICMP packets :	", ind_syn_icmp," packets" > FREPORT
print "Other packets :	",ind_syn," packets" > FREPORT

printf("\nTCP packets :\n\n") > FREPORT

shape_tcp(ind_syn_tcp,tsyn_tcp)

printf("\nUDP packets :\n\n") > FREPORT

shape_udp(ind_syn_udp,tsyn_udp)

printf("\nICMP packets :\n\n") > FREPORT

shape_icmp(ind_syn_icmp,tsyn_icmp)

printf("\nOther packets :\n\n") > FREPORT

shape_other(ind_syn,tsyn)

printf("\n------------------- END of analysis ----------------------") > FREPORT 
close(FREPORT)

exit 0
}
