#!/bin/bash

PROGRAM=$0

usage()
{
	printf "\n$PROGRAM\n"
	printf "\nDESCRIPTION\n"
	printf "\tProgram used to configure hadafs server volume file. It will\n"
	printf "\tproduce server volume file for every server, and scp the file\n"
	printf "\tto each server in /etc/hadafs."
	printf "\nUSAGE:\n"
	printf "\t$PROGRAM NWK FID LID RSS [RSP] EXP LSP VOL\n"
	printf "\tNWK:\t first three fileds of network address, such as 20.0.2\n"
	printf "\tFID:\t first node id of hadafs server, such as 1\n"
	printf "\tLID:\t last node id of hadafs server, such as 50\n"
	printf "\tRSS:\t ip address of redis-server\n"
	printf "\tRSP:\t listen port of redis-server, default 6379\n"
	printf "\tEXP:\t export directory path of server\n"
	printf "\tLSP:\t listening port of server\n"
	printf "\tVOL:\t volume file name of server /etc/hadafs/\n"
	printf "\nEXAMPLE:\n"
	printf "\tIf you want to configure 50 nodes named from io050 to io100 with\n"
	printf "\tip address from 152.1.0.50 to 152.1.0.100 as server in hadafs, and\n"
	printf "\tyour hadafs redis-server address is 120.1.2.81(default port), \n"
	printf "\tdirectory /mnt/ssd/export1 exported on port 8999, volume file name\n"
	printf "\tis export1.vol, then configuring command should be\n"
	printf "\n\t\t$PROGRAM 152.1.0 50 100 120.1.12.81 /mnt/ssd/export1 8999 export1.vol\n\n"
	printf "\tNOte: if the above command finished with no errors, the origin file\n"
	printf "\t/etc/hadafs/export1.vol will be replaced.\n\n"
}

if [ $# -eq 7 ]
then
	NTW=$1
	FID=$2
	LID=$3
	RSS=$4
	RSP=6379
	EXP=$5
	LSP=$6
	VOL=$7
elif [ $# -eq 8 ]
then
	NTW=$1
	FID=$2
	LID=$3
	RSS=$4
	RSP=$5
	EXP=$6
	LSP=$7
	VOL=$8
else
	usage
	exit -1
fi

#create volume file for each server
for server in `seq $FID $LID`
do
	server_ipaddr="$NTW.$server"
	volumefile="$server.volume_file"
	> $volumefile
	
	# export directory brick xlator
	printf "volume brick\n" >> $volumefile
	printf "\ttype storage/posix\n" >> $volumefile
	printf "\toption directory $EXP\n" >> $volumefile
	printf "\tend-volume\n" >> $volumefile
	unfiy_children="brick";

	#sibing xlator
	for client in `seq $FID $LID`
	do
		if [ $client -eq $server ]
		then
			continue
		fi
		client_ipaddr="$NTW.$client"
		printf "\nvolume client${client}" >> $volumefile
		printf "\ttype protocol/client\n" >> $volumefile
		printf "\toption remote-host $client_ipaddr\n" >> $volumefile
		printf "\toption remote-port $LSP\n" >> $volumefile
		printf "\toption remote-subvolume unify\n" >> $volumefile
		printf "\tend-volume\n\n" >> $volumefile
		unfiy_children="$unfiy_children client${client}";
	done	
	
	#unfiy xlator
	printf "\nvolume unify\n" >> $volumefile
	printf "\ttype cluster/unify\n" >> $volumefile
	printf "\tsubvolumes $unify_children\n" >> $volumefile
	printf "\tend-volume\n" >> $volumefile

	#server xlator	
	printf "\nvolume server\n" >> $volumefile
	printf "\ttype protocol/server\n" >> $volumefile
	printf "\toption name-server $RSS\n" >> $volumefile
	printf "\toption rs-port $RSP\n" >> $volumefile
	printf "\toption local-address $server_ipaddr\n" >> $volumefile
	printf "\toption transport-type ib-verbs\n" >> $volumefile
	printf "\toption transport.ib-verbs.listen-port $LSP\n" >> $volumefile
	printf "\tsubvolumes unify\n" >> $volumefile
	printf "\toption auth.addr.unify.allow *\n" >> $volumefile
	printf "\tend-volume\n" >> $volumefile

	#scp volume to remote host
	scp $volume $server_ipaddr:/etc/hadafs/$VOL
	if [ $? -ne 0 ]
	then
		printf "scp $volume to $server_ipaddr failed\n"
	else
		printf "scp $volume to $server_ipaddr ok\n"
	fi
done
