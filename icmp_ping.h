//#pragma once

#ifndef ICMP_PING_H
#define ICMP_PING_H

#define DEF_PACKET_SIZE 32

//datasize can be up to 1Kb
//return percentage*100 of OK, if < 0, some error or not OK  
int ping(char *host, int pingcount = 4, int datasize = DEF_PACKET_SIZE);
char* get_ping_error_str(int errcode);

#define ERR_CODE 100
// Error codes
enum PING_ERR{
	PING_OK = -ERR_CODE,
	PING_FAILED,
	NULL_POINTER,
	WSASTARTUP_ERR,
	INVALID_SOCK,
	SOCK_ERR,
	UN_RESOLVE_HOST,
	HEAP_ALLOC_ERR,
	TIME_OUT,
	NON_ECHO,
	PACKET_ERR,
	SEND_FAILED,
};


#endif
