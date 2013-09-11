#include "icmp_ping.h"

#pragma pack(4)

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

#define ICMP_MIN 8 // minimum 8 byte icmp packet (just header)

/* The IP header */
typedef struct iphdr {
         unsigned int h_len:4;           // length of the header
         unsigned int version:4;         // Version of IP
         unsigned char tos;              // Type of service
         unsigned short total_len;       // total length of the packet
         unsigned short ident;           // unique identifier
         unsigned short frag_and_flags; // flags
         unsigned char   ttl; 
         unsigned char proto;            // protocol (TCP, UDP etc)
         unsigned short checksum;        // IP checksum

         unsigned int sourceIP;
         unsigned int destIP;

}IpHeader;

//
// ICMP header
//
typedef struct _ihdr {
   BYTE i_type;
   BYTE i_code; /* type sub code */
   USHORT i_cksum;
   USHORT i_id;
   USHORT i_seq;
   /* This is not the std header, but we reserve space for time */
   ULONG timestamp;
}IcmpHeader;

#pragma pack()

#define STATUS_FAILED 0xFFFF
//#define DEF_PACKET_SIZE 32
#define MAX_PACKET 1024

#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define xfree(p)    HeapFree (GetProcessHeap(),0,(p))

#define ERRSTR_SIZE 12
char *pgerrstr[] = {
	"Ping成功",
	"Ping失败",
	"空指针",
	"WSAStartup失败",
	"无效Socket",
	"Socket错误",
	"无法解析目标主机",
	"堆分配错误",
	"超时",
	"不是ICMP的ECHO回复",
	"数据包错误",
	"发送失败"
};

void fill_icmp_data(char *, int);
USHORT checksum(USHORT *, int);
int decode_resp(char *,int ,struct sockaddr_in *);

void Usage(char *progname){
  
   fprintf(stderr,"Usage:\n");
   fprintf(stderr,"%s <host> [data_size]\n",progname);
   fprintf(stderr,"datasize can be up to 1Kb\n");
   ExitProcess(STATUS_FAILED);

}


//int ping(int argc, char **argv){
int ping(char *host, int pingcount/* = 4*/, int datasize/* = DEF_PACKET_SIZE*/){

	if(host == NULL){
		return NULL_POINTER;
	}

   WSADATA wsaData;
   SOCKET sockRaw;
   struct sockaddr_in dest,from;
   struct hostent * hp;
   int bread;
   int fromlen = sizeof(from);
   int timeout = 1000;
   char *dest_ip;
   char *icmp_data;
   char *recvbuf;
   unsigned int addr=0;
   USHORT seq_no = 0;

   if (WSAStartup(MAKEWORD(2,1),&wsaData) != 0){
         fprintf(stderr,"WSAStartup failed: %d\n",GetLastError());
         //ExitProcess(STATUS_FAILED);
		 return WSASTARTUP_ERR;
   }

#if 0
   //windows的WSASocket有时无法设置超时
   sockRaw = WSASocket(AF_INET,
                        SOCK_RAW,
                        IPPROTO_ICMP,
                        NULL, 0,0);

#else 
   sockRaw = socket(AF_INET,
                    SOCK_RAW,
                    IPPROTO_ICMP
                    );
#endif

   if (sockRaw == INVALID_SOCKET) {
         fprintf(stderr,"WSASocket() failed: %d\n",WSAGetLastError());
         //ExitProcess(STATUS_FAILED);
		 return INVALID_SOCK;
   }
   bread = setsockopt(sockRaw,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,
                                           sizeof(timeout));
   if(bread == SOCKET_ERROR) {
         fprintf(stderr,"failed to set recv timeout: %d\n",WSAGetLastError());
         //ExitProcess(STATUS_FAILED);
		 return SOCK_ERR;
   }
   timeout = 1000;
   bread = setsockopt(sockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,
                                           sizeof(timeout));
   if(bread == SOCKET_ERROR) {
         fprintf(stderr,"failed to set send timeout: %d\n",WSAGetLastError());
         //ExitProcess(STATUS_FAILED);
		 return SOCK_ERR;
   }
   memset(&dest,0,sizeof(dest));

   hp = gethostbyname(host);

   if (!hp){
         addr = inet_addr(host);
   }
   if ((!hp)   && (addr == INADDR_NONE) ) {
         fprintf(stderr,"Unable to resolve %s\n",host);
         //ExitProcess(STATUS_FAILED);
		 return UN_RESOLVE_HOST;
   }

   if (hp != NULL)
           memcpy(&(dest.sin_addr),hp->h_addr,hp->h_length);
   else
           dest.sin_addr.s_addr = addr;

   if (hp)
           dest.sin_family = hp->h_addrtype;
   else
           dest.sin_family = AF_INET;

   dest_ip = inet_ntoa(dest.sin_addr);
        
   datasize += sizeof(IcmpHeader);  

   icmp_data = (char*)xmalloc(MAX_PACKET);
   recvbuf = (char*)xmalloc(MAX_PACKET);

   if (!icmp_data) {
         fprintf(stderr,"HeapAlloc failed %d\n",GetLastError());
         //ExitProcess(STATUS_FAILED);
		 return HEAP_ALLOC_ERR;
   }  

   memset(icmp_data,0,MAX_PACKET);
   fill_icmp_data(icmp_data,datasize);

   int ping_ok = 0;
   int total = 0;
   int bwrote;
   int ret = 0;

   while(pingcount--) {
         
        
         ((IcmpHeader*)icmp_data)->i_cksum = 0;
         ((IcmpHeader*)icmp_data)->timestamp = GetTickCount();

         ((IcmpHeader*)icmp_data)->i_seq = seq_no++;
         ((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);

         bwrote = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,
                                         sizeof(dest));


         if (bwrote == SOCKET_ERROR){
           if (WSAGetLastError() == WSAETIMEDOUT) {
                 printf("timed out\n");
                 continue;
           }
           fprintf(stderr,"sendto failed: %d\n",WSAGetLastError());
           //ExitProcess(STATUS_FAILED);
		   return SEND_FAILED;
         }
         if (bwrote < datasize ) {
           fprintf(stdout,"Wrote %d bytes\n",bwrote);
         }
         bread = recvfrom(sockRaw,recvbuf,MAX_PACKET,0,(struct sockaddr*)&from,
                                  &fromlen);
		 

         if (bread == SOCKET_ERROR){
           if (WSAGetLastError() == WSAETIMEDOUT) {
                   printf("timed out\n");
                 continue;
           }
           fprintf(stderr,"recvfrom failed: %d\n",WSAGetLastError());
           //ExitProcess(STATUS_FAILED);
		   return TIME_OUT;
         }
         if((ret = decode_resp(recvbuf,bread,&from)) >= 0){
			 ping_ok++;
		 }
		 total++;

         Sleep(1000);
   }

   delete [] icmp_data;
   delete [] recvbuf;

   ping_ok = (int)((double)ping_ok / total * 100);
   if(ping_ok == 0) return ret;
   else return ping_ok;

}
/* 
         The response is an IP packet. We must decode the IP header to locate 
         the ICMP data 

		 return ms, if return < 0, some error 
*/
int decode_resp(char *buf, int bytes,struct sockaddr_in *from) {

          IpHeader *iphdr;
         IcmpHeader *icmphdr;
         unsigned short iphdrlen;

         iphdr = (IpHeader *)buf;

         iphdrlen = iphdr->h_len * 4 ; // number of 32-bit words *4 = bytes

         if (bytes   < iphdrlen + ICMP_MIN) {
                 printf("Too few bytes from %s\n",inet_ntoa(from->sin_addr));
         }

         icmphdr = (IcmpHeader*)(buf + iphdrlen);

         if (icmphdr->i_type != ICMP_ECHOREPLY) {
                 fprintf(stderr,"non-echo type %d recvd\n",icmphdr->i_type);
                 return NON_ECHO;
         }
         if (icmphdr->i_id != (USHORT)GetCurrentProcessId()) {
                 fprintf(stderr,"someone else's packet!\n");
                 return PACKET_ERR;
         }

         printf("%d bytes from %s:",bytes, inet_ntoa(from->sin_addr));
         printf(" icmp_seq = %d. ",icmphdr->i_seq);
         printf(" time: %d ms ",GetTickCount()-icmphdr->timestamp);
         printf("\n");
		 return GetTickCount()-icmphdr->timestamp;
                
}


USHORT checksum(USHORT *buffer, int size) {

   unsigned long cksum=0;

   while(size >1) {
         cksum+=*buffer++;
         size -=sizeof(USHORT);
   }
  
   if(size ) {
         cksum += *(UCHAR*)buffer;
   }

   cksum = (cksum >> 16) + (cksum & 0xffff);
   cksum += (cksum >>16);
   return (USHORT)(~cksum);
}
/* 
         Helper function to fill in various stuff in our ICMP request.
*/
void fill_icmp_data(char * icmp_data, int datasize){

   IcmpHeader *icmp_hdr;
   char *datapart;

   icmp_hdr = (IcmpHeader*)icmp_data;

   icmp_hdr->i_type = ICMP_ECHO;
   icmp_hdr->i_code = 0;
   icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
   icmp_hdr->i_cksum = 0;
   icmp_hdr->i_seq = 0;
  
   datapart = icmp_data + sizeof(IcmpHeader);
   //
   // Place some junk in the buffer.
   //
   memset(datapart,'E', datasize - sizeof(IcmpHeader));

}


char* get_ping_error_str(int errcode)
{
	if(errcode + ERR_CODE < ERRSTR_SIZE && errcode + ERR_CODE > 0){
		return pgerrstr[errcode + ERR_CODE];
	}

	return NULL;
}