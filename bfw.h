#ifndef bfw_h
#define bfw_h
#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define IPT_IN_ON "/usr/sbin/iptables -A INPUT -p all -j NFQUEUE --queue-num 0"
#define IPT_IN_OFF "/usr/sbin/iptables   -D INPUT -p all -j NFQUEUE --queue-num 0"
#define IPT_OUT_ON "/usr/sbin/iptables   -A OUTPUT  -p all -j NFQUEUE --queue-num 0"
#define IPT_OUT_OFF "/usr/sbin/iptables   -D OUTPUT  -p all -j NFQUEUE --queue-num 0"
#define INGRESS 1
#define EGRESS 0
#define TCP 0X600
#define UDP 0x1100
static unsigned char *raw_packet;
static struct nlif_handle *nlfh;
static FILE *learn_log;
struct meta_data
{
  int size;			//packet size
  int direction;		//packet direction
  int layer4;			//Transport layer protocol
  time_t stamp;			//unix time stamp
  char interface[IFNAMSIZ];
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
};
typedef struct meta_data meta_data;
#endif
