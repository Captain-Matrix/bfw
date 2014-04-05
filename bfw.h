#ifndef bfw_h
#define bfw_h
#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define IPT_IN_ON "/usr/sbin/iptables -t nat  -A PREROUTING -p all -j NFQUEUE --queue-num 0"
#define IPT_IN_OFF "/usr/sbin/iptables -t nat    -D PREROUTING -p all -j NFQUEUE --queue-num 0"
#define IPT_OUT_ON "/usr/sbin/iptables -t nat    -A POSTROUTING  -p all -j NFQUEUE --queue-num 0"
#define IPT_OUT_OFF "/usr/sbin/iptables -t nat    -D POSTROUTING  -p all -j NFQUEUE --queue-num 0"


#define IPT_IN_RAW_ON "/usr/sbin/iptables -t raw  -A PREROUTING -p all -j NFQUEUE --queue-num 0"
#define IPT_IN_RAW_OFF "/usr/sbin/iptables -t raw    -D PREROUTING -p all -j NFQUEUE --queue-num 0"
#define IPT_OUT_RAW_ON "/usr/sbin/iptables -t raw    -A POSTROUTING  -p all -j NFQUEUE --queue-num 0"
#define IPT_OUT_RAW_OFF "/usr/sbin/iptables -t raw    -D POSTROUTING  -p all -j NFQUEUE --queue-num 0"


#define INGRESS 1
#define EGRESS 2
#define TCP 0X600
#define UDP 0x1100
#define OTHER 0XFFFF
#define LEARNING 0
#define ENFORCING 1
static unsigned char *raw_packet;
static struct nlif_handle *nlfh;
struct nfq_handle *h;
struct nfq_q_handle *qh;

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
void die (int code, char *msg);
void fw_log (meta_data M);
int check_rules (meta_data M);
#endif
