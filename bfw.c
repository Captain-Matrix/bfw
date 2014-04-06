#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netinet/in.h>
#include <signal.h>
#include <linux/types.h>

#include <linux/netfilter.h>

#include <linux/ip.h>

#include <linux/tcp.h>

#include <linux/udp.h>
#include "bfw.h"
#include "utils.h"
#include "processlog.h"
#include "server.h"
#include "mongoose/mongoose.h"
static int debug = 0, rcount = -1, r_index = 0, mode = ENFORCING;
static rule *r;
static int
nf_callback (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	     struct nfq_data *nfa, void *data)
{
  int verdict = DENY, i, j = 0, id = 0, ifin = -1, ifout = -1, ifpin =
    -1, ifpout = -1, size = nfq_get_payload (nfa, &raw_packet);
  uint16_t sport, dport;
  char *upperlayers;
  struct nfqnl_msg_packet_hdr *ph;
  meta_data M;
  memset (&M, 0, sizeof (meta_data));
  ph = nfq_get_msg_packet_hdr (nfa);
  id = ntohl (ph->packet_id);
  if (ph)
    {
      if (debug)
	printf
	  ("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
      fflush (stdout);
      M.size = size;
      M.stamp = time (NULL);
      // printf("%d %d %d %d\n" ,nfq_get_physindev(nfa),nfq_get_physoutdev(nfa),nfq_get_indev(nfa),nfq_get_outdev(nfa));
      ifout = nfq_get_outdev (nfa);
      ifin = nfq_get_indev (nfa);
      ifpin = nfq_get_physindev (nfa);
      ifpout = nfq_get_physoutdev (nfa);
      M.ip_header = (struct iphdr *) raw_packet;
      M.layer4 = M.ip_header->protocol;
      if (ntohs (M.layer4) == TCP)
	{
	  M.tcp_header =
	    (struct tcphdr *) (raw_packet + (M.ip_header->ihl << 2));
	  upperlayers = (char *) M.tcp_header + (sizeof (struct tcphdr));
	  sport = ntohs (M.tcp_header->source);
	  dport = ntohs (M.tcp_header->dest);
	}
      else if (ntohs (M.layer4) == UDP)
	{
	  M.udp_header =
	    (struct udphdr *) (raw_packet + (M.ip_header->ihl << 2));
	  upperlayers = (char *) M.udp_header + (sizeof (struct udphdr));
	  sport = ntohs (M.udp_header->source);
	  dport = ntohs (M.udp_header->dest);
	}
      else
	{
	  upperlayers = (char *) raw_packet;
	}
      if (ph->hook == NF_INET_PRE_ROUTING)
	{
	  M.direction = INGRESS;
	  if (ifpin)
	    {
	      if (nfq_get_physindev_name (nlfh, nfa, (char *) &M.interface) ==
		  -1)
		perror ("Error fetching egress interface name: ");
	    }
	  else
	    {
	      if (nfq_get_indev_name (nlfh, nfa, (char *) &M.interface) == -1)
		perror ("Error fetching egress interface name: ");

	    }

	}
      else if (ph->hook == NF_INET_POST_ROUTING)
	{
	  M.direction = EGRESS;
	  if (ifpout)
	    {
	      if (nfq_get_physoutdev_name (nlfh, nfa, (char *) &M.interface)
		  == -1)
		perror ("Error fetching egress interface name: ");
	    }
	  else
	    {
	      if (nfq_get_outdev_name (nlfh, nfa, (char *) &M.interface) ==
		  -1)
		perror ("Error fetching egress interface name: ");

	    }
	}

      if (debug)
	{
	  for (i = 0, j = 0; i < M.size; i++, j++)
	    {
	      if (isprint (raw_packet[i]))
		printf ("%c", raw_packet[i]);
	      else
		printf (".");
	      if (j == 80)
		{
		  j = 0;
		  printf ("\n");
		}
	    }
	}

      ///////////////////meta_data parsed this is where the fw will make decisions on traffic///////////////////////////////
//        if(M.direction==INGRESS)printf("IN %s\n",M.interface);
//        if(M.direction==EGRESS)printf("OUT %s\n",M.interface);
//     //  printf("%s\n",M.interface);
      if (mode == LEARNING)
	fw_log (M);
      else if (mode == ENFORCING)
	{
	  verdict = check_rules (M);
	}

      //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    }
  switch (verdict)
    {
    case PERMIT:
      nfq_set_verdict (qh, id, NF_ACCEPT, size, raw_packet);
      break;
    case DENY:
      nfq_set_verdict (qh, id, NF_DROP, size, raw_packet);
      break;
    case LOG:
      fw_log (M);
      nfq_set_verdict (qh, id, NF_ACCEPT, size, raw_packet);
      break;
    default:
      nfq_set_verdict (qh, id, NF_DROP, size, raw_packet);
      break;
    }
  return 0;
}

int
check_rules (meta_data M)
{
  uint32_t s_ip = ntohl (M.ip_header->saddr), d_ip =
    ntohl (M.ip_header->daddr);
  uint16_t s_port = 0, d_port = 0;
  if (ntohs (M.layer4) == TCP)
    s_port = ntohs (M.tcp_header->source), d_port =
      ntohs (M.tcp_header->dest);
  else if (ntohs (M.layer4) == UDP)
    s_port = ntohs (M.udp_header->source), d_port =
      ntohs (M.udp_header->dest);

  for (r = rule_head.cqh_first, r_index = 0;
       r != (void *) &rule_head; r = r->entries.cqe_next, r_index++)
    {
      // printf("%s %s --> %s %s / %s ? %s\n",int_to_ip(r->src),int_to_ip(r->src_mask),int_to_ip(r->dest),int_to_ip(r->dest_mask),int_to_ip(d_ip));
      if (match (r->src, r->src_mask, s_ip)
	  && match (r->dest, r->dest_mask, d_ip))
	{
	  if (p_match (s_port, r->s_port, r->s_port_last)
	      && p_match (d_port, r->d_port, r->d_port_last))
	    {
	      r->hits++;
	      r->bw += M.size;
	      return r->action;	// in soviet russia you don't block programs ,programs block you!
	    }
	}

    }
  return DENY;			//default deny policy when enforcing rules
}

void
fw_log (meta_data M)
{				//binary logs,converting to text during packet processing would be too costly
  fwrite (&M.size, sizeof (M.size), 1, learn_log);
  fwrite (&M.direction, sizeof (M.direction), 1, learn_log);
  fwrite (&M.layer4, sizeof (M.layer4), 1, learn_log);
  fwrite (&M.stamp, sizeof (time_t), 1, learn_log);
  fwrite (&M.interface, sizeof (char), IFNAMSIZ, learn_log);
  fwrite (M.ip_header, sizeof (struct iphdr), 1, learn_log);
  if (ntohs (M.layer4) == TCP)
    fwrite (M.tcp_header, sizeof (struct tcphdr), 1, learn_log);
  else if (ntohs (M.layer4) == UDP)
    fwrite (M.udp_header, sizeof (struct udphdr), 1, learn_log);

}

int
start_fw ()
{
  struct nfnl_handle *nh;
  int fd, rv;
  char buf[4096];

  acl_load ("./test_rules");
  // summarize (NULL);
  if (!(learn_log = fopen ("./bfw_learn.log", "ab+")))
    {
      fprintf (stderr, "Error opening learning log file\n");
      iptables_off ();
      exit (1);
    }

  h = nfq_open ();
  if (h == NULL)
    {
      fprintf (stderr, "error during nfq_open()\n");
      return -1;
    }
  if (nfq_unbind_pf (h, AF_INET) < 0)
    {
      printf ("Error during nfq_unbind_pf()\n");
      return -1;
    }
  if (nfq_bind_pf (h, AF_INET) < 0)
    {
      printf ("Error during nfq_bind_pf()\n");
      perror ("err");
      return -1;
    }

  qh = nfq_create_queue (h, 0, &nf_callback, NULL);
  if (!qh)
    {
      fprintf (stderr, "error during nfq_create_queue()\n");
      perror ("err");
      return -1;
    }

  printf ("Started bfw...\n");
  if (nfq_set_mode (qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
      fprintf (stderr, "can't set packet_copy mode\n");
      return -1;

    }
  nh = nfq_nfnlh (h);
  fd = nfnl_fd (nh);
  nlfh = nlif_open ();
  if (nlfh == NULL)
    {
      perror ("nlif_open");
      exit (EXIT_FAILURE);
    }
  nlif_query (nlfh);

  while (1)
    {
      rv = recv (fd, buf, sizeof (buf), 0);
      if (rv > 0)
	{

	  nfq_handle_packet (h, buf, rv);
	}

    }



  die (0, "Normal exit.");

}

void
die (int code, char *msg)
{
  fprintf (stderr, "Exit with code 0x%x :%s\n\a", code, msg);

  iptables_off ();
  nfq_destroy_queue (qh);
  nfq_close (h);
  fclose (learn_log);
  exit (code);
}

void
CATCH_ALL (int signal)
{
  if (debug)
    printf
      ("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^SIGNAL(%d) CAUGHT^^^^^^^^^^^^^^^^^^^^^^^^\n",
       signal);
  fflush (stdout);
  switch (signal)
    {
    case SIGSEGV:
      die
	(11,
	 "Segmentation fault detected,please contact developer and/or maintainer to report a bug.");
      break;
    case SIGINT:
    case SIGTERM:
      iptables_off ();
      printf ("Exiting program normally...\n\a");
      exit (0);
      break;
    case SIGKILL:
      die (signal, "Program killed!!.");
      break;
    case SIGCHLD:
      if (debug)
	printf ("process terminated.\n");
      break;
    default:
      break;
    }

}


void
start_server ()
{
  pthread_t tid = (pthread_t) 999;
  pthread_create (&tid, 0, server, NULL);
  pthread_detach (tid);
}

int
main ()
{
  int i;
  if (getuid () != 0)
    {
      die (1, "This program needs to run as root to function properly.\r\n");

    }
  for (i; i < 32; i++)
    signal (i, CATCH_ALL);
  iptables_on ();
  start_server ();
  if (!start_fw ())
    die (0xDEAD, "Error during startup.");

}
