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

int debug = 0;
static int
nf_callback (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	     struct nfq_data *nfa, void *data)
{
  int i, j = 0, id = 0, ifin, ifout, size =
    nfq_get_payload (nfa, &raw_packet);
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
	  ("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");fflush(stdout);
      M.size = size;
      M.stamp = time (NULL);
      ifout = nfq_get_outdev (nfa);
      ifin = nfq_get_indev (nfa);
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

      if (ifout > 0)
	{			//egress
	  M.direction = EGRESS;
	  if (nfq_get_outdev_name (nlfh, nfa, (char *) &M.interface) == -1)
	    {
	      perror ("Error fetching egress interface name: ");
	    }
	  else
	    {
	      if (debug)
		{
		  printf
		    ("\t\t%s \t\tEGRESS: %s\tL4:%0x\n%s:%d ---> %s:%d\n\n",
		     ctime (&M.stamp), M.interface, ntohs (M.layer4),
		     int_to_ip (ntohl (M.ip_header->saddr)), sport,
		     int_to_ip (ntohl (M.ip_header->daddr)), dport);fflush(stdout);
		}
	    }


	}
      else if (ifin > 0)
	{			//ingress
	  M.direction = INGRESS;
	  if (nfq_get_indev_name (nlfh, nfa, (char *) &M.interface) == -1)
	    {
	      perror ("Error fetching ingress interface name: ");
	    }
	  else
	    {
	      if (debug)
		{
		  printf
		    ("\t\t%s \t\tINGRESS: %s\tL4:%0x\n%s:%d ---> %s:%d\n\n",
		     ctime (&M.stamp), M.interface, ntohs (M.layer4),
		     int_to_ip (ntohl (M.ip_header->saddr)), sport,
		     int_to_ip (ntohl (M.ip_header->daddr)), dport);fflush(stdout);
		}
	    }
	}
//       if (debug)
// 	{
// 	  for (i = 0, j = 0; i < M.size; i++, j++)
// 	    {
// 	      if (isprint (raw_packet[i]))
// 		printf ("%c", raw_packet[i]);
// 	      else
// 		printf (".");
// 	      if (j == 80)
// 		{
// 		  j = 0;
// 		  printf ("\n");
// 		}
// 	    }
// 	}
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
  nfq_set_verdict (qh, id, NF_ACCEPT, size, raw_packet);
}

int
start_fw ()
{
  struct nfnl_handle *nh;
  int fd, rv;
  char buf[4096];

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


  
 die(0,"Normal exit.");

}
void die(int code,char *msg){
    fprintf(stderr,"Exit with code 0x%x :%s\n\a",code,msg);

  iptables_off();
   nfq_destroy_queue (qh);
  nfq_close (h);
  fclose(learn_log);
  exit(code);
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
	(11,"Segmentation fault detected,please contact developer and/or maintainer to report a bug.");
         break;
    case SIGINT:
    case SIGTERM:
      iptables_off ();
      printf ("Exiting program normally...\n\a");
      exit (0);
      break;
    case SIGKILL:
      die(signal,"Program killed!!.");
      break;
    case SIGCHLD:
     if(debug) printf ("process terminated.\n");
      break;
    default:
      break;
    }

}

int
main ()
{
  int i;
  if (getuid () != 0)
    {
      die(1,"This program needs to run as root to function properly.\r\n");
      
    }
  for (i; i < 32; i++)
    signal (i, CATCH_ALL);
  iptables_on ();
  if(!start_fw ())die(0xDEAD,"Error during startup.");
  
}
