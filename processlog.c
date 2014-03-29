#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "bfw.h"
#include "utils.h"



int
main ()
{
  meta_data M;
  int sport, dport;
  if ((learn_log = fopen ("./bfw_learn.log", "rb")) == -1)
    {
      fprintf (stderr, "Error opening learning log");
      exit (1);
    }
  M.ip_header = malloc (sizeof (struct iphdr));
  M.tcp_header = malloc (sizeof (struct tcphdr));
  M.udp_header = malloc (sizeof (struct udphdr));
  while (!feof (learn_log))
    {
      memset (M.ip_header, 0, sizeof (struct iphdr));
      memset (M.tcp_header, 0, sizeof (struct tcphdr));
      memset (M.udp_header, 0, sizeof (struct udphdr));
      fread (&M.size, sizeof (M.size), 1, learn_log);
      fread (&M.direction, sizeof (M.direction), 1, learn_log);
      fread (&M.layer4, sizeof (M.layer4), 1, learn_log);
      fread (&M.stamp, sizeof (time_t), 1, learn_log);
      fread (&M.interface, sizeof (char), IFNAMSIZ, learn_log);
      fread (M.ip_header, sizeof (struct iphdr), 1, learn_log);
      if (M.layer4 == TCP)
	{
	  fread (M.tcp_header, sizeof (struct tcphdr), 1, learn_log);
	  sport = M.tcp_header->source;
	  dport = M.tcp_header->dest;
	}
      else if (M.layer4 == UDP)
	{
	  fread (M.udp_header, sizeof (struct udphdr), 1, learn_log);
	  sport = ntohs (M.udp_header->source);
	  dport = ntohs (M.udp_header->dest);
	}
      /////////////////////////////////////////////////////////////////
      if (M.direction == EGRESS)
	{			//egress    

	  printf ("\t\t%s \t\tEGRESS: %s\tL4:%0x\n%s:%d ---> %s:%d\n\n",
		  ctime (&M.stamp), M.interface, ntohs (M.layer4),
		  int_to_ip (ntohl (M.ip_header->saddr)), sport,
		  int_to_ip (ntohl (M.ip_header->daddr)), dport);



	}
      if (M.direction == INGRESS)
	{			//ingress


	  printf ("\t\t%s \t\tINGRESS: %s\tL4:%0x\n%s:%d ---> %s:%d\n\n",
		  ctime (&M.stamp), M.interface, ntohs (M.layer4),
		  int_to_ip (ntohl (M.ip_header->saddr)), sport,
		  int_to_ip (ntohl (M.ip_header->daddr)), dport);

	}
    }

  return 0;
}
