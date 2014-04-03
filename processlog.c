#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/types.h>
#include <string.h>
#include "bfw.h"
#include "utils.h"
#include "processlog.h"
int debug = 0, rcount = -1, r_index = 0;
rule *r;
void
usage ()
{
  printf
    ("\n-----------------------------------------------------------------------\n"
     "|			  Press:					      |\n"
     "|			  space key to scroll through rules                   |\n"
     "|			  ? to display this guide again			      |\n"
     "|			  ! to delete a rule  				      |\n"
     "|			  # to add a rule                                     |\n"
     "|			  $ to edit a rule                                    |\n"
     "|			  W to write rules to a file                          |\n"
     "|			  R to read text acl rules from a file                |\n"
     "|			  P to (re)process binary log                         |\n"
     "|			  q to quit program                                   |\n"
     "-------------------------------------------------------------------------\n");
  printf (PROMPT);

  fflush (stdout);
}


int
more (int index)
{
  if (index > rcount)
    {
      // r_index = 0;
      index = 0;
      r = CIRCLEQ_FIRST (&rule_head);
    }
  int rows = r_index + ROWS;


  cls ();
  char l4[10];
  char l3[10];
  char Dow[10], hour[10], minute[10];
  char time[10];
  struct tm *T;

  printf
    ("%3s %6s  %s  %15s %17s %15s %15s %3s %5s %5s %4s %8s %4s %5s  %7s\n",
     "#", "ACTION", "L3", "SOURCE", "ACL MASK", "DEST", "ACL MASK", "L4",
     "SRC", "DEST", "BW", "DOW", "TIME", "IF", "DIRECTON");
  for (r = rule_head.cqh_first, r_index = 0;
       r_index < rows && r != (void *) &rule_head;
       r = r->entries.cqe_next, r_index++)
    {
      switch (r->L3)
	{
	case 4:
	  snprintf (l3, 10, "IPv4");
	  break;
	case 6:
	  snprintf (l3, 10, "IPv6");
	  break;
	default:
	  snprintf (l3, 10, "OTHER");
	  break;
	}
      switch (r->L4)
	{
	case TCP:
	  snprintf (l4, 10, "TCP");
	  break;
	case UDP:
	  snprintf (l4, 10, "UDP");
	  break;
	default:
	  snprintf (l4, 10, "OTHER");
	  break;

	}

      if (r->dow == -1)
	snprintf (Dow, 10, "ANY");
      else
	snprintf (Dow, 10, "%s", days[r->dow]);
      if (r->hour == -1)
	snprintf (hour, 10, "*");
      else
	snprintf (hour, 10, "%d", r->hour);
      if (r->minute == -1)
	snprintf (minute, 10, "*");
      else
	snprintf (minute, 10, "%d", r->minute);
      fprintf
	(stdout, "%3d"
	 " %6s  %s  %15s %15s %15s"
	 " %15s %3s %5d %5d %4d %8s %2s:%2s "
	 "%5s  %7s\n",
	 r->number, r->action ? "PERMIT" : "DENY", l3, int_to_ip (r->src),
	 int_to_ip (r->src_mask), int_to_ip (r->dest),
	 int_to_ip (r->dest_mask), l4, r->s_port, r->d_port, 0,
	 Dow, hour, minute, r->IF, r->direction ? "INGRESS" : "EGRESS");
      //r = CIRCLEQ_NEXT (r, entries);

    }
  if (r_index >= rcount)
    {
      r_index = 0;
    }
  printf (PROMPT);
}

int
write_rules (char *path)
{
  rule *rtmp = CIRCLEQ_FIRST (&rule_head);
  int i = 0;
  FILE *f = fopen (path, "aw");
  char l4[10];
  char l3[10];
  char Dow[10], hour[10], minute[10];
  char time[10];
  struct tm *T;

  if (!f)
    return 1;
  for (i; i < rcount; i++)
    {
      switch (rtmp->L3)
	{
	case 4:
	  snprintf (l3, 10, "IPv4");
	  break;
	case 6:
	  snprintf (l3, 10, "IPv6");
	  break;
	default:
	  snprintf (l3, 10, "OTHER");
	  break;
	}
      switch (rtmp->L4)
	{
	case TCP:
	  snprintf (l4, 10, "TCP");
	  break;
	case UDP:
	  snprintf (l4, 10, "UDP");
	  break;
	default:
	  snprintf (l4, 10, "OTHER");
	  break;

	}
      if (rtmp->dow == -1)
	snprintf (Dow, 10, "ANY");
      else
	snprintf (Dow, 10, "%s", days[rtmp->dow]);
      if (rtmp->hour == -1)
	snprintf (hour, 10, "*");
      else
	snprintf (hour, 10, "%d", rtmp->hour);
      if (rtmp->minute == -1)
	snprintf (minute, 10, "*");
      else
	snprintf (minute, 10, "%d", rtmp->minute);
      fprintf
	(f, "%3d"
	 " %6s  %s  %15s %15s %15s"
	 " %15s %3s %5d %5d %4d %8s %2s:%2s "
	 "%5s  %7s\n",
	 rtmp->number, rtmp->action ? "PERMIT" : "DENY", l3,
	 int_to_ip (rtmp->src), int_to_ip (rtmp->src_mask),
	 int_to_ip (rtmp->dest), int_to_ip (rtmp->dest_mask), l4,
	 rtmp->s_port, rtmp->d_port, 0, Dow, hour, minute, rtmp->IF,
	 rtmp->direction ? "INGRESS" : "EGRESS");
      rtmp = CIRCLEQ_NEXT (rtmp, entries);

    }
  return 0;
}

void
summarize (rule * rarg)
{
  int i = 0;
  float avgm, hundred = 100, f_index = 0;
  struct tm *T1, *T2;

  rule *rtmp, *rtmp2, *rtmp3;
//   if (rarg == NULL)
  rtmp = CIRCLEQ_FIRST (&rule_head);
//   else
//     rtmp = rarg;
  printf ("Summarizing rules.... %d\n", rtmp->action);
  avgm = hundred / rcount;
  for (r_index, f_index; r_index < rcount; f_index++, r_index++)
    {

      rtmp2 = CIRCLEQ_NEXT (rtmp, entries);

      for (i = r_index; i < rcount; i++)
	{

	  if (rtmp->action ==
	      rtmp2->action &&
	      rtmp->L3 == rtmp2->L3 &&
	      match (rtmp->src, rtmp->src_mask, rtmp2->src)
	      && match (rtmp->dest, rtmp->dest_mask, rtmp2->dest)
	      && rtmp->L4 == rtmp2->L4 && rtmp->d_port == rtmp2->d_port
	      //  && rtmp2->s_port== rtmp->s_port
	      // && rtmp2->s_port_last <= rtmp->s_port_last
	      && rtmp->direction == rtmp2->direction
	      && rtmp->hour == rtmp2->hour
	      && strncmp (rtmp->IF, rtmp2->IF, IFNAMSIZ) == 0)
	    {


	      CIRCLEQ_REMOVE (&rule_head, rtmp2, entries);
	      rtmp3 = CIRCLEQ_NEXT (rtmp2, entries);

	      free (rtmp2);
	      rtmp2 = rtmp3;
	      printf ("\r%.2f%% Done [%5d/%5d]", f_index * avgm, r_index,
		      rcount);

	      --rcount;
	      avgm = hundred / rcount;

	    }
	  else
	    {
	      rtmp2 = CIRCLEQ_NEXT (rtmp2, entries);
	      //T2=localtime (&rtmp2->stamp);
	    }
	}
      rtmp = CIRCLEQ_NEXT (rtmp, entries);
    }
  rtmp = CIRCLEQ_FIRST (&rule_head);
  for (i = 0; i < rcount; i++)
    {
      rtmp->number = i;
      rtmp = CIRCLEQ_NEXT (rtmp, entries);
    }
  r = CIRCLEQ_FIRST (&rule_head);
}

void
empty ()
{
  rule *r1, *r2;
  //r = CIRCLEQ_FIRST (&rule_head);
  while (rcount > 0 && rule_head.cqh_first != (void *) &rule_head)
    {
      CIRCLEQ_REMOVE (&rule_head, rule_head.cqh_first, entries);
      --rcount;
    }
  printf ("Emptied rule FIFO[%d]\n", rcount);

}

void
prompt ()
{
  char c, buf[256];
  r = CIRCLEQ_FIRST (&rule_head);
  usage ();
  while (c = gettc ())
    {
      switch (c)
	{
	case 'q':
	case 'Q':
	  return;
	  break;
	case '?':
	  usage ();
	  break;
	case ' ':
	  more (r_index);
	  break;
	case 'w':
	case 'W':
	  printf
	    ("\n%s\n Please enter the file path to write the rules to:\n",
	     PROMPT);
	  readin (256, &buf[0]);
	  if (write_rules (buf))
	    printf ("Encountered error while writing logs to file\n");
	  else
	    printf ("Successfully wrote %d rules to %s\n", rcount, buf);
	  usage ();
	  break;
	case 'r':
	case 'R':
	  printf
	    ("\n%s\n Please enter the file path where the desired rules/acls are located:\n",
	     PROMPT);
	  readin (256, &buf[0]);
	  acl_load (buf);
	  summarize (NULL);
	  usage ();
	  break;
	case 'p':
	case 'P':
	  printf
	    ("\n%s\n Please specify the path for the binary log file generated by bfw:\n",
	     PROMPT);
	  readin (256, &buf[0]);
	  load (buf);
	  usage ();
	  break;
	default:
	  break;
	}

    }

}

void
load (char *path)
{
  meta_data M;
  if (rcount > 0 && !CIRCLEQ_EMPTY (&rule_head))
    empty ();

  CIRCLEQ_INIT (&rule_head);
  memset (&M, 0, sizeof (meta_data));
  int sport, dport, i;
  struct tm *T;
  if (!(learn_log = fopen (path, "rb")))
    {
      fprintf (stderr, "Error opening learning log");
      return;
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
      if (ntohs (M.layer4) == TCP)
	{
	  fread (M.tcp_header, sizeof (struct tcphdr), 1, learn_log);
	  sport = ntohs (M.tcp_header->source);
	  dport = ntohs (M.tcp_header->dest);
	}
      else if (ntohs (M.layer4) == UDP)
	{
	  fread (M.udp_header, sizeof (struct udphdr), 1, learn_log);
	  sport = ntohs (M.udp_header->source);
	  dport = ntohs (M.udp_header->dest);
	}
      /////////////////////////////////////////////////////////////////
      r = malloc (sizeof (rule));
      memset (r, 0, sizeof (rule));
      ++rcount;

      r->direction = M.direction;
      memcpy (r->IF, M.interface, IFNAMSIZ);
      r->IF[IFNAMSIZ] = '\0';
      T = localtime (&M.stamp);
      r->minute = T->tm_min;
      r->hour = T->tm_hour;
      r->dow = T->tm_wday;
      r->s_port = sport;
      r->d_port = dport;
      r->L4 = ntohs (M.layer4);
      r->src_mask = HOST;
      r->dest_mask = HOST;
      r->src = ntohl (M.ip_header->saddr);
      r->dest = ntohl (M.ip_header->daddr);
      r->L3 = M.ip_header->version;
      r->action = PERMIT;
      r->number = rcount;
      CIRCLEQ_INSERT_TAIL (&rule_head, r, entries);

      /////////////////////////////////////////////////////////////////


      if (debug)
	{
	  printf
	    ("_____________________________________________________________\n");
	  if (M.direction == EGRESS)
	    {			//egress    

	      printf ("\t\t%s \t\tEGRESS: %s\tL4:%0x\n\t%s:%d ---> %s:%d\n",
		      ctime (&M.stamp), M.interface, ntohs (M.layer4),
		      int_to_ip (ntohl (M.ip_header->saddr)), sport,
		      int_to_ip (ntohl (M.ip_header->daddr)), dport);



	    }
	  if (M.direction == INGRESS)
	    {			//ingress


	      printf ("\t\t%s \t\tINGRESS: %s\tL4:%0x\n\t%s:%d ---> %s:%d\n",
		      ctime (&M.stamp), M.interface, ntohs (M.layer4),
		      int_to_ip (ntohl (M.ip_header->saddr)), sport,
		      int_to_ip (ntohl (M.ip_header->daddr)), dport);

	    }
	}
    }

}

void
acl_load (char *path)
{
  if (!CIRCLEQ_EMPTY (&rule_head))
    empty ();
  CIRCLEQ_INIT (&rule_head);
  rcount = 0;
  FILE *f = fopen (path, "r");
  char line[1024];
  char buf[20], *t, *s = " ";
  struct sockaddr_in sa;
  int i, j, invalid = 0;
  if (!f)
    {
      fprintf (stderr, "Unable to open rule file at %s\n", path);
      return;
    }

  while (!feof (f))
    {
      fgets (line, 1024, f);
      if (line[strlen (line) - 1] == '\n')
	line[strlen (line) - 1] = '\0';
      t = strtok (line, s);
      r = malloc (sizeof (rule));

      for (i = 0; i < 15 && t != NULL; i++)
	{
	  switch (i)
	    {
	    case 0:
	      r->number = rcount;	//yeah,I know-I don't care what number you put it in your rule file,it will process it in the order it reads it.
	      break;
	    case 1:
	      toLower (t);
	      if (strncmp ("permit", t, 6) == 0)
		r->action = PERMIT;
	      else if (strncmp (t, "deny", 4) == 0)
		r->action = DENY;
	      else if (strncmp (t, "log", 3) == 0)
		r->action = LOG;
	      break;
	    case 2:
	      toLower (t);
	      if (strncmp (t, "ipv4", 4) == 0)
		r->L3 = 4;
	      break;
	    case 3:		//source ip
	      //only ipv4 supported atm

	      if (inet_pton (AF_INET, t, &(r->src)) < 1)
		{
		  invalid = 1;
		  printf ("failed ip conversion [%s]\n", t);
		  goto endloop;	//temporary solution

		}
	      r->src = ntohl (r->src);
	      break;
	    case 4:		//source ip mask
	      if (inet_pton (AF_INET, t, (void *) &r->src_mask) < 1)
		{
		  invalid = 1;
		  goto endloop;	//temporary solution

		}
	      r->src_mask = ntohl (r->src_mask);
	      break;
	    case 5:		//destination ip
	      if (inet_pton (AF_INET, t, (void *) &r->dest) < 1)
		{
		  invalid = 1;
		  goto endloop;	//temporary solution

		}
	      r->dest = ntohl (r->dest);
	      break;
	    case 6:		//destination ip mask

	      if (inet_pton (AF_INET, t, (void *) &r->dest_mask) < 1)
		{
		  invalid = 1;
		  goto endloop;	//temporary solution

		}
	      r->dest_mask = ntohl (r->dest_mask);
	      break;
	    case 7:		//layer 4 type
	      toLower (t);
	      if (strncmp ("tcp", t, 3) == 0)
		r->L4 = TCP;
	      else if (strncmp ("udp", t, 3) == 0)
		r->L4 = UDP;
	      else
		r->L4 = OTHER;
	      break;
	    case 8:		//src port
	      toLower (t);
	      if (strncmp ("*", t, 1) == 0)
		{
		  r->s_port = 0;
		  r->s_port_last = r->s_port;
		}
	      else if (contains (t, '-'))
		{
		  sscanf (t, "%d-%d", &r->s_port, &r->s_port_last);
		}
	      else
		{
		  sscanf (t, "%d", &r->s_port);
		  r->s_port_last = r->s_port;
		}
	      break;
	    case 9:		//dest port
	      toLower (t);
	      if (strncmp ("any", t, 3) == 0)	//only numeric ports allowed,well known services list TODO
		{
		  r->d_port = 0;
		  r->d_port_last = r->d_port;
		}
	      else if (contains (t, '-'))
		{
		  sscanf (t, "%d-%d", &r->d_port, &r->d_port_last);
		}
	      else
		{
		  sscanf (t, "%d", &r->d_port);
		  r->d_port_last = r->d_port;
		}
	      break;
	    case 10:
	      r->bw = 0;	//not yet supported bandwidth per rule.
	      break;
	    case 11:		//dow/day of week
	      toLower (t);
	      if (strncmp ("any", t, 3) == 0)
		{
		  r->dow = -1;
		  break;
		}
	      else
		{
		  for (j = 0; j < 7; j++)
		    {
		      if (strncmp (t, days[j], strlen (t)) == 0)
			r->dow = j;
		      break;
		    }
		}
	      break;
	    case 12:
	      j = contains (t, '*');
	      if (j == 1)
		{
		  r->hour = -1;
		  r->minute = -1;
		}
	      else if (j > 1)
		{
		  sscanf (t + (j + 1), "%d:", &r->hour);
		  r->minute = -1;
		}
	      else
		sscanf (t, "%d:%d", &r->hour, &r->minute);	//obvious
	      break;
	    case 13:
	      toLower (t);
	      snprintf (r->IF, IFNAMSIZ, "%s", t);
	      break;
	    case 14:
	      toLower (t);
	      if (strncmp ("egress", t, 6) == 0)
		r->direction = EGRESS;
	      else if (strncmp ("ingress", t, 7) == 0)
		r->direction = INGRESS;
	      break;
	    default:
	      printf ("%d how the f*#$ did this happen??\n\a", i);
	      break;
	    }

	  t = strtok (NULL, s);
	}
    endloop:
      if (!invalid)
	{
	  CIRCLEQ_INSERT_TAIL (&rule_head, r, entries);
	  rcount++;
	  printf ("\r%d Rules Loaded...", rcount);
	}
      else
	invalid = 0;
    }
  r = CIRCLEQ_FIRST (&rule_head);
  printf ("\n");
}

int
main (int argc, char **argv)
{
  if (argc < 2)
    {
      prompt ();
    }
  else
    {
      load (argv[1]);
      summarize (NULL);
      printf ("Loaded %d rules from %s\n", rcount, argv[1]);
      prompt ();
    }
  return 0;
}
