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
more (rinfo * info, int index)
{
  if (index > info->rcount)
    {
      // info->r_index = 0;
      index = 0;
      info->r = CIRCLEQ_FIRST (&rule_head);
    }
  int rows = info->r_index + ROWS;


  cls ();
  char l4[10];
  char l3[10];
  char Dow[10], hour[10], minute[10];
  char time[10];

  printf
    ("%3s %6s  %s  %15s %17s %15s %15s %3s %5s %5s %4s %8s %4s %5s  %7s\n",
     "#", "ACTION", "L3", "SOURCE", "ACL MASK", "DEST", "ACL MASK", "L4",
     "SRC", "DEST", "BW", "DOW", "TIME", "IF", "DIRECTON");
  for (info->r = rule_head.cqh_first, info->r_index = 0;
       info->r_index < rows && info->r != (void *) &rule_head;
       info->r = info->r->entries.cqe_next, info->r_index++)
    {
      switch (info->r->L3)
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
      switch (info->r->L4)
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

      if (info->r->dow == -1)
	snprintf (Dow, 10, "ANY");
      else
	snprintf (Dow, 10, "%s", days[info->r->dow]);
      if (info->r->hour == -1)
	snprintf (hour, 10, "*");
      else
	snprintf (hour, 10, "%u", info->r->hour);
      if (info->r->minute == -1)
	snprintf (minute, 10, "*");
      else
	snprintf (minute, 10, "%u", info->r->minute);
      fprintf
	(stdout, "%3d"
	 " %6s  %s  %15s %15s %15s"
	 " %15s %3s %5d %5d %4d %8s %2s:%2s "
	 "%5s  %7s\n",
	 info->r->number, info->r->action ? "PERMIT" : "DENY", l3,
	 int_to_ip (info->r->src), int_to_ip (info->r->src_mask),
	 int_to_ip (info->r->dest), int_to_ip (info->r->dest_mask), l4,
	 info->r->s_port, info->r->d_port, 0, Dow, hour, minute, info->r->IF,
	 info->r->direction ? "INGRESS" : "EGRESS");
      //r = CIRCLEQ_NEXT (r, entries);

    }
  if (info->r_index >= info->rcount)
    {
      info->r_index = 0;
    }
  printf (PROMPT);
}

int
write_rules (rinfo * info, char *path)
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
  for (i; i < info->rcount; i++)
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
	snprintf (hour, 10, "%u", rtmp->hour);
      if (rtmp->minute == -1)
	snprintf (minute, 10, "*");
      else
	snprintf (minute, 10, "%u", rtmp->minute);
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
summarize (rinfo * info, rule * rarg)
{
  int i = 0;
  float avgm, hundred = 100, f_index = 0;
  struct tm *T1, *T2;

  rule *rtmp, *rtmp2, *rtmp3;
//   if (rarg == NULL)
  rtmp = CIRCLEQ_FIRST (&rule_head);
//   else
//     rtmp = rarg;
  printf ("Summarizing rules.... %u\n", rtmp->action);
  avgm = hundred / info->rcount;
  for (info->r_index, f_index; info->r_index < info->rcount;
       f_index++, info->r_index++)
    {

      rtmp2 = CIRCLEQ_NEXT (rtmp, entries);

      for (i = info->r_index; i < info->rcount; i++)
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
	      printf ("\r%.2f%% Done [%5d/%5d]", f_index * avgm,
		      info->r_index, info->rcount);

	      --info->rcount;
	      avgm = hundred / info->rcount;

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
  for (i = 0; i < info->rcount; i++)
    {
      rtmp->number = i;
      rtmp = CIRCLEQ_NEXT (rtmp, entries);
    }
  info->r = CIRCLEQ_FIRST (&rule_head);
}

void
empty (rinfo * info)
{
  rule *r1, *r2;
  //r = CIRCLEQ_FIRST (&rule_head);
  while (info->rcount > 0 && rule_head.cqh_first != (void *) &rule_head)
    {
      CIRCLEQ_REMOVE (&rule_head, rule_head.cqh_first, entries);
      --info->rcount;
    }
  printf ("Emptied rule FIFO[%u]\n", info->rcount);

}

void
prompt (rinfo * info)
{
  char c, buf[256];
  info->r = CIRCLEQ_FIRST (&rule_head);
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
	  more (info, info->r_index);
	  break;
	case 'w':
	case 'W':
	  printf
	    ("\n%s\n Please enter the file path to write the rules to:\n",
	     PROMPT);
	  readin (256, &buf[0]);
	  if (write_rules (info, buf))
	    printf ("Encountered error while writing logs to file\n");
	  else
	    printf ("Successfully wrote %u rules to %s\n", info->rcount, buf);
	  usage ();
	  break;
	case 'r':
	case 'R':
	  printf
	    ("\n%s\n Please enter the file path where the desired rules/acls are located:\n",
	     PROMPT);
	  readin (256, &buf[0]);
	  acl_load (info, buf);
	  summarize (info, NULL);
	  usage ();
	  break;
	case 'p':
	case 'P':
	  printf
	    ("\n%s\n Please specify the path for the binary log file generated by bfw:\n",
	     PROMPT);
	  readin (256, &buf[0]);
	  load (info, buf);
	  usage ();
	  break;
	default:
	  break;
	}

    }

}

void
load (rinfo * info, char *path)
{
  meta_data M;
  if (info->rcount > 0 && !CIRCLEQ_EMPTY (&rule_head))
    empty (info);

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
      info->r = malloc (sizeof (rule));
      memset (info->r, 0, sizeof (rule));
      ++info->rcount;

      info->r->direction = M.direction;
      memcpy (info->r->IF, M.interface, IFNAMSIZ);
      info->r->IF[IFNAMSIZ] = '\0';
      T = localtime (&M.stamp);
      info->r->minute = T->tm_min;
      info->r->hour = T->tm_hour;
      info->r->dow = T->tm_wday;
      info->r->s_port = sport;
      info->r->d_port = dport;
      info->r->L4 = ntohs (M.layer4);
      info->r->src_mask = HOST;
      info->r->dest_mask = HOST;
      info->r->src = ntohl (M.ip_header->saddr);
      info->r->dest = ntohl (M.ip_header->daddr);
      info->r->L3 = M.ip_header->version;
      info->r->action = PERMIT;
      info->r->number = info->rcount;
      CIRCLEQ_INSERT_TAIL (&rule_head, info->r, entries);

      /////////////////////////////////////////////////////////////////


      if (info->debug)
	{
	  printf
	    ("_____________________________________________________________\n");
	  if (M.direction == EGRESS)
	    {			//egress    

	      printf ("\t\t%s \t\tEGRESS: %s\tL4:%0x\n\t%s:%u ---> %s:%u\n",
		      ctime (&M.stamp), M.interface, ntohs (M.layer4),
		      int_to_ip (ntohl (M.ip_header->saddr)), sport,
		      int_to_ip (ntohl (M.ip_header->daddr)), dport);



	    }
	  if (M.direction == INGRESS)
	    {			//ingress


	      printf ("\t\t%s \t\tINGRESS: %s\tL4:%0x\n\t%s:%u ---> %s:%u\n",
		      ctime (&M.stamp), M.interface, ntohs (M.layer4),
		      int_to_ip (ntohl (M.ip_header->saddr)), sport,
		      int_to_ip (ntohl (M.ip_header->daddr)), dport);

	    }
	}
    }

}

int
string_to_v4 (uint32_t * v4src, char *string)
{
  toLower (string);
  uint32_t v4;
  char str[INET6_ADDRSTRLEN];
  if (strncmp ("any", string, 3) == 0)
    {
      v4 = (uint32_t) (~0);

    }
  else if (strncmp ("host", string, 4) == 0)
    {
      v4 = 0;
    }
  else if (inet_pton (AF_INET, string, &(v4)) < 1)
    {

      printf ("failed ip conversion [%s]\n", string);
      return 1;

    }
  v4 = ntohl (v4);







  *v4src = v4;
  return 0;
}

int
string_to_port (uint16_t * mi, uint16_t * ma, char *string)
{
  uint16_t min, max;
  toLower (string);
  int dash = contains (string, '-');
  if (strncmp ("any", string, 3) == 0)
    {
      min = 0;
      max = min;
    }
  else if (dash > 1 && dash < strlen (string) - 1)
    {
      sscanf (string, "%hu-%hu", &min, &max);
    }
  else
    {
      sscanf (string, "%hu", &min);
      max = min;
    }
  if (min > max)
    return 1;

  *mi = min;
  *ma = max;
  return 0;
}

int
string_to_rule (rinfo * info, rule * r, char *separator, char *line)
{
  char buf[20], *t;
  struct sockaddr_in sa;
  int i, j;
  t = strtok (line, separator);
  if (line[0] != '#')		//comments
    {
      for (i = 0; i < 15 && t != NULL; i++)
	{
	  switch (i)
	    {
	    case 0:
	      info->r->number = info->rcount;	//yeah,I know-I don't care what number you put it in your rule file,it will process it in the order it reads it.
	      snprintf (info->r->name, 32, "[%u]%s", info->rcount, t);
	      break;
	    case 1:
	      toLower (t);
	      if (strncmp ("permit", t, 6) == 0)
		info->r->action = PERMIT;
	      else if (strncmp (t, "deny", 4) == 0)
		info->r->action = DENY;
	      else if (strncmp (t, "log", 3) == 0)
		info->r->action = LOG;
	      break;
	    case 2:
	      toLower (t);
	      if (strncmp (t, "ipv4", 4) == 0)
		info->r->L3 = 4;
	      break;
	    case 3:		//source ip
	      //only ipv4 supported atm

	      if (string_to_v4 (&info->r->src, t))
		return 1;


	      break;
	    case 4:		//source ip mask
	      if (string_to_v4 (&info->r->src_mask, t))
		return 1;
	      break;
	    case 5:		//destination ip
	      if (string_to_v4 (&info->r->dest, t))
		return 1;
	      break;
	    case 6:		//destination ip mask
	      if (string_to_v4 (&info->r->dest_mask, t))
		return 1;
	      break;
	    case 7:		//layer 4 type
	      toLower (t);
	      if (strncmp ("tcp", t, 3) == 0)
		info->r->L4 = TCP;
	      else if (strncmp ("udp", t, 3) == 0)
		info->r->L4 = UDP;
	      else
		info->r->L4 = OTHER;
	      break;
	    case 8:		//src port
	      if (string_to_port (&info->r->s_port, &info->r->s_port_last, t))
		return 1;
	      break;
	    case 9:		//dest port
	      if (string_to_port (&info->r->d_port, &info->r->d_port_last, t))
		return 1;
	      break;
	    case 10:
	      info->r->bw = 0;	//not yet supported bandwidth per rule.
	      break;
	    case 11:		//dow/day of week
	      toLower (t);
	      if (strncmp ("any", t, 3) == 0)
		{
		  info->r->dow = -1;
		  break;
		}
	      else
		{
		  for (j = 0; j < 7; j++)
		    {
		      if (strncmp (t, days[j], strlen (t)) == 0)
			info->r->dow = j;
		      break;
		    }
		}
	      break;
	    case 12:
	      j = contains (t, '*');
	      if (j == 1)
		{
		  info->r->hour = -1;
		  info->r->minute = -1;
		}
	      else if (j > 1)
		{
		  sscanf (t + (j + 1), "%u:", &info->r->hour);
		  info->r->minute = -1;
		}
	      else
		sscanf (t, "%u:%u", &info->r->hour, &info->r->minute);	//obvious
	      break;
	    case 13:
	      toLower (t);
	      snprintf (info->r->IF, IFNAMSIZ, "%s", t);
	      break;
	    case 14:
	      toLower (t);
	      if (strncmp ("egress", t, 6) == 0)
		info->r->direction = EGRESS;
	      else if (strncmp ("ingress", t, 7) == 0)
		info->r->direction = INGRESS;
	      break;
	    default:
	      printf ("%u how the f*#$ did this happen??\n\a", i);
	      break;
	    }

	  t = strtok (NULL, separator);
	}
    }
  else
    {
      return 1;

    }


  return 0;

}

void
acl_load (rinfo * info, char *path)
{
  if (!CIRCLEQ_EMPTY (&rule_head))
    empty (info);
  CIRCLEQ_INIT (&rule_head);
  info->rcount = 0;
  int sz;
  FILE *f = fopen (path, "r");
  char line[1024];
  if (!f)
    {
      fprintf (stderr, "Unable to open rule file at %s\n", path);
      return;
    }

  while (!feof (f))
    {
      memset (&line, 0, 1024);
      fgets (line, 1024, f);
      sz = strlen (line);
      if (sz > 20 && line[0] != '#')
	{
	  if (line[strlen (line) - 1] == '\n')
	    line[strlen (line) - 1] = '\0';
	  info->r = malloc (sizeof (rule));

	  if (!string_to_rule (info, info->r, " ", &line[0]))
	    {

	      CIRCLEQ_INSERT_TAIL (&rule_head, info->r, entries);
	      info->rcount++;
	      printf ("\r%i Rules Loaded...", info->rcount);
	      //  printf("converted %s\n",int_to_ip(info->r->src));

	    }
	  else
	    {
	      free (info->r);
	      printf ("Unable to load %s\n", line);
	    }

	}
    }

  info->r = CIRCLEQ_FIRST (&rule_head);
  // printf ("\n");


}

// int
// main (int argc, char **argv)
// {
//   if (argc < 2)
//     {
//       prompt ();
//     }
//   else
//     {
//       load (argv[1]);
//       summarize (NULL);
//       printf ("Loaded %u rules from %s\n", info->rcount, argv[1]);
//       prompt ();
//     }
//   return 0;
// }
