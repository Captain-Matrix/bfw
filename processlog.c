#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/types.h>
#include <string.h>
#include "bfw.h"
#include "utils.h"
#include "processlog.h"
int debug=0,rcount=-1,r_index=0;
rule *r;
void usage(){
 printf(
"\n-------------------------------------------------------------------------------\n"
"|			  Press:					      |\n"
"|			  space key to scroll through rules                   |\n" 
"|			  ? to display this guide again			      |\n"
"|			  ! to delete a rule  				      |\n"
"|			  # to add a rule                                     |\n" 
"|			  $ to edit a rule                                    |\n"
"|			  W to write rules to file                            |\n"
"|			  R to re-process binary log                          |\n"
"|			  q to quit program                                   |\n"
"-------------------------------------------------------------------------------\n");
   printf(PROMPT);

 fflush(stdout);
} 


int more(int index){
  int rows=r_index+ROWS;
  cls();
  char l4[10];
  char l3[10];
  char dow[10];
  char time[10];
  struct tm *T=localtime(&r->stamp);
  
 printf("%3s %6s  %s  %15s %17s %15s %15s %3s %5s %5s %4s %8s %4s %5s  %7s\n",
 "#","ACTION","L3","SOURCE","ACL MASK","DEST","ACL MASK","L4","SRC","DEST","BW","DOW","TIME","IF","DIRECTON"
 );
  for(r_index;r_index<rcount && r_index<rows;r_index++){
 switch(r->L3){
   case 4:
     snprintf(l3,10,"IPv4");
     break;
   case 6:
     snprintf(l3,10,"IPv6");
     break;
   default:
     snprintf(l3,10,"OTHER");
     break;
 }
 switch(r->L4){
      case TCP:
     snprintf(l4,10,"TCP");
     break;
   case UDP:
     snprintf(l4,10,"UDP");
     break;
   default:
     snprintf(l4,10,"OTHER");
     break;
   
 }
 
 printf(
 "%3d %6s  %s  %15s %15s %15s %15s %3s %5d %5d %4d %8s %2d:%2d %5s  %7s\n",
 r->number,r->action? "PERMIT" : "DENY",
 l3,
 int_to_ip(r->src),
 int_to_ip(r->src_mask),
 int_to_ip(r->dest),
 int_to_ip(r->dest_mask),
 l4,
 r->s_port,
 r->d_port,0,
 days[T->tm_wday],
 T->tm_hour,T->tm_min,
 r->IF,
 r->direction?"INGRESS":"EGRESS" 
 );
    r=TAILQ_NEXT(r,entries);

  }
  if(r_index>=rcount){
   r_index=0;
   printf("%s Rollover\n",PROMPT);
  }
  printf(PROMPT);
}
void prompt(){
  char c;
  r=TAILQ_FIRST(&rule_head);
usage();
while((c=gettc())!='q'){
     switch(c){
       case '?':
       usage();
       break;
       case ' ':
	 more(r_index);
	 break;
       break;
       default:
	 break;
     }
   
 }
  
}
void load(){
 meta_data M;
   TAILQ_INIT (&rule_head);

  int sport, dport, i;
  if (!(learn_log = fopen ("./bfw_learn.log1", "rb")))
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
	r=malloc(sizeof(rule));
        memset(r,0,sizeof(rule));
        ++rcount;
      
	r->direction=M.direction;
        snprintf(r->IF,IFNAMSIZ,"%s",M.interface);
	r->stamp=M.stamp;
	r->s_port=sport;
	r->d_port=dport;
	r->L4=ntohs (M.layer4);
	r->src_mask=HOST;
	r->dest_mask=HOST;
	r->src=ntohl (M.ip_header->saddr);
	r->dest=ntohl (M.ip_header->daddr);
	r->L3=M.ip_header->version;
	r->action=PERMIT;
	r->number=rcount;
      	  TAILQ_INSERT_TAIL (&rule_head, r, entries);

      /////////////////////////////////////////////////////////////////
	  
        
      if(debug){
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
int
main ()
{
  load();
  printf("Loaded %d rules....\n",rcount);
  prompt();
  
  return 0;
}
