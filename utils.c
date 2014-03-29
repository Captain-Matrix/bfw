#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "bfw.h"
char *
int_to_ip (int ip)
{
  unsigned char bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;
  char *res = malloc (16);
  snprintf (res, 16, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
  return res;
}

void
iptables_on ()
{
  if (system (IPT_IN_ON) < 0 || system (IPT_OUT_ON) < 0)
    {
      perror ("Error adding iptables rule to redirect taffic to bfw: ");
      exit (1);
    }


}

void
iptables_off ()
{
  if (system (IPT_IN_OFF) < 0 || system (IPT_OUT_OFF) < 0)
    {
      perror
	("Error removing iptables rules to resume normal traffic flow: ");
      printf
	("Please manually flush iptables by running /usr/sbin/iptables -F\n");
      exit (1);
    }
}
