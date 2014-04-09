#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdint.h>
#include "utils.h"
#include "bfw.h"
#include <termcap.h>
static const char *safe =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890/.";
inline uint32_t
match (uint32_t network, uint32_t acl, uint32_t ip)
{
  return (network | acl) ^ (ip | acl) ? 0 : 1;
}

int
p_match (uint16_t port, uint16_t min, uint16_t max)
{				//second argument has to be from the fw rule
  if ((min + max) == 0)
    return 1;			//any src/dest
  if (min == max)
    if (port == min)
      return 1;			//no port range
  if (port >= min && port <= max)
    return 1;			//both non-zero range value

//printf("%hu ? %hu -> %hu\n",port,min,max);

  return 0;			//no match :(
}

void
cls ()
{
  char buf[1024];
  char *str;

  tgetent (buf, getenv ("TERM"));
  str = tgetstr ("cl", NULL);
  fputs (str, stdout);
}

void
readin (int sz, char *s)
{
  fgets (s, sz, stdin);
  if (s[strlen (s) - 1] == '\n')
    s[strlen (s) - 1] = '\0';
}

unsigned int
contains (const char *str, char c)
{
  int i = 0, sz = strlen (str);
  if (sz < 1)
    return 0;
  for (i; i < sz; i++)
    if (str[i] == c)
      return i ? i : 1;

  return 0;
}

char *
toLower (char *s)
{
  int i = 0, sz;
  sz = strlen (s);
  while (s[i] && i < sz)
    {
      s[i] = tolower (s[i]);
      ++i;
    }
  return s;
}

int
gettc ()
{
  struct termios oldt, newt;
  int ch;
  tcgetattr (STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ICANON);
  tcsetattr (STDIN_FILENO, TCSANOW, &newt);
  ch = getchar ();
  tcsetattr (STDIN_FILENO, TCSANOW, &oldt);
  return ch;
}

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
  if (system (IPT_IN_ON) < 0 || system (IPT_OUT_ON) < 0
      || system (IPT_IN_RAW_ON) < 0 || system (IPT_OUT_RAW_ON) < 0||
     system (IPT_IN_FILTER_ON) < 0 || system (IPT_OUT_FILTER_ON) < 0
    
  )
    {
      perror ("Error adding iptables rule to redirect taffic to bfw: ");
      exit (1);
    }


}

void
iptables_off ()
{
  if (system (IPT_IN_OFF) < 0 || system (IPT_OUT_OFF) < 0
      || system (IPT_IN_RAW_OFF) < 0 || system (IPT_OUT_RAW_OFF) < 0
     || system (IPT_IN_FILTER_OFF) < 0 || system (IPT_OUT_FILTER_OFF) < 0
    
  )
    {
      perror
	("Error removing iptables rules to resume normal traffic flow: ");
      printf
	("Please manually flush iptables by running /usr/sbin/iptables -F\n");
      exit (1);
    }
}

char *
trim (char *s)
{
  char *string = s;
  int sz = strlen (string);
  int i = 0;

  for (i; i < sz; i++)
    if (s[i] == ' ')
      s = s + (i + 1);		//get rid of leading white space

  sz = strlen (s);
  while ((s[sz - 1] == ' ') || (s[sz - 1] == '\n'))
    {
      string[sz - 1] = '\0';	//get rid of trailing white space
      --sz;
    }

  return s;
}

void
sanitize (char *s)
{
  int sz = strlen (s), sz_al = strlen (safe), i = 0, j = 0, ok = 0;
  if (sz < 1)
    return;
  for (i = 0; i < sz; i++)
    {
      if (s[i] == '.' && s[i + 1] == '.')
	{
	  s[i] = '\0';

	  return;

	}
      for (j = 0; j < sz_al; j++)
	{
	  if (s[i] == safe[j])
	    {

	      ok = 1;
	      break;
	    }

	}
      if (!ok)
	s[i] = '\0';
      ok = 0;
    }
}
