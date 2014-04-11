#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "server.h"
#include "bfw.h"
#include "utils.h"
#include "processlog.h"
#include "mongoose/mongoose.h"
static rinfo *inf;
void
fserve (struct mg_connection *conn, char *file)
{
  char line[10000];
  printf ("Serving %s\n", file);
  FILE *f = fopen (file, "r");

  if (f == NULL)
    return;
  while (!feof (f))
    {
      fgets (line, 10000, f);
      if (strlen (line) > 0)
	{			// ;)
	  mg_send_data (conn, &line[0], strlen (line));
	}
    }
}

void
web_table (rinfo * info, int sz, char *buf)
{
  char l4[10];
  char l3[10];
  char Dow[10], hour[10], minute[10];
  char time[10], action[10], direction[10];
  int i;
  struct tm *T;
//   i += snprintf (buf, sz, "<html><body><table style=\"border-collapse:collapse;border:1px solid green;background-color:black;color:lime;\">");
//   i += snprintf (buf + strlen (buf), sz - i,
//               "<tr>#%4s #%3s #%6s  #%s  #%15s #%17s #%15s #%15s #%3s #%5s #%5s #%4s #%8s #%2s#%2s  #%5s  #%7s</tr>\n<br/>",
//               "#", "Hits", "ACTION", "L3", "SOURCE", "ACL MASK",
//               "DEST", "ACL MASK", "L4", "SRC", "DEST", "BW", "DOW",
//               "hour","minute", "IF", "DIRECTON");
  for (info->r = rule_head.cqh_first, info->rcount = 0;
       info->r->entries.cqe_next != (void *) &rule_head;
       info->r = info->r->entries.cqe_next, info->rcount++)
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
      switch (info->r->action)
	{
	case PERMIT:
	  snprintf (action, 10, "PERMIT");
	  break;
	case DENY:
	  snprintf (action, 10, "DENY");
	  break;
	case LOG:
	  snprintf (action, 10, "LOG");
	  break;
	default:
	  snprintf (action, 10, "DENY");

	}
      if (info->r->direction == EGRESS)
	snprintf (direction, 10, "EGRESS");
      else if (info->r->direction == INGRESS)
	snprintf (direction, 10, "INGRESS");

      i += snprintf
	(buf + strlen (buf), sz - i,
	 "#%s#%u"
	 "#%s#%s#%s#%s#%s"
	 "#%s#%s#%u#%u#%u#%u "
	 "#%u KB#%s#%s#%s"
	 "#%s#%s!",
	 info->r->name, info->r->hits, trim (action), trim (l3),
	 trim (int_to_ip (info->r->src)),
	 trim (int_to_ip (info->r->src_mask)),
	 trim (int_to_ip (info->r->dest)),
	 trim (int_to_ip (info->r->dest_mask)), trim (l4), info->r->s_port,
	 info->r->s_port_last, info->r->d_port, info->r->d_port_last,
	 (info->r->bw / 1024), trim (Dow), trim (hour), trim (minute),
	 trim (info->r->IF), trim (direction));
      //r = CIRCLEQ_NEXT (r, entries);


    }
  trim (buf);
  buf[strlen (buf) - 1] = '\0';
// printf("%s\n",buf);
}

void
apply (rinfo * info, struct mg_connection *conn)
{
  int sz = conn->content_len;
  int i = 0, j = 0;
  char *rules = malloc (sz);
  char *tmp, buf[4096][1024];
  rinfo *itmp, *tmp_info = malloc (sizeof (rinfo));
  tmp_info->rcount = 0;
  if (rules == NULL)
    return;

  memset (rules, 0, sz);
  mg_get_var (conn, "rules", rules, sz);

  tmp = strtok (rules, "!");
  if (tmp == NULL)
    return;

  for (tmp, i = 0; tmp != NULL; i++)
    {
      snprintf (buf[i], 1024, "%s", tmp);
      trim (&buf[i]);
      tmp = strtok (NULL, "!");
    }
  for (j = 0; j < i; j++)
    {
      tmp_info->r = malloc (sizeof (rule));

      printf ("%s\n", buf[j]);
      if (!string_to_rule (tmp_info, tmp_info->r, " ", &buf[j][0]))
	{

	  CIRCLEQ_INSERT_TAIL (&rule_head, tmp_info->r, entries);
	  tmp_info->rcount++;


	}
      else
	{
	  free (tmp_info->r);
	  printf ("Unable to load %s\n", buf[j]);
	}
    }



  itmp = info;
  info = tmp_info;
  empty (itmp);

}

static int
request_handler (struct mg_connection *conn, enum mg_event ev)
{
  int result = MG_FALSE;
  char buf[100000];

  memset (&buf, 0, 100000);

  if (ev == MG_REQUEST)
    {
      if (strncmp (conn->uri, "/", strlen (conn->uri)) == 0)
	{
	  fserve (conn, "./index.html");
	  return MG_TRUE;

	}
      else if (strncmp ("/rules", conn->uri, 6) == 0)
	{
	  web_table (inf, 100000, &buf[0]);

	  mg_send_data (conn, buf, strlen (buf));
	  mg_printf_data (conn, "\r\n\r\n");
	  //printf ("~~~~~%s~~~~~~~\n", buf);
	  return MG_TRUE;
	}
      else if (strncmp ("/apply", conn->uri, 6) == 0)
	{

	  // apply(inf,conn);
	  return MG_TRUE;
	}
      result = MG_TRUE;
    }
  else if (ev == MG_AUTH)
    {
      result = MG_TRUE;
    }

  return result;
}

void *
server (void *args)
{
  inf = args;
  struct mg_server *server;

  // Create and configure the server
  server = mg_create_server (NULL, request_handler);
  mg_set_option (server, "listening_port", "8989");

  // Serve request. Hit Ctrl-C to terminate the program
  printf ("Starting on port %s\n", mg_get_option (server, "listening_port"));
  for (;;)
    {
      mg_poll_server (server, 1000);
    }

  // Cleanup, and free server instance
  mg_destroy_server (&server);
}
