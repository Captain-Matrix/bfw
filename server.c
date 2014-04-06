#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "server.h"
#include "bfw.h"
#include "utils.h"
#include "processlog.h"
#include "mongoose/mongoose.h"
static int debug = 0, rcount = -1, r_index = 0;
static rule *r;
void
fserve (struct mg_connection *conn, char *file)
{
  char line[1024];
  FILE *f = fopen (file, "r");

  if (f == NULL)
    return;
  while (!feof (f))
    {
      fgets (line, 1024, f);
      if (strlen (line) > 0)
	{			// ;)
	  mg_printf_data (conn, line);
	}
    }
}

void
web_table (int sz, char *buf)
{
  char l4[10];
  char l3[10];
  char Dow[10], hour[10], minute[10];
  char time[10], action[10], direction[10];
  int i;
  struct tm *T;
  i += snprintf (buf, sz, "<html><body><table border=\"1\">");
  i += snprintf (buf + strlen (buf), sz - i,
		 "<tr><td contenteditable=\"true\">%4s</td> <td contenteditable=\"true\">%3s</td> <td contenteditable=\"true\">%6s</td>  <td contenteditable=\"true\">%s</td>  <td contenteditable=\"true\">%15s</td> <td contenteditable=\"true\">%17s</td> <td contenteditable=\"true\">%15s</td> <td contenteditable=\"true\">%15s</td> <td contenteditable=\"true\">%3s</td> <td contenteditable=\"true\">%5s</td> <td contenteditable=\"true\">%5s</td> <td contenteditable=\"true\">%4s</td> <td contenteditable=\"true\">%8s</td> <td contenteditable=\"true\">%4s</td> <td contenteditable=\"true\">%5s</td>  <td contenteditable=\"true\">%7s</td></tr>\n<br/>",
		 "#", "Hits", "ACTION", "L3", "SOURCE", "ACL MASK",
		 "DEST", "ACL MASK", "L4", "SRC", "DEST", "BW", "DOW",
		 "TIME", "IF", "DIRECTON");
  for (r = rule_head.cqh_first, r_index = 0; r != (void *) &rule_head;
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
      switch (r->action)
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
      if (r->direction == EGRESS)
	snprintf (direction, 10, "EGRESS");
      else if (r->direction == INGRESS)
	snprintf (direction, 10, "INGRESS");

      i += snprintf
	(buf + strlen (buf), sz - i,
	 " <tr><td contenteditable=\"true\">%3d</td> <td contenteditable=\"true\">%4d</td>   "
	 " <td contenteditable=\"true\">%6s</td>  <td contenteditable=\"true\">%s</td>  <td contenteditable=\"true\">%15s</td> <td contenteditable=\"true\">%15s</td> <td contenteditable=\"true\">%15s</td>"
	 " <td contenteditable=\"true\">%15s</td> <td contenteditable=\"true\">%3s</td>  <td contenteditable=\"true\">%4d</td> <td contenteditable=\"true\">%5d</td> "
	 "<td contenteditable=\"true\">%4d KB</td> <td contenteditable=\"true\">%8s</td> <td contenteditable=\"true\">%2s</td><td contenteditable=\"true\">%2s</td> "
	 "<td contenteditable=\"true\">%5s</td>  <td contenteditable=\"true\">%7s</td></tr>",
	 r->number, r->hits, action, l3, int_to_ip (r->src),
	 int_to_ip (r->src_mask), int_to_ip (r->dest),
	 int_to_ip (r->dest_mask), l4, r->s_port, r->d_port, (r->bw / 1024),
	 Dow, hour, minute, r->IF, direction);
      //r = CIRCLEQ_NEXT (r, entries);


    }
  i +=
    snprintf (buf + strlen (buf), sz - i,
	      "</table></body></html> \0\r\n\r\n");

}

static int
request_handler (struct mg_connection *conn, enum mg_event ev)
{
  int result = MG_FALSE;
  char buf[100000];
  if (ev == MG_REQUEST)
    {
      if (strncmp (conn->uri, "/", strlen (conn->uri)) == 0)
	{
	  fserve (conn, "./index.html");
	}
      else if (strncmp ("/table", conn->uri, 6) == 0)
	{
	  web_table (100000, &buf);

	  mg_send_data (conn, buf, strlen (buf));
	  mg_printf_data (conn, "\r\n\r\n");
	  printf ("~~~~~%s~~~~~~~\n", buf);
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
  struct mg_server *server;

  // Create and configure the server
  server = mg_create_server (NULL, request_handler);
  mg_set_option (server, "listening_port", "9999");

  // Serve request. Hit Ctrl-C to terminate the program
  printf ("Starting on port %s\n", mg_get_option (server, "listening_port"));
  for (;;)
    {
      mg_poll_server (server, 1000);
    }

  // Cleanup, and free server instance
  mg_destroy_server (&server);
}