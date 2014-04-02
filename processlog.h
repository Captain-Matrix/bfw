#ifndef processlog_h
#define processlog_h
#include <sys/queue.h>
#include <net/if.h>
#include <time.h>
#include <stdint.h>
#define  ANY ~0
#define  HOST 0
#define PERMIT 1
#define DENY 0
#define LOG -1
#define ROWS 40
#define PROMPT "$(learning)>"
char days[7][10] =
  { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
  "Saturday"
};

struct rule
{
  int number;
  int action;
  int L3;
  uint32_t src;
  uint32_t dest;
  uint32_t src_mask;
  uint32_t dest_mask;
  int L4;
  uint16_t s_port;
  uint16_t s_port_last;
  uint16_t d_port;
  uint16_t d_port_last;
  unsigned int bw;		//not using this field at the moment.
  int hour, minute, dow;	//probably temporary for the sake of simpler summary
  char IF[IFNAMSIZ];
  int direction;
    CIRCLEQ_ENTRY (rule) entries;
};
typedef struct rule rule;
CIRCLEQ_HEAD (, rule) rule_head;
     void load (char *p);
     void acl_load (char *path);
#endif
