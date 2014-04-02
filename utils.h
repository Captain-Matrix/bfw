#ifndef utils_h
#define utils_h
#include <stdint.h>
char *int_to_ip (int ip);
void iptables_on ();
void iptables_off ();
int gettc ();
void cls ();
void readin (int sz, char *s);
unsigned int contains (const char *str, char c);
char *toLower (char *s);
uint32_t match (uint32_t network, uint32_t acl, uint32_t ip);


#endif
