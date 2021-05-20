#include "includes.hpp"

typedef struct {
  int           verbose;
  int 			mode;
  char         	*input;
  int 			inputsz;
  int          output;
  int       	elf;
  DIR          *dir;
} options_t;


void usage(char *progname, int opt);
void error(const char *str);
void error_verbose(const char *str, char *progname);
char* default_payload();
int default_payload_size();


typedef long(*DecryptionProc)(void *);