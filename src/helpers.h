#include "includes.hpp"

#ifndef HELPERS_H
	#define HELPERS_H

	typedef long(*DecryptionProc)(void *);
	typedef struct {
	  int           verbose;
	  int 			mode;
	  char         	*input;
	  int 			inputsz;
	  int 			output;
	  std::filebuf*  elf;
	  int 			elfsz;
	  DIR           *dir;
	} options_t;

	void usage(char *progname, int opt);
	void error(const char *str);
	void error_verbose(const char *str, char *progname);
	void write_default_payload(char* payload);
	int default_payload_size();
#endif