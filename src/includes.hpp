#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <curses.h>
#include <math.h>
#include <unistd.h>
#include <signal.h>
#include <malloc.h>
#include <errno.h>
#include <sys/mman.h>
#include <iostream>     // std::cout
#include <algorithm>    // std::shuffle
#include <array>        // std::array
#include <random>       // std::default_random_engine
#include <chrono>       // std::chrono::system_clock
#include <string>
#include <fstream>
#include <streambuf>
#include <cstdio>

#include "../lib/asmjit.h"

//#define DEBUG(s) (std::cout << s << "\n")
//#define DEBUG2(s1, s2) (std::cout << s1 << s2 << "\n")
#define ERROR(s) (std::cout << "[!!] " << s << "\n")
#define DEBUG(s) 
#define DEBUG2(s1, s2)

//typedef unsigned int(*DecryptionProc)(char *);
typedef long(*DecryptionProc)(void *);

//typedef long(*DecryptionProc)(long);

#ifndef ERR_CODES

  #define MUTAGEN_ERR_PARAMS 1
  #define MUTAGEN_ERR_MEMORY 2
  #define MUTAGEN_ERR_SUCCESS 0

#endif

#define ASMJIT_EMBED
#define BLOCK_SIZE 128


//typedef unsigned int(*DecryptionProc)(void *);

