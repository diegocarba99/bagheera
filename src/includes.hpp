#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <curses.h>

#include <iostream>     // std::cout
#include <algorithm>    // std::shuffle
#include <array>        // std::array
#include <random>       // std::default_random_engine
#include <chrono>       // std::chrono::system_clock

#include <cstdio>

#include "../lib/asmjit.h"


#include "../lib/asmjit.h"

#ifndef ERR_CODES

  #define MUTAGEN_ERR_PARAMS -1
  #define MUTAGEN_ERR_MEMORY -2
  #define MUTAGEN_ERR_SUCCESS 0

#endif

#define ASMJIT_EMBED
#define BLOCK_SIZE 128


//typedef unsigned int(*DecryptionProc)(void *);

