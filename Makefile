# the compiler: gcc for C program, define as g++ for C++
CC = g++

# compiler flags:
#  -g         - this flag adds debugging information to the executable file
#  -Wall      - this flag is used to turn on most compiler warnings
#  -std=c++11 - this flag enables C++11 support in order to use AsmJit
CFLAGS  = -ggdb -Wall -std=c++11 -DASMJIT_STATIC

# The build target
TARGET = main
ENGINE = bagheera

TEST = src/asmjit_test_assembler
x86TEST = src/asmjit_test_assembler_x86
BENCH = asmjit_bench_x86


SRC = src/
LIB = lib/
BINS = bins/
TMP = tmp/
LOG = log/
COOL_NAME = bagheera
AV = clamscan
SIGNATUREDB = -d clamav_db/
DB = signatures.ndb
SOURCES = src/bagheera.cpp src/engine.cpp src/helpers.cpp src/infect.cpp
HEADERS = src/bagheera.hpp src/definitions.h src/engine.h src/helpers.h src/infect.h


ULIMIT_CONF = ulimit -c unlimited

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS) $(TARGET).cpp
	$(CC) -o $(COOL_NAME) $(TARGET).cpp $(SOURCES) $(CFLAGS) -L$(LIB) -lasmjit

make single:
	$(CC) -o $(TARGET) $(TARGET).cpp $(CFLAGS) -L$(LIB) -lasmjit

av:
	$(AV) $(SIGNATUREDB)$(DB) $(BINS)* -v

run:
	./$(COOL_NAME)

clean:
	$(RM) core*
	$(RM) $(TARGET)
	$(RM) $(BINS)*
	$(RM) $(TMP)*
	$(RM) $(LOG)*
