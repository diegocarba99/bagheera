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

ULIMIT_CONF = ulimit -c unlimited

all: $(TARGET)

$(TARGET): $(SRC)$(ENGINE).cpp $(SRC)$(ENGINE).hpp
	$(ULIMIT_CONF)
	$(CC) -o $(TARGET) $(TARGET).cpp $(SRC)$(ENGINE).cpp $(CFLAGS) -L$(LIB) -lasmjit 

make single:
	$(CC) -o $(TARGET) $(TARGET).cpp $(CFLAGS) -L$(LIB) -lasmjit

test:
	$(CC) -o $(TEST) $(x86TEST).cpp $(TEST).cpp $(CFLAGS) -L$(LIB) -lasmjit 

test2:
	$(CC) -o $(BENCH) $(SRC)$(BENCH).cpp $(CFLAGS) -L$(LIB) -lasmjit 

test_run:
	./$(TEST)

run:
	./$(TARGET)

clean: 
	$(RM) core*
	$(RM) $(TARGET)
	$(RM) $(BINS)*
	$(RM) $(TMP)*
	$(RM) $(LOG)*
