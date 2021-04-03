# the compiler: gcc for C program, define as g++ for C++
CC = g++

# compiler flags:
#  -g         - this flag adds debugging information to the executable file
#  -Wall      - this flag is used to turn on most compiler warnings
#  -std=c++11 - this flag enables C++11 support in order to use AsmJit
CFLAGS  = -g -Wall -std=c++11 -DASMJIT_STATIC

# The build target
TARGET = main
ENGINE = bagheera

x86TEST = x86_assembler_test
#x86TEST = test

SRC = src/
LIB = lib/

ULIMIT_CONF = ulimit -c unlimited

all: $(TARGET)

$(TARGET): $(SRC)$(ENGINE).cpp $(SRC)$(ENGINE).hpp
	$(ULIMIT_CONF)
	$(CC) -o $(TARGET) $(TARGET).cpp $(SRC)$(ENGINE).cpp $(CFLAGS) -L$(LIB) -lasmjit 

make single:
	$(CC) -o $(TARGET) $(TARGET).cpp $(CFLAGS) -L$(LIB) -lasmjit

test:
	$(CC) -o $(x86TEST) $(x86TEST).cpp $(CFLAGS) -L$(LIB) -lasmjit 

run:
	./$(TARGET)

clean: 
	$(RM) $(TARGET)
