CC = gcc-8
CFLAGS = -Wall -Wextra -Werror -O3
EXEC = cool-debugger
DEBUG = debugger-debug-version
SRC= main.c debugger.c
OBJ= $(SRC:.c=.o)
TEST = test.c
DEMO = $(wildcard test-*)
LIBNAME = capstone

all: release
release: $(OBJ) 
	@echo "Compiling release version"
	$(CC) $(CFLAGS) -s -o $(EXEC) $(OBJ) -l$(LIBNAME)
	@echo "Done"
debug: $(OBJ)
	@echo "Compiling debug version"
	$(CC) $(CFLAGS) -o $(DEBUG) $(OBJ) -l$(LIBNAME)
	@echo "Done"
debugger.o: debugger.h debugger.c
	$(CC) -c -o debugger.o debugger.c
main.o: debugger.h main.c
	$(CC) -c -o main.o main.c
demo: $(TEST)
	@echo "Compiling demo"
	$(CC) -static -o test-static $(TEST)
	$(CC) -o test-dyn $(TEST)
	$(CC) -s -o test-stripped $(TEST)
	$(CC) -static-pie -o test-static-pie $(TEST)
	@echo "Done"
clean:
	@rm $(EXEC)
clean-demo:
	@rm $(DEMO)
clean-debug:
	@rm $(DEBUG)
clean-obj:
	@rm $(OBJ)
