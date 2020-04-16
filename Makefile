all:
	gcc-8 -Wall -Wextra -Werror -O3 -s -o debugger main.c
	gcc-8 -static -o test-static test.c
clean:
	rm test-static test-dyn debugger