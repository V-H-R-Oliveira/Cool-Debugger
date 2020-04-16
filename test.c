#include <stdio.h>

int op(int a, int b)
{
    if (a % b == 0)
        return a + b;
    
    puts("I'm fake");
    long long int mul = 1;

    for (long long int i = 1; i < (b-a *4); ++i)
        mul *= i;

    printf("Dummy mul: %lld\n", mul);
    return 0;
}


int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage %s <argv>\n", *argv);
        return 1;
    }

    printf("Your arg is: %s\n", argv[1]);
    puts("I'm the test");
    int soma = 0;

    for (int i = 0; i < 10; ++i)
        soma += i;
    
    printf("Soma: %d\n", soma);
    int res = op(2, 3);

    printf("sum: %d\n", res);
    return 0;
}