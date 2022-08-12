#include "algorithm.h"

int main(void)
{
    int seed = 12138;
    int ret = 0;
    fprintf(stdout, "================== Number =================\n");
    for (int i = 0 ; i < 5; ++i) {
        algorithm::murmurhash3_x86_32(&i, sizeof(int), seed, &ret);
        fprintf(stdout, "key: %d, seed: %d, out: %d\n", i, seed, ret);
    }

    fprintf(stdout, "================== String =================\n");
    const char *str[4] = {"hello", "hfllo", "k", "hh"};
    for (int i = 0 ; i < 5; ++i) {
        algorithm::murmurhash3_x86_32(str[i], strlen(str[i]), seed, &ret);
        fprintf(stdout, "key: %s, seed: %d, out: %d\n", str[i], seed, ret);
    }
    return 0;
}