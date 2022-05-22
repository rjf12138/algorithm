#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "algorithm.h"

using namespace std;
using namespace basic;
using namespace algorithm;

/*
 *  Define patterns for testing
 */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b
const char *testarray[5] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4
};
long int repeatcount[4] = { 1, 1, 1000000, 10};
const char *resultarray[4] =
{
    "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
    "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
    "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
};

int main()
{
    uint8_t Message_Digest[20];
    basic::ByteBuffer inbuf, outbuf;
    /*
     *  Perform SHA-1 tests
     */
    for(int j = 0; j < 4; ++j)
    {
        printf( "\nTest %d: %ld, '%s'\n",
                j+1,
                repeatcount[j],
                testarray[j]);

        inbuf.clear();
        for (int k = 0; k < repeatcount[j]; ++k) {
            inbuf.write_bytes(testarray[j], strlen(testarray[j]));
        }
        ssize_t ret = sha1(inbuf, outbuf);
        if (ret < 0)
        {
            printf("error: Sha1::sha1()\n");
        }
        outbuf.read_bytes(Message_Digest, 20);
        printf("\t");
        for(int i = 0; i < 20 ; ++i)
        {
            printf("%02X ", Message_Digest[i]);
        }
        printf("\n");
        printf("Should match:\n");
        printf("\t%s\n", resultarray[j]);
    }
    return 0;
}