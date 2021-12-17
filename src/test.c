#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cfxaddr.h"

// https://stackoverflow.com/a/3409211
void hex_to_bytes(char *in, uint8_t *out) {
    char *pos = (in[1] == 'x') ? in + 2 : in;

    for (size_t count = 0; count < CFXADDR_HEX_ADDRESS_LEN; count++) {
        sscanf(pos, "%2hhx", &out[count]);
        pos += 2;
    }
}

void assert_equal(char *str1, char *str2) {
    if (strcmp(str1, str2) != 0) {
        printf("%s != %s\n", str1, str2);
        assert(0);
    }
}

void test_encode(char *hexaddr, uint32_t networkId, char *cfxaddr) {
    uint8_t bytes[CFXADDR_HEX_ADDRESS_LEN] = { 0x00 };
    hex_to_bytes(hexaddr, bytes);

    char addr[CFXADDR_MAX_LENGTH + 1] = { 0 };
    int ret = cfxaddr_encode(bytes, addr, sizeof(addr), networkId);
    assert(ret == CFXADDR_SUCCESS);
    assert_equal(addr, cfxaddr);
}

int main(void) {
    // general tests
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",  1029,      "cfx:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956n0en4fhe");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",     1,  "cfxtest:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956b7156tds");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",     2,     "net2:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956g83y91jb");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",   100,   "net100:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956u0k1w1jm");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",   999,   "net999:aaketjh9tkj5g2k4zx3kfvb9vkku8nr95681ah8012");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",  1000,  "net1000:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956jafjwf9c");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",  1001,  "net1001:aaketjh9tkj5g2k4zx3kfvb9vkku8nr95653vygz0g");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",  9999,  "net9999:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956nz01uz4b");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf", 10000, "net10000:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956jrm0uxb4");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf", 65535, "net65535:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956dy1m7n6x");
    test_encode("0x10109fC8DF283027b6285cc889F5aA624EaC1F55", 65535, "net65535:aajbbh8j56ydak70fbspvctzzkve7na9myc0ba3yj5");
    test_encode("0x10109fC8DF283027b6285cc889F5aA624EaC1F55",     0,     "net0:aajbbh8j56ydak70fbspvctzzkve7na9myjhst4bsb");

    // tests cases from CIP-37
    test_encode("0x85d80245dc02f5a89589e1f19c5c718e405b56cd", 1029,     "cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp");
    test_encode("0x85d80245dc02f5a89589e1f19c5c718e405b56cd",    1, "cfxtest:acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg");
    test_encode("0x1a2f80341409639ea6a35bbcab8299066109aa55", 1029,     "cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg");
    test_encode("0x1a2f80341409639ea6a35bbcab8299066109aa55",    1, "cfxtest:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p");
    test_encode("0x19c742cec42b9e4eff3b84cdedcde2f58a36f44f", 1029,     "cfx:aap6su0s2uz36x19hscp55sr6n42yr1yk6r2rx2eh7");
    test_encode("0x19c742cec42b9e4eff3b84cdedcde2f58a36f44f",    1, "cfxtest:aap6su0s2uz36x19hscp55sr6n42yr1yk6hx8d8sd1");
    test_encode("0x84980a94d94f54ac335109393c08c866a21b1b0e", 1029,     "cfx:acckucyy5fhzknbxmeexwtaj3bxmeg25b2b50pta6v");
    test_encode("0x84980a94d94f54ac335109393c08c866a21b1b0e",    1, "cfxtest:acckucyy5fhzknbxmeexwtaj3bxmeg25b2nuf6km25");
    test_encode("0x1cdf3969a428a750b89b33cf93c96560e2bd17d1", 1029,     "cfx:aasr8snkyuymsyf2xp369e8kpzusftj14ec1n0vxj1");
    test_encode("0x1cdf3969a428a750b89b33cf93c96560e2bd17d1",    1, "cfxtest:aasr8snkyuymsyf2xp369e8kpzusftj14ej62g13p7");

    // zero address
    test_encode("0x0000000000000000000000000000000000000000",  1029,      "cfx:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0sfbnjm2");
    test_encode("0x0000000000000000000000000000000000000000",     1,  "cfxtest:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6f0vrcsw");
    test_encode("0x0000000000000000000000000000000000000000", 65535, "net65535:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8p0apgvt");

    // internal contracts
    test_encode("0x0888000000000000000000000000000000000000",  1029,      "cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2mhjju8k");
    test_encode("0x0888000000000000000000000000000000000000",     1,  "cfxtest:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaaawby2s44d");
    test_encode("0x0888000000000000000000000000000000000000", 65535, "net65535:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaaaujykt8f8");

    test_encode("0x0888000000000000000000000000000000000001",  1029,      "cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaaegg2r16ar");
    test_encode("0x0888000000000000000000000000000000000001",     1,  "cfxtest:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaaeprn7v0eh");
    test_encode("0x0888000000000000000000000000000000000001", 65535, "net65535:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaaesenpuw54");

    test_encode("0x0888000000000000000000000000000000000002",  1029,      "cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajrwuc9jnb");
    test_encode("0x0888000000000000000000000000000000000002",     1,  "cfxtest:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajh3dw3ctn");
    test_encode("0x0888000000000000000000000000000000000002", 65535, "net65535:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajfudd2gu0");

    test_encode("0x0888000000000000000000000000000000000003",  1029,      "cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaapx8thaezf");
    test_encode("0x0888000000000000000000000000000000000003",     1,  "cfxtest:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaap3z61gsvt");
    test_encode("0x0888000000000000000000000000000000000003", 65535, "net65535:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaap566ghmsw");

    // large network id
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",      65536,      "net65536:aaketjh9tkj5g2k4zx3kfvb9vkku8nr95690chjwh9");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",   16777215,   "net16777215:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956tz3vh911");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",   16777216,   "net16777216:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956x1p6wgp5");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",   33554431,   "net33554431:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956n977s70m");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",  268435455,  "net268435455:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956k8372c4e");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf",  536870911,  "net536870911:aaketjh9tkj5g2k4zx3kfvb9vkku8nr956r2w200ez");
    test_encode("0x1247a0ff7a51b3613aacf292c43f8a530f2dbfdf", 4294967295, "net4294967295:aaketjh9tkj5g2k4zx3kfvb9vkku8nr95660vurfn6");

    printf("Pass\n");
    return 0;
}
