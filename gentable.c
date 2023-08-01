#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// #define DEFAULT "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-*_"
#define DEFAULT ".WLERNTAISO-GDUHMPBKCFY2ZV1X34J065789Q_*"

int main (int argc, char **argv) {
    unsigned char table[256];
    char *order = argv[1];
    int labelsep = 0, wildcard = 0;
    memset(table, 0xff, sizeof(table));

    if (!order) {
        fprintf(stderr, "gentable: No arguments, Using default order.\n");
        order = DEFAULT;
    }

    // Check the order
    if (strlen(order) != 40) {
        fprintf(stderr, "gentable: Error: %ld chars instead of 40. Using default order.\n",
                strlen(argv[1]));
        order = DEFAULT;
    } else {
        char c[] = DEFAULT;
        int count = 0;
        for (int i = 0; i < 40; i++) {
            if (order[i] >= 'a' && order[i] <= 'z') {
                order[i] -= 0x20;
            }
            char *ptr = strchr(c, order[i]);
            if (ptr) {
                count++;
                *ptr = ' ';
            }
        }
        if (count != 40) {
            fprintf(stderr, "gentable: Error: Some chars are missing. Using default order.\n");
            order = DEFAULT;
        }
    }

    for (int i = 0; i < strlen(order); i++) {
        table[(int)order[i]] = i;
        table[order[i]|0x20] = i;
        if (order[i] == '.')
            labelsep = i;
        else if (order[i] == '*')
            wildcard = i;
    }

    printf("#define LABELSEP 0x%x\n"
           "#define WILDCARD 0x%x\n",
           labelsep, wildcard);
    printf("#define CHAR2IDTABLE \"");
    for (int i = 0; i < sizeof(table); i++) {
        printf("\\x%x", table[i]);
    }
    printf("\"\n");
}
