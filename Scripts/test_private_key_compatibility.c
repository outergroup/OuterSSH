#include <OuterSSH/OuterSSH.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    assert(argc == 3);
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    unsigned char key[32769];
    size_t length = fread(key, 1, sizeof(key), file);
    assert(!ferror(file) && length < sizeof(key));
    fclose(file);
    uint32_t capabilities = outerssh_private_key_capabilities();
    const char *reason = outerssh_check_private_key(key, length, capabilities, true);
    if(!strcmp(argv[2], "valid")) {
        if(reason) fprintf(stderr, "%s\n", reason);
        assert(!reason);
        assert(outerssh_check_private_key(key, length, 0, false));
    } else {
        assert(reason && strstr(reason, argv[2]));
    }
    memset(key, 0, sizeof(key));
    puts("PASS: private-key compatibility");
}
