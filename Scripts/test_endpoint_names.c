#include "OuterSSH/SSHEndpointNames.h"
#include "../OuterSSH/SSHEndpointRecord.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    OuterSSHEndpointRecord *records;
    size_t count;
} Names;

static Names *parse(const void *bytes, size_t length) {
    Names *names = calloc(1, sizeof(*names));
    assert(names);
    if (!outersshpriv_endpoint_names_parse(bytes, length, &names->records, &names->count)) {
        assert(!names->records && !names->count);
        free(names);
        return NULL;
    }
    return names;
}

static const OuterSSHEndpointName *lookup(const Names *names, const char *transport, const char *address, uint16_t port) {
    const OuterSSHEndpointRecord *record = outerssh_endpoint_records_find(names->records, names->count, transport, address, port);
    return record ? &record->name : NULL;
}

static void names_free(Names *names) {
    if (names) free(names->records);
    free(names);
}

static uint32_t crc(const unsigned char *bytes, size_t length) {
    uint32_t value = 0xffffffffu;
    while (length--) {
        value ^= *bytes++;
        for (int bit = 0; bit < 8; bit++) value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1)));
    }
    return value ^ 0xffffffffu;
}

static size_t chunk(unsigned char *out, const char *type, const unsigned char *data, uint32_t length) {
    out[0] = (unsigned char)(length >> 24); out[1] = (unsigned char)(length >> 16);
    out[2] = (unsigned char)(length >> 8); out[3] = (unsigned char)length;
    memcpy(out + 4, type, 4);
    if (length) memcpy(out + 8, data, length);
    uint32_t value = crc(out + 4, 4 + (size_t)length);
    out[8 + length] = (unsigned char)(value >> 24); out[9 + length] = (unsigned char)(value >> 16);
    out[10 + length] = (unsigned char)(value >> 8); out[11 + length] = (unsigned char)value;
    return 12 + (size_t)length;
}

static size_t png(unsigned char *out, uint32_t width, uint32_t height, size_t data_length) {
    static const unsigned char signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    unsigned char header[13] = {(unsigned char)(width >> 24), (unsigned char)(width >> 16), (unsigned char)(width >> 8),
        (unsigned char)width, (unsigned char)(height >> 24), (unsigned char)(height >> 16), (unsigned char)(height >> 8),
        (unsigned char)height, 8, 6, 0, 0, 0};
    unsigned char *data = calloc(1, data_length + 1);
    assert(data);
    memcpy(out, signature, 8);
    size_t used = 8;
    used += chunk(out + used, "IHDR", header, 13);
    used += chunk(out + used, "IDAT", data, (uint32_t)data_length);
    used += chunk(out + used, "IEND", NULL, 0);
    free(data);
    return used;
}

static void test_icons(void) {
    static unsigned char image[OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES * 2];
    size_t length = png(image, 16, 16, 20);
    assert(outerssh_endpoint_icon_is_valid(image, length));
    assert(!outerssh_endpoint_icon_is_valid(image, length - 1));
    image[length - 13] ^= 1;
    assert(!outerssh_endpoint_icon_is_valid(image, length));
    length = png(image, 512, 512, 20);
    assert(outerssh_endpoint_icon_is_valid(image, length));
    length = png(image, 513, 16, 20);
    assert(!outerssh_endpoint_icon_is_valid(image, length));
    length = png(image, 16, 0, 20);
    assert(!outerssh_endpoint_icon_is_valid(image, length));
    length = png(image, 16, 16, OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES - 57);
    assert(length == OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES && outerssh_endpoint_icon_is_valid(image, length));
    length = png(image, 16, 16, OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES - 56);
    assert(!outerssh_endpoint_icon_is_valid(image, length));
    assert(!outerssh_endpoint_icon_is_valid("GIF89a", 6));
    unsigned char no_data[64];
    unsigned char header[13] = {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0};
    memcpy(no_data, image, 8);
    size_t used = 8 + chunk(no_data + 8, "IHDR", header, 13);
    used += chunk(no_data + used, "IEND", NULL, 0);
    assert(!outerssh_endpoint_icon_is_valid(no_data, used));

    char name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY];
    assert(outerssh_endpoint_icon_file_name("unix", "/run/user/1000/app", 18, 0, name));
    assert(!strcmp(name, "476840428b67c48d6ee75d7335f2c8e0454c264c96b3541c76e7d310628fa072.png"));
    assert(outerssh_endpoint_icon_file_name("tcp", "LocalHost", 9, 6006, name));
    assert(!strcmp(name, "57cadb02e51f395b58595fe590195d2f5b1a921b18f35ee60ea5fbfbb4cb19b5.png"));
    assert(outerssh_endpoint_icon_file_name("tcp", "127.0.0.1", 9, 6006, name));
    assert(!strcmp(name, "06b50cb707a42ca2df8be800d814b7d7e82c048ffbeea28e0b00076222c190d6.png"));
    assert(outerssh_endpoint_icon_file_name("tcp", "::1", 3, 6006, name));
    assert(!strcmp(name, "41efa6c0b079e49bf463a94e31f6e957f32de6240ed90ff2a972252c5eba4de1.png"));
    assert(outerssh_endpoint_icon_file_name("pipe", "\\\\.\\PIPE\\Example", 16, 0, name));
    assert(!strcmp(name, "e28663b1c31ca2f3597a33e07b6912cf20a15c846dfddbcd8f30eaaa52283489.png"));
    assert(!outerssh_endpoint_icon_file_name("unix", "relative", 8, 0, name));
    assert(!outerssh_endpoint_icon_file_name("unix", "/a", 2, 80, name));
    assert(!outerssh_endpoint_icon_file_name("tcp", "localhost", 9, 0, name));
    assert(!outerssh_endpoint_icon_file_name("tcp", "a/b", 3, 80, name));
    assert(!outerssh_endpoint_icon_file_name("unix", "/a\nb", 4, 0, name));
    assert(!outerssh_endpoint_icon_file_name("unix", "/a\0b", 4, 0, name));
    assert(!outerssh_endpoint_icon_file_name("http", "/a", 2, 0, name));
}

static void test_enumeration(void) {
    const char data[] = "alice\0outerssh-endpoints-v2\nunix /b\n\nBeta\ntcp LOCALHOST 80\nBox\nWeb\n"
        "unix /a\n\nAlpha\nunix /c\n\nOne\ntcp localhost 80\nBox\nWeb\nunix /B\n\nUpper\n"
        "tcp 127.0.0.1 80\nBox\nWeb\ntcp ::1 80\nBox\nWeb\n\0"
        "root\0outerssh-endpoints-v2\nunix /c\n\nTwo\nunix /b\n\nBeta\n\0";
    Names *names = parse(data, sizeof(data) - 1);
    assert(names);
    assert(names->count == 5);
    const char *expected[][4] = {{"tcp", "LOCALHOST", "Box", "Web"}, {"unix", "/a", "", "Alpha"},
        {"unix", "/B", "", "Upper"}, {"tcp", "127.0.0.1", "Box", "Web"}, {"tcp", "::1", "Box", "Web"}};
    for (size_t i = 0; i < 5; i++) {
        const OuterSSHEndpointRecord *record = &names->records[i];
        assert(record && !strcmp(record->transport, expected[i][0]) && !strcmp(record->address, expected[i][1]));
        assert(!strcmp(record->name.container, expected[i][2]) && !strcmp(record->name.app, expected[i][3]));
        assert(!strcmp(record->name.user, "alice") && record->port == (!strcmp(expected[i][0], "tcp") ? 80 : 0));
    }
    OuterSSHEndpointRecord *copy = outerssh_endpoint_records_copy(names->records, names->count);
    assert(copy);
    names_free(names);
    assert(!strcmp(copy[4].address, "::1") && !strcmp(copy[4].name.user, "alice") && copy[4].port == 80);
    assert(outerssh_endpoint_records_find(copy, 5, "tcp", "localhost", 80) == &copy[0]);
    free(copy);
    copy = outerssh_endpoint_records_copy(NULL, 0);
    assert(copy);
    free(copy);
    names = parse(NULL, 0);
    assert(names && names->count == 0 && names->records);
    assert(!lookup(names, "unix", "/a", 0));
    names_free(names);
    assert(!outerssh_endpoint_records_find(NULL, 0, "unix", "/a", 0));
}

int main(void) {
    test_icons();
    test_enumeration();
    const char data[] = "alice\0outerssh-endpoints-v2\npipe \\\\.\\pipe\\Example\nAlpha\nPlaintext\n\0"
        "alice\0outerssh-endpoints-v2\r\ntcp localhost 6006\r\n\r\nTensorBoard\r\n"
        "unix /run/user/501/My Editor\n\nEditor\n";
    Names *names = parse(data, sizeof(data));
    assert(names);
    const OuterSSHEndpointName *name = lookup(names, "pipe", "\\\\.\\pipe\\EXAMPLE", 0);
    assert(name && !strcmp(name->user, "alice") && !strcmp(name->app, "Plaintext") && !strcmp(name->container, "Alpha"));
    assert(lookup(names, "tcp", "LOCALHOST", 6006));
    assert(!lookup(names, "tcp", "127.0.0.1", 6006));
    assert(!lookup(names, "tcp", "::1", 6006));
    assert(!lookup(names, "tcp", "127.0.0.2", 6006));
    assert(!lookup(names, "tcp", "localhost", 6007));
    assert(lookup(names, "unix", "/run/user/501/My Editor", 0));
    assert(!lookup(names, "unix", "/run/user/501/my editor", 0));
    names_free(names);
    const char conflict[] = "alice\0outerssh-endpoints-v2\nunix /a\n\nApp\nunix /a\n\nOther\n"
        "tcp 127.0.0.1 3000\n\nApp\ntcp ::1 3000\n\nOther\ntcp LocalHost 4000\n\nApp\ntcp localhost 4000\n\nOther\n";
    names = parse(conflict, sizeof(conflict));
    assert(names && !lookup(names, "unix", "/a", 0));
    assert(!lookup(names, "tcp", "localhost", 4000));
    assert(lookup(names, "tcp", "127.0.0.1", 3000));
    assert(lookup(names, "tcp", "::1", 3000));
    assert(!lookup(names, "tcp", "localhost", 3000));
    assert(names->count == 2);
    names_free(names);
    const char *invalid[] = {
        "alice\0outerssh-endpoints-v1\n", "alice\0outerssh-endpoints-v2\nunix /a\n\n",
        "alice\0outerssh-endpoints-v2\ntcp localhost 65536\n\nApp\n",
        "alice\0outerssh-endpoints-v2\nunix /spoof\nAlpha\nroot\nApp\n",
        "alice\0outerssh-endpoints-v2\nunix relative\n\nApp\n",
        "alice\0outerssh-endpoints-v2\nunix /a\n\nBad\tName\n",
        "alice\0outerssh-endpoints-v2\nunix /a\n\n\xc0\x80\n"
    };
    for (size_t i = 0; i < sizeof(invalid)/sizeof(*invalid); i++)
        assert(!parse(invalid[i], strlen(invalid[i]) + 1 + strlen(invalid[i] + strlen(invalid[i]) + 1) + 1));
    const char scopes[] = "alice\0outerssh-endpoints-v2\nunix /user\nAlpha\nEditor\n\0root\0outerssh-endpoints-v2\nunix /system\n\nEditor\n";
    names = parse(scopes, sizeof(scopes)); assert(names);
    assert(!strcmp(lookup(names, "unix", "/user", 0)->user, "alice"));
    assert(!strcmp(lookup(names, "unix", "/system", 0)->user, "root"));
    names_free(names);
    names = parse(NULL, 0); assert(names); names_free(names);
    assert(!parse(data, sizeof(data) - 1));
    puts("Endpoint names tests passed");
}
