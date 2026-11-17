#include "include/OuterSSH/SSHEndpointNames.h"
#include "SSHEndpointRecord.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _MSC_VER
#define strdup _strdup
#endif

#define MAX_SNAPSHOT (1024u * 1024u)
#define MAX_FILE 65536u
#define MAX_RECORDS 8192u
#define MAX_ENDPOINT 4096u

typedef struct {
    OuterSSHEndpointRecord *entries;
    size_t count;
    const OuterSSHEndpointRecord **distinct;
    size_t distinct_count;
} Snapshot;

static unsigned char ascii_lower(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}
static bool ascii_prefix(const char *text, const char *prefix) {
    while (*prefix) {
        if (ascii_lower((unsigned char)*text++) != (unsigned char)*prefix++) return false;
    }
    return true;
}
static bool text_valid(const char *s, size_t maximum) {
    size_t n = strlen(s);
    if (n > maximum) return false;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned c = *p++;
        if (c < 32 || c == 127) return false;
        if (c < 128) continue;
        unsigned extra, minimum;
        if (c >= 0xc2 && c <= 0xdf) { extra = 1; minimum = 0x80; c &= 31; }
        else if (c >= 0xe0 && c <= 0xef) { extra = 2; minimum = 0x800; c &= 15; }
        else if (c >= 0xf0 && c <= 0xf4) { extra = 3; minimum = 0x10000; c &= 7; }
        else return false;
        while (extra--) { if ((*p & 0xc0) != 0x80) return false; c = (c << 6) | (*p++ & 63); }
        if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff) || (c >= 0x80 && c <= 0x9f)) return false;
    }
    return true;
}
static char *line(char **cursor) {
    if (!*cursor || !**cursor) return NULL;
    char *s = *cursor, *end = strchr(s, '\n');
    if (end) { *end = 0; *cursor = end + 1; } else *cursor = NULL;
    size_t n = strlen(s);
    if (n && s[n - 1] == '\r') s[n - 1] = 0;
    return s;
}
static void entry_free(OuterSSHEndpointRecord *e) {
    free((void *)e->transport); free((void *)e->address);
    free((void *)e->name.container); free((void *)e->name.user); free((void *)e->name.app);
}
static void snapshot_free(Snapshot *names) {
    if (!names) return;
    for (size_t i = 0; i < names->count; i++) entry_free(&names->entries[i]);
    free(names->entries); free(names->distinct); free(names);
}
/* Splits an endpoint line in place: endpoint keeps the transport. */
static bool parse_endpoint(char *endpoint, char **address_out, uint16_t *port_out) {
    char *address = strchr(endpoint, ' ');
    if (!address) return false;
    *address++ = 0;
    uint16_t port = 0;
    if (!strcmp(endpoint, "unix")) { if (*address != '/') return false; }
    else if (!strcmp(endpoint, "pipe")) { if (!ascii_prefix(address, "\\\\.\\pipe\\") || !address[9]) return false; }
    else if (!strcmp(endpoint, "tcp")) {
        char *number = strrchr(address, ' ');
        if (!number) return false;
        *number++ = 0;
        if (!*address || !*number || strspn(number, "0123456789") != strlen(number)) return false;
        unsigned long value = strtoul(number, NULL, 10);
        if (!value || value > 65535 || strpbrk(address, " /\\?#@[]")) return false;
        port = (uint16_t)value;
    } else return false;
    *address_out = address;
    *port_out = port;
    return true;
}
static bool add_file(Snapshot *names, char *file, const char *user) {
    char *cursor = file, *header = line(&cursor);
    if (!header || strcmp(header, "outerssh-endpoints-v2")) return false;
    while (cursor && *cursor) {
        char *endpoint = line(&cursor), *container = line(&cursor), *app = line(&cursor);
        if (!endpoint || !container || !user || !app || !*app ||
            !text_valid(endpoint, MAX_ENDPOINT) || !text_valid(container, 256) ||
            !text_valid(user, 256) || !text_valid(app, 256) || names->count == MAX_RECORDS) return false;
        char *address;
        uint16_t port;
        if (!parse_endpoint(endpoint, &address, &port)) return false;
        OuterSSHEndpointRecord e = {strdup(endpoint), strdup(address), port, {strdup(container), strdup(user), strdup(app)}};
        if (!e.transport || !e.address || !e.name.container || !e.name.user || !e.name.app) { entry_free(&e); return false; }
        OuterSSHEndpointRecord *entries = realloc(names->entries, (names->count + 1) * sizeof(*entries));
        if (!entries) { entry_free(&e); return false; }
        names->entries = entries; entries[names->count++] = e;
    }
    return true;
}
static int ascii_compare(const char *a, const char *b) {
    while (*a && ascii_lower((unsigned char)*a) == ascii_lower((unsigned char)*b)) { a++; b++; }
    return (int)ascii_lower((unsigned char)*a) - (int)ascii_lower((unsigned char)*b);
}
static int endpoint_compare(const OuterSSHEndpointRecord *a, const OuterSSHEndpointRecord *b) {
    int result = strcmp(a->transport, b->transport);
    if (result) return result;
    if (a->port != b->port) return a->port < b->port ? -1 : 1;
    return !strcmp(a->transport, "unix") ? strcmp(a->address, b->address) : ascii_compare(a->address, b->address);
}
static int record_order(const void *left, const void *right) {
    const OuterSSHEndpointRecord *a = *(const OuterSSHEndpointRecord *const *)left;
    const OuterSSHEndpointRecord *b = *(const OuterSSHEndpointRecord *const *)right;
    int result = endpoint_compare(a, b);
    return result ? result : (a < b ? -1 : a > b);
}
static int position_order(const void *left, const void *right) {
    const OuterSSHEndpointRecord *a = *(const OuterSSHEndpointRecord *const *)left;
    const OuterSSHEndpointRecord *b = *(const OuterSSHEndpointRecord *const *)right;
    return a < b ? -1 : a > b;
}
static bool same_name(const OuterSSHEndpointName *a, const OuterSSHEndpointName *b) {
    return !strcmp(a->container, b->container) && !strcmp(a->user, b->user) && !strcmp(a->app, b->app);
}
static bool index_distinct(Snapshot *names) {
    if (!names->count) return true;
    names->distinct = malloc(names->count * sizeof(*names->distinct));
    if (!names->distinct) return false;
    for (size_t i = 0; i < names->count; i++) names->distinct[i] = &names->entries[i];
    qsort(names->distinct, names->count, sizeof(*names->distinct), record_order);
    size_t kept = 0;
    for (size_t start = 0; start < names->count;) {
        size_t end = start + 1;
        bool conflict = false;
        while (end < names->count && !endpoint_compare(names->distinct[start], names->distinct[end])) {
            conflict = conflict || !same_name(&names->distinct[start]->name, &names->distinct[end]->name);
            end++;
        }
        if (!conflict) names->distinct[kept++] = names->distinct[start];
        start = end;
    }
    qsort(names->distinct, kept, sizeof(*names->distinct), position_order);
    names->distinct_count = kept;
    return true;
}
static Snapshot *snapshot_parse(const void *bytes, size_t length) {
    if (length > MAX_SNAPSHOT || (length && !bytes)) return NULL;
    Snapshot *names = calloc(1, sizeof(*names));
    if (!names) return NULL;
    const char *p = bytes;
    while (length) {
        const char *account_end = memchr(p, 0, length);
        if (!account_end || account_end == p || (size_t)(account_end - p) > 256 || !text_valid(p, 256)) goto fail;
        const char *account = p;
        size_t account_length = (size_t)(account_end - p) + 1;
        p += account_length; length -= account_length;
        const char *end = memchr(p, 0, length);
        if (!end || (size_t)(end - p) > MAX_FILE) goto fail;
        size_t n = (size_t)(end - p);
        char *file = malloc(n + 1);
        if (!file) goto fail;
        memcpy(file, p, n); file[n] = 0;
        bool valid = add_file(names, file, account); free(file);
        if (!valid) goto fail;
        p += n + 1; length -= n + 1;
    }
    if (!index_distinct(names)) goto fail;
    return names;
fail:
    snapshot_free(names); return NULL;
}
static OuterSSHEndpointRecord *copy_records(const OuterSSHEndpointRecord *const *sources, const OuterSSHEndpointRecord *records,
    size_t count) {
    if (count > (SIZE_MAX - 1) / sizeof(OuterSSHEndpointRecord)) return NULL;
    size_t total = count * sizeof(OuterSSHEndpointRecord) + 1;
    for (size_t i = 0; i < count; i++) {
        const OuterSSHEndpointRecord *r = sources ? sources[i] : &records[i];
        total += strlen(r->transport) + strlen(r->address) + strlen(r->name.container) +
            strlen(r->name.user) + strlen(r->name.app) + 5;
    }
    OuterSSHEndpointRecord *copies = malloc(total);
    if (!copies) return NULL;
    char *cursor = (char *)(copies + count);
    for (size_t i = 0; i < count; i++) {
        const OuterSSHEndpointRecord *r = sources ? sources[i] : &records[i];
        const char *fields[5] = {r->transport, r->address, r->name.container, r->name.user, r->name.app};
        const char *placed[5];
        for (int field = 0; field < 5; field++) {
            size_t n = strlen(fields[field]) + 1;
            memcpy(cursor, fields[field], n);
            placed[field] = cursor;
            cursor += n;
        }
        copies[i] = (OuterSSHEndpointRecord){placed[0], placed[1], r->port, {placed[2], placed[3], placed[4]}};
    }
    *cursor = 0;
    return copies;
}
bool outersshpriv_endpoint_names_parse(const void *bytes, size_t length, OuterSSHEndpointRecord **records, size_t *count) {
    *records = NULL; *count = 0;
    Snapshot *names = snapshot_parse(bytes, length);
    if (!names) return false;
    OuterSSHEndpointRecord *copies = copy_records(names->distinct, NULL, names->distinct_count);
    size_t copied = names->distinct_count;
    snapshot_free(names);
    if (!copies) return false;
    *records = copies; *count = copied;
    return true;
}
static bool ascii_equal(const char *a, const char *b) {
    while (*a && *b) { if (ascii_lower((unsigned char)*a++) != ascii_lower((unsigned char)*b++)) return false; }
    return *a == *b;
}
const OuterSSHEndpointRecord *outerssh_endpoint_records_find(const OuterSSHEndpointRecord *records, size_t count,
    const char *transport, const char *address, uint16_t port) {
    if (!records || !transport || !address) return NULL;
    for (size_t i = 0; i < count; i++) {
        const OuterSSHEndpointRecord *r = &records[i];
        if (!strcmp(r->transport, transport) && r->port == port &&
            (!strcmp(transport, "unix") ? !strcmp(r->address, address) : ascii_equal(r->address, address))) return r;
    }
    return NULL;
}
OuterSSHEndpointRecord *outerssh_endpoint_records_copy(const OuterSSHEndpointRecord *records, size_t count) {
    if (count && !records) return NULL;
    return copy_records(NULL, records, count);
}

/* Endpoint Records */

char *outersshpriv_endpoint_record_line(const char *transport, const char *address, size_t address_length,
    uint16_t port, size_t *length) {
    if (!transport || !address || address_length == 0 || address_length > MAX_ENDPOINT ||
        memchr(address, 0, address_length)) return NULL;
    bool tcp = !strcmp(transport, "tcp");
    bool lowercase = tcp || !strcmp(transport, "pipe");
    if ((!lowercase && strcmp(transport, "unix")) || tcp != (port != 0)) return NULL;
    size_t prefix = strlen(transport) + 1, capacity = prefix + address_length + 7;
    char *text = malloc(capacity);
    if (!text) return NULL;
    memcpy(text, transport, prefix - 1);
    text[prefix - 1] = ' ';
    for (size_t i = 0; i < address_length; i++)
        text[prefix + i] = lowercase ? (char)ascii_lower((unsigned char)address[i]) : address[i];
    size_t used = prefix + address_length;
    if (tcp) used += (size_t)snprintf(text + used, capacity - used, " %u", (unsigned)port);
    else text[used] = 0;
    char *copy = strdup(text);
    char *parsed_address;
    uint16_t parsed_port;
    bool valid = copy && text_valid(text, MAX_ENDPOINT) && parse_endpoint(copy, &parsed_address, &parsed_port) &&
        parsed_port == port && strlen(parsed_address) == address_length;
    free(copy);
    if (!valid) { free(text); return NULL; }
    if (length) *length = used;
    return text;
}

bool outersshpriv_endpoint_record_parse(char *text, const char **transport, const char **address, uint16_t *port) {
    char *parsed_address;
    if (!text_valid(text, MAX_ENDPOINT) || !parse_endpoint(text, &parsed_address, port)) return false;
    *transport = text;
    *address = parsed_address;
    return true;
}

/* Endpoint Icons */

typedef struct { uint32_t state[8]; uint64_t length; unsigned char block[64]; size_t used; } SHA256;
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static uint32_t rotate(uint32_t value, unsigned count) { return (value >> count) | (value << (32 - count)); }
static void sha256_block(SHA256 *hash) {
    uint32_t w[64], s[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)hash->block[i * 4] << 24 | (uint32_t)hash->block[i * 4 + 1] << 16 |
            (uint32_t)hash->block[i * 4 + 2] << 8 | hash->block[i * 4 + 3];
    for (int i = 16; i < 64; i++)
        w[i] = w[i - 16] + (rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] +
            (rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >> 10));
    memcpy(s, hash->state, sizeof(s));
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = s[7] + (rotate(s[4], 6) ^ rotate(s[4], 11) ^ rotate(s[4], 25)) +
            ((s[4] & s[5]) ^ (~s[4] & s[6])) + sha256_k[i] + w[i];
        uint32_t t2 = (rotate(s[0], 2) ^ rotate(s[0], 13) ^ rotate(s[0], 22)) +
            ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
        memmove(s + 1, s, 7 * sizeof(*s));
        s[4] += t1;
        s[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) hash->state[i] += s[i];
}
static void sha256_update(SHA256 *hash, const unsigned char *bytes, size_t length) {
    hash->length += length;
    while (length--) {
        hash->block[hash->used++] = *bytes++;
        if (hash->used == 64) { sha256_block(hash); hash->used = 0; }
    }
}
static void sha256(const void *bytes, size_t length, unsigned char digest[32]) {
    SHA256 hash = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}, 0, {0}, 0};
    sha256_update(&hash, bytes, length);
    uint64_t bits = hash.length * 8;
    unsigned char padding[72] = {0x80};
    size_t pad = (hash.used < 56 ? 56 : 120) - hash.used;
    for (int i = 0; i < 8; i++) padding[pad + i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(&hash, padding, pad + 8);
    for (int i = 0; i < 32; i++) digest[i] = (unsigned char)(hash.state[i / 4] >> (24 - 8 * (i % 4)));
}

static uint32_t read_be32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint32_t crc32_update(uint32_t crc, const unsigned char *bytes, size_t length) {
    while (length--) {
        crc ^= *bytes++;
        for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    return crc;
}

bool outerssh_endpoint_icon_is_valid(const void *png, size_t length) {
    static const unsigned char signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    const unsigned char *p = png;
    if (!png || length < 8 || length > OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES || memcmp(p, signature, 8)) return false;
    size_t offset = 8;
    bool header = false, data = false;
    while (offset + 12 <= length) {
        uint32_t chunk = read_be32(p + offset);
        const unsigned char *type = p + offset + 4;
        if (chunk > length - offset - 12) return false;
        for (int i = 0; i < 4; i++)
            if (!((type[i] >= 'A' && type[i] <= 'Z') || (type[i] >= 'a' && type[i] <= 'z'))) return false;
        if (crc32_update(0xffffffffu, type, 4 + (size_t)chunk) ^ 0xffffffffu ^ read_be32(type + 4 + chunk)) return false;
        if (!header) {
            if (memcmp(type, "IHDR", 4) || chunk != 13) return false;
            uint32_t width = read_be32(type + 4), height = read_be32(type + 8);
            if (!width || !height || width > OUTERSSH_ENDPOINT_ICON_MAXIMUM_DIMENSION ||
                height > OUTERSSH_ENDPOINT_ICON_MAXIMUM_DIMENSION) return false;
            header = true;
        } else if (!memcmp(type, "IHDR", 4)) {
            return false;
        } else if (!memcmp(type, "IDAT", 4)) {
            data = true;
        } else if (!memcmp(type, "IEND", 4)) {
            return chunk == 0 && data && offset + 12 == length;
        }
        offset += 12 + (size_t)chunk;
    }
    return false;
}

bool outerssh_endpoint_icon_file_name(const char *transport, const char *address, size_t address_length,
    uint16_t port, char name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY]) {
    size_t length;
    char *text = outersshpriv_endpoint_record_line(transport, address, address_length, port, &length);
    if (!text) return false;
    unsigned char digest[32];
    sha256(text, length, digest);
    free(text);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        name[i * 2] = hex[digest[i] >> 4];
        name[i * 2 + 1] = hex[digest[i] & 15];
    }
    memcpy(name + 64, ".png", 5);
    return true;
}

#ifndef _WIN32
#include "../OuterSSHHelper/EndpointNamesRead.h"
#include "../OuterSSHHelper/EndpointIconsLocal.h"
#endif
