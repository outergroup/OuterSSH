#include "SSHTestReactor.h"
#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include "olibssh/key_exchange_internal.h"
#include "olibssh/key_exchange.h"
#include "SSHReactorReadInternal.h"
#include "olibssh/handshake.h"
#if !OUTERSSH_APPLE_CRYPTO
#include "olibssh/libssh2/cipher-chachapoly.h"
#endif

#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

static int fail_random;
static int test_random(unsigned char *buffer, size_t length)
{
    return fail_random ? -1 : _libssh2_random(buffer, length);
}

// Inject cookie failure without adding a test hook to the library API.
#undef _libssh2_random
#define _libssh2_random(buffer, length) test_random(buffer, length)
#include "olibssh/key_exchange.c"
#undef _libssh2_random

#ifdef SSH_REKEY_REACTOR_TEST
static unsigned completed_exchanges;
static void assert_exchange_can_advance(void);
static int observed_read(LIBSSH2_SESSION *session, SSHReactor *reactor);
static OLIBSSHKeyExchangeStep observed_advance(
    LIBSSH2_SESSION *session, OLIBSSHKeyExchange *exchange)
{
    assert_exchange_can_advance();
    OLIBSSHKeyExchangeStep before = exchange->step;
    OLIBSSHKeyExchangeStep after = olibssh_key_exchange_advance(session, exchange);
    if(before != OLIBSSH_KEY_EXCHANGE_COMPLETE &&
       after == OLIBSSH_KEY_EXCHANGE_COMPLETE)
        completed_exchanges++;
    return after;
}
#define olibssh_key_exchange_advance observed_advance
#define olibssh_transport_read observed_read
#include "SSHReactor.c"
#include "SSHReactorRelay.c"
#include "SSHReactorOutput.c"
#include "SSHReactorKeyExchange.c"
#undef olibssh_key_exchange_advance
#undef olibssh_transport_read

static SSHReactor *active_reactor;
static unsigned data_reads_during_write, kex_reads_during_write;

static void assert_exchange_can_advance(void)
{
    if(active_reactor) {
        const SSHWriteAction *head = outersshpriv_reactor_const_write_action_at(active_reactor, 0);
        assert(!head || !head->must_resume);
    }
}

static int observed_read(LIBSSH2_SESSION *session, SSHReactor *reactor)
{
    const SSHWriteAction *head = outersshpriv_reactor_const_write_action_at(active_reactor, 0);
    bool resuming_write = head && head->must_resume;
    int rc = olibssh_transport_read(session, reactor);
    if(resuming_write && rc >= 0) {
        data_reads_during_write += (rc == SSH_MSG_CHANNEL_DATA || rc == SSH_MSG_CHANNEL_EXTENDED_DATA);
        kex_reads_during_write += rc == SSH_MSG_KEXINIT;
    }
    return rc;
}
#endif

typedef struct {
    LIBSSH2_SESSION *session;
    OLIBSSHKeyExchange exchange;
} ExchangeReadContext;

#ifndef SSH_REKEY_REACTOR_TEST
typedef struct {
    LIBSSH2_SESSION *session;
    unsigned deliveries;
} DirectReadTest;

void outersshpriv_reactor_received_authentication(SSHReactor *reactor,
    const unsigned char *packet, size_t length)
{ (void)reactor; (void)packet; (void)length; abort(); }

void outersshpriv_reactor_received_service_accept(SSHReactor *reactor,
    const unsigned char *packet, size_t length)
{
    (void)reactor; (void)packet; (void)length;
    abort();
}

static void check_completed_packet(DirectReadTest *test)
{
    assert(test->session->packet.payload == NULL);
    assert(test->session->packet.total_num == 0);
}

void outersshpriv_reactor_received_channel_data(SSHReactor *reactor,
    uint32_t channel_id, uint32_t stream_id,
    const unsigned char *bytes, size_t byte_count)
{
    DirectReadTest *test = (DirectReadTest *)reactor;
    check_completed_packet(test);
    assert(channel_id == 7);
    assert(byte_count == 3);
    assert(stream_id == test->deliveries);
    assert(memcmp(bytes, test->deliveries == 0 ? "abc" : "def", byte_count) == 0);
    test->deliveries++;
}
void outersshpriv_reactor_received_channel_eof(SSHReactor *reactor,
    uint32_t channel_id)
{
    (void)reactor;
    (void)channel_id;
    abort();
}
void outersshpriv_reactor_received_channel_close(SSHReactor *reactor,
    uint32_t channel_id)
{
    (void)reactor;
    (void)channel_id;
    DirectReadTest *test = (DirectReadTest *)reactor;
    check_completed_packet(test);
    assert(channel_id == 7 && test->deliveries == 2);
}
void outersshpriv_reactor_received_channel_window_adjust(SSHReactor *reactor,
    uint32_t channel_id, uint32_t adjustment)
{
    (void)reactor;
    (void)channel_id;
    (void)adjustment;
    abort();
}
void outersshpriv_reactor_received_channel_open_confirmation(SSHReactor *reactor,
    uint32_t channel_id, uint32_t remote_id, uint32_t window_size, uint32_t packet_size)
{
    (void)reactor;
    (void)channel_id;
    (void)remote_id;
    (void)window_size;
    (void)packet_size;
    abort();
}
void outersshpriv_reactor_received_channel_open_failure(SSHReactor *reactor,
    uint32_t channel_id, uint32_t value)
{
    (void)reactor;
    (void)channel_id;
    (void)value;
    abort();
}
void outersshpriv_reactor_received_channel_request_success(SSHReactor *reactor,
    uint32_t channel_id)
{
    (void)reactor;
    (void)channel_id;
    abort();
}
void outersshpriv_reactor_received_channel_request_failure(SSHReactor *reactor,
    uint32_t channel_id)
{
    (void)reactor;
    (void)channel_id;
    abort();
}
void outersshpriv_reactor_received_channel_exit_status(SSHReactor *reactor,
    uint32_t channel_id, uint32_t value)
{
    (void)reactor;
    (void)channel_id;
    (void)value;
    abort();
}
bool outersshpriv_reactor_reject_channel_request(SSHReactor *reactor, uint32_t channel_id)
{
    (void)reactor;
    (void)channel_id;
    abort();
}
bool outersshpriv_reactor_queue_protocol_response(SSHReactor *reactor,
    const void *bytes, size_t byte_count)
{
    (void)reactor;
    (void)bytes;
    (void)byte_count;
    abort();
}
void outersshpriv_reactor_received_global_response(SSHReactor *reactor, bool succeeded)
{
    (void)reactor;
    (void)succeeded;
    abort();
}
void outersshpriv_reactor_received_key_exchange_packet(SSHReactor *reactor,
    unsigned char *packet, size_t length)
{
    ExchangeReadContext *context = (ExchangeReadContext *)reactor;
    assert(olibssh_key_exchange_receive(context->session, &context->exchange,
                                       packet, length) == 0);
}
#endif

typedef enum {
    INITIAL_HANDSHAKE, ADVANCE, READ_PACKET, WRITE_PACKET, REACTOR_IO
} Phase;
static Phase phase;
static unsigned send_calls, receive_calls, blocked_sends, partial_sends;
static int fragment_io;
static int capture_send;
static int fail_send;
static size_t live_allocations;
static struct {
    void *pointer;
    size_t size;
    void *trace[16];
    int trace_count;
} allocations[4096];

static void assert_no_allocations(void)
{
    for(size_t i = 0; i < 4096; i++) {
        if(allocations[i].pointer) {
            fprintf(stderr, "leaked %zu bytes:\n", allocations[i].size);
            backtrace_symbols_fd(allocations[i].trace, allocations[i].trace_count, 2);
        }
    }
    assert(live_allocations == 0);
}

static void *tracked_alloc(size_t size, void **abstract)
{
    (void)abstract;
    void *allocation = malloc(size);
    if(allocation) {
        live_allocations++;
        size_t i = 0;
        while(i < 4096 && allocations[i].pointer)
            i++;
        assert(i < 4096);
        allocations[i].pointer = allocation;
        allocations[i].size = size;
        allocations[i].trace_count = backtrace(allocations[i].trace, 16);
    }
    return allocation;
}

static void tracked_free(void *allocation, void **abstract)
{
    (void)abstract;
    if(allocation) {
        assert(live_allocations > 0);
        live_allocations--;
        size_t i = 0;
        while(i < 4096 && allocations[i].pointer != allocation)
            i++;
        assert(i < 4096);
        allocations[i].pointer = NULL;
        free(allocation);
    }
}

static void *tracked_realloc(void *allocation, size_t size, void **abstract)
{
    if(!allocation)
        return tracked_alloc(size, abstract);
    if(size == 0) {
        tracked_free(allocation, abstract);
        return NULL;
    }
    size_t i = 0;
    while(i < 4096 && allocations[i].pointer != allocation)
        i++;
    assert(i < 4096);
    void *replacement = realloc(allocation, size);
    if(replacement) {
        allocations[i].pointer = replacement;
        allocations[i].size = size;
    }
    return replacement;
}

static ssize_t checked_send(libssh2_socket_t socket, const void *buffer,
                            size_t length, int flags, void **abstract)
{
    (void)abstract;
    assert(phase == INITIAL_HANDSHAKE || phase == WRITE_PACKET ||
           phase == REACTOR_IO);
    send_calls++;
    if(fail_send)
        return -ECONNRESET;
    if(fragment_io && (send_calls % 3) == 0) {
        blocked_sends++;
        return -EAGAIN;
    }
    if(fragment_io && length > 17) {
        length = 17;
        partial_sends++;
    }
    if(capture_send)
        return (ssize_t)length;
    ssize_t rc = otsocket_send(socket, buffer, length, flags);
    return rc < 0 ? -errno : rc;
}

static ssize_t checked_recv(libssh2_socket_t socket, void *buffer,
                            size_t length, int flags, void **abstract)
{
    (void)abstract;
    assert(phase == INITIAL_HANDSHAKE || phase == READ_PACKET ||
           phase == REACTOR_IO);
    receive_calls++;
    if(fragment_io && length > 23)
        length = 23;
    ssize_t rc = otsocket_recv(socket, buffer, length, flags);
    return rc < 0 ? -errno : rc;
}

static LIBSSH2_SESSION *new_session(void)
{
    LIBSSH2_SESSION *session = olibssh_session_init_ex(
        tracked_alloc, tracked_free, tracked_realloc, NULL);
    assert(session);
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND,
                                  (libssh2_cb_generic *)checked_send);
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_RECV,
                                  (libssh2_cb_generic *)checked_recv);
    return session;
}

typedef struct {
    unsigned char bytes[65536];
    size_t length, offset, read_limit, write_limit;
    unsigned writes, encrypted_calls, decrypted_calls, delivered;
    size_t largest_encrypt, largest_decrypt;
    const unsigned char *expected;
    size_t expected_length;
    const LIBSSH2_CRYPT_METHOD *cipher;
    LIBSSH2_SESSION *sender;
} CipherTest;

static CipherTest cipher_test;

static ssize_t cipher_test_send(libssh2_socket_t socket, const void *buffer,
                                size_t length, int flags, void **abstract)
{
    (void)socket; (void)flags; (void)abstract;
    if(++cipher_test.writes % 3 == 0)
        return -EAGAIN;
    if(length > cipher_test.write_limit)
        length = cipher_test.write_limit;
    assert(length <= sizeof(cipher_test.bytes) - cipher_test.length);
    memcpy(cipher_test.bytes + cipher_test.length, buffer, length);
    cipher_test.length += length;
    return (ssize_t)length;
}

static ssize_t cipher_test_recv(libssh2_socket_t socket, void *buffer,
                                size_t length, int flags, void **abstract)
{
    (void)socket; (void)flags; (void)abstract;
    size_t available = cipher_test.length - cipher_test.offset;
    if(!available)
        return -EAGAIN;
    if(length > available)
        length = available;
    if(length > cipher_test.read_limit)
        length = cipher_test.read_limit;
    memcpy(buffer, cipher_test.bytes + cipher_test.offset, length);
    cipher_test.offset += length;
    return (ssize_t)length;
}

static int counted_cipher(LIBSSH2_SESSION *session, unsigned int seqno,
                          unsigned char *buffer, size_t length, void **abstract,
                          int firstlast)
{
    if(session == cipher_test.sender) {
        cipher_test.encrypted_calls++;
        if(length > cipher_test.largest_encrypt)
            cipher_test.largest_encrypt = length;
    } else {
        cipher_test.decrypted_calls++;
        if(length > cipher_test.largest_decrypt)
            cipher_test.largest_decrypt = length;
    }
    return cipher_test.cipher->crypt(session, seqno, buffer, length,
                                    abstract, firstlast);
}

static LIBSSH2_IGNORE_FUNC(cipher_test_ignore)
{
    (void)session; (void)abstract;
    assert((size_t)message_len == cipher_test.expected_length - 1);
    assert(memcmp(message, cipher_test.expected + 1, (size_t)message_len) == 0);
    cipher_test.delivered++;
}

static void test_aead_packets(const char *name, size_t read_limit, int corruption)
{
    const LIBSSH2_CRYPT_METHOD **methods = libssh2_crypt_methods();
    while(*methods && strcmp((*methods)->name, name))
        methods++;
    assert(*methods);
    cipher_test = (CipherTest){.cipher = *methods, .read_limit = read_limit,
                               .write_limit = 17};
    LIBSSH2_CRYPT_METHOD cipher = **methods;
    cipher.crypt = counted_cipher;
    LIBSSH2_SESSION *sender = new_session(), *receiver = new_session();
    cipher_test.sender = sender;
    sender->state = receiver->state = LIBSSH2_STATE_NEWKEYS;
    sender->socket_state = receiver->socket_state = LIBSSH2_SOCKET_CONNECTED;
    sender->local.crypt = receiver->remote.crypt = &cipher;
    sender->local.mac = receiver->remote.mac = _libssh2_mac_override(&cipher);
    assert(sender->local.mac ||
           (cipher.flags & LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET));
    unsigned char iv[12] = {0}, key[64];
    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    int free_iv, free_key;
    assert(cipher.init(sender, &cipher, iv, &free_iv, key, &free_key, 1,
                       &sender->local.crypt_abstract) == 0);
    assert(cipher.init(receiver, &cipher, iv, &free_iv, key, &free_key, 0,
                       &receiver->remote.crypt_abstract) == 0);
    libssh2_session_callback_set2(sender, LIBSSH2_CALLBACK_SEND,
                                  (libssh2_cb_generic *)cipher_test_send);
    libssh2_session_callback_set2(receiver, LIBSSH2_CALLBACK_RECV,
                                  (libssh2_cb_generic *)cipher_test_recv);
    libssh2_session_callback_set2(receiver, LIBSSH2_CALLBACK_IGNORE,
                                  (libssh2_cb_generic *)cipher_test_ignore);
    const size_t lengths[] = {5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1024, 32768};
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        unsigned char payload[32768];
        size_t length = corruption ? sizeof(payload) : lengths[i];
        payload[0] = SSH_MSG_IGNORE;
        _libssh2_htonu32(payload + 1, (uint32_t)(length - 5));
        for(size_t j = 5; j < length; j++)
            payload[j] = (unsigned char)(j * 73 + i);
        cipher_test.length = cipher_test.offset = 0;
        cipher_test.encrypted_calls = cipher_test.decrypted_calls = 0;
        cipher_test.largest_encrypt = cipher_test.largest_decrypt = 0;
        cipher_test.delivered = 0;
        cipher_test.expected = payload;
        cipher_test.expected_length = length;
        int rc = olibssh_transport_write(sender, payload, length, NULL, 0);
        unsigned attempts = 0;
        while(rc == LIBSSH2_ERROR_EAGAIN) {
            rc = olibssh_transport_resume_write(sender);
            assert(++attempts < 10000);
        }
        assert(rc == 0);
        assert(cipher_test.encrypted_calls ==
               (cipher.flags & LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET ? 1u : 2u));
        assert(cipher_test.largest_encrypt >= length);
        if(corruption)
            cipher_test.bytes[corruption == 1 ? 20 : cipher_test.length - 1] ^= 1;
        attempts = 0;
        do {
            rc = olibssh_transport_read(receiver, NULL);
            assert(++attempts < 100000);
        } while(rc == LIBSSH2_ERROR_EAGAIN);
        if(corruption) {
            assert(rc == LIBSSH2_ERROR_DECRYPT);
            assert(cipher_test.delivered == 0);
            break;
        }
        assert(rc == SSH_MSG_IGNORE);
        assert(cipher_test.delivered == 1);
        assert(cipher_test.offset == cipher_test.length);
        if(length >= 1024 && read_limit >= 4096) {
            assert(cipher_test.largest_decrypt > 16);
            assert(cipher_test.decrypted_calls < length / 16);
        }
    }
    assert(olibssh_session_free(sender) == 0);
    assert(olibssh_session_free(receiver) == 0);
    assert_no_allocations();
}

#ifndef SSH_REKEY_REACTOR_TEST
static void test_direct_channel_packets(void)
{
    cipher_test = (CipherTest){.read_limit = 65536, .write_limit = 17};
    LIBSSH2_SESSION *sender = new_session(), *receiver = new_session();
    sender->socket_state = receiver->socket_state = LIBSSH2_SOCKET_CONNECTED;
    libssh2_session_callback_set2(sender, LIBSSH2_CALLBACK_SEND,
        (libssh2_cb_generic *)cipher_test_send);
    libssh2_session_callback_set2(receiver, LIBSSH2_CALLBACK_RECV,
        (libssh2_cb_generic *)cipher_test_recv);
    const unsigned char packets[][16] = {
        {SSH_MSG_CHANNEL_DATA, 0, 0, 0, 7, 0, 0, 0, 3, 'a', 'b', 'c'},
        {SSH_MSG_CHANNEL_EXTENDED_DATA, 0, 0, 0, 7, 0, 0, 0, 1,
            0, 0, 0, 3, 'd', 'e', 'f'},
        {SSH_MSG_CHANNEL_CLOSE, 0, 0, 0, 7},
        {SSH_MSG_UNIMPLEMENTED, 0, 0, 0, 0},
        {255},
    };
    const size_t lengths[] = {12, 16, 5, 5, 1};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        int rc = olibssh_transport_write(sender, packets[i], lengths[i], NULL, 0);
        unsigned attempts = 0;
        while (rc == LIBSSH2_ERROR_EAGAIN) {
            rc = olibssh_transport_resume_write(sender);
            assert(++attempts < 10000);
        }
        assert(rc == 0);
    }
    DirectReadTest test = {.session = receiver};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        int rc = olibssh_transport_read(receiver, (SSHReactor *)&test);
        assert(rc == packets[i][0]);
    }
    assert(test.deliveries == 2);
    assert(olibssh_transport_read(receiver, (SSHReactor *)&test) == LIBSSH2_ERROR_EAGAIN);
    assert(olibssh_session_free(sender) == 0);
    assert(olibssh_session_free(receiver) == 0);
    assert_no_allocations();
}
#endif

static void test_initial_strict_packet_order(void)
{
    for (unsigned scenario = 0; scenario < 2; scenario++) {
        cipher_test = (CipherTest){.read_limit = 65536, .write_limit = 65536};
        LIBSSH2_SESSION *sender = new_session(), *receiver = new_session();
        assert(receiver->state & LIBSSH2_STATE_INITIAL_KEX);
        receiver->kex_strict = scenario == 0;
        receiver->remote.seqno = scenario == 1;
        receiver->fullpacket_required_type = scenario == 0 ? SSH_MSG_NEWKEYS : SSH_MSG_KEXINIT;
        libssh2_session_callback_set2(sender, LIBSSH2_CALLBACK_SEND,
            (libssh2_cb_generic *)cipher_test_send);
        libssh2_session_callback_set2(receiver, LIBSSH2_CALLBACK_RECV,
            (libssh2_cb_generic *)cipher_test_recv);
        static const char strict[] = "kex-strict-s-v00@openssh.com";
        unsigned char packet[21 + sizeof(strict) - 1] = {0};
        size_t length;
        if (scenario == 0) {
            packet[0] = SSH_MSG_IGNORE;
            length = 5;
        } else {
            packet[0] = SSH_MSG_KEXINIT;
            _libssh2_htonu32(packet + 17, sizeof(strict) - 1);
            memcpy(packet + 21, strict, sizeof(strict) - 1);
            length = sizeof(packet);
        }
        int rc = olibssh_transport_write(sender, packet, length, NULL, 0);
        while (rc == LIBSSH2_ERROR_EAGAIN)
            rc = olibssh_transport_resume_write(sender);
        assert(rc == 0);
        assert(olibssh_transport_read(receiver, NULL) == LIBSSH2_ERROR_SOCKET_DISCONNECT);
        assert(receiver->socket_state == LIBSSH2_SOCKET_DISCONNECTED);
        assert(olibssh_session_free(sender) == 0);
        assert(olibssh_session_free(receiver) == 0);
        assert_no_allocations();
    }
    puts("PASS: strict initial exchange rejects unexpected packets and a non-first KEXINIT");
}

#if !OUTERSSH_APPLE_CRYPTO
static void test_chacha_packet_vector(void)
{
    // OpenSSH-format packet produced by the retained upstream implementation:
    // key bytes 0..63, sequence 0x01020304, length 65, payload byte i * 73.
    static const unsigned char expected[] = {
        0xbc, 0x79, 0x80, 0x3a, 0xb2, 0xaf, 0xaa, 0x4d, 0x93, 0x80, 0xfc, 0x8a,
        0xb8, 0xd8, 0xda, 0xbb, 0x38, 0x99, 0x78, 0x1f, 0xb5, 0xd0, 0x52, 0x58,
        0xeb, 0x98, 0x07, 0x6d, 0x71, 0x37, 0xc2, 0x7d, 0x01, 0x33, 0x9d, 0x23,
        0x24, 0x50, 0xf6, 0x5e, 0x4d, 0xc1, 0x03, 0x02, 0x4e, 0xd7, 0x35, 0xfc,
        0xcb, 0x11, 0x9c, 0x84, 0x5a, 0x52, 0xdd, 0xaa, 0x33, 0x0c, 0x84, 0xb8,
        0xf4, 0x27, 0x91, 0xf3, 0x82, 0x31, 0x99, 0x36, 0x3e, 0xe3, 0xe5, 0x84,
        0xce, 0x35, 0xa0, 0xcd, 0x35, 0x4a, 0x2e, 0x31, 0x80, 0xdd, 0x0c, 0x9b,
        0x5d,
    };
    unsigned char key[64], plaintext[69], packet[sizeof(expected)];
    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    _libssh2_htonu32(plaintext, 65);
    for(size_t i = 4; i < sizeof(plaintext); i++)
        plaintext[i] = (unsigned char)(i * 73);
    struct chachapoly_ctx ctx;
    assert(olibssh_chachapoly_init(&ctx, key, sizeof(key)) == 0);
    const unsigned sequences[] = {0x01020304, UINT32_MAX, 0, 1, 0x01020304};
    for(size_t i = 0; i < sizeof(sequences) / sizeof(sequences[0]); i++) {
        assert(olibssh_chachapoly_crypt(&ctx, sequences[i], packet, plaintext, 65, 4, 1) == 0);
        if(sequences[i] == 0x01020304)
            assert(memcmp(packet, expected, sizeof(expected)) == 0);
        unsigned length = 0;
        assert(olibssh_chachapoly_get_length(&ctx, &length, sequences[i], packet, 3) != 0);
        assert(olibssh_chachapoly_get_length(&ctx, &length, sequences[i], packet, 4) == 0);
        assert(length == 65);
        assert(olibssh_chachapoly_crypt(&ctx, sequences[i], packet, packet, 65, 4, 0) == 0);
        assert(memcmp(packet, plaintext, sizeof(plaintext)) == 0);
    }
    // Corrupted length, payload, and tag must leave the ciphertext untouched.
    const size_t corruptions[] = {0, 20, sizeof(expected) - 1};
    for(size_t i = 0; i < sizeof(corruptions) / sizeof(corruptions[0]); i++) {
        memcpy(packet, expected, sizeof(packet));
        packet[corruptions[i]] ^= 1;
        unsigned char corrupted[sizeof(packet)];
        memcpy(corrupted, packet, sizeof(packet));
        assert(olibssh_chachapoly_crypt(&ctx, 0x01020304, packet, packet, 65, 4, 0) != 0);
        assert(memcmp(packet, corrupted, sizeof(packet)) == 0);
    }
    memcpy(packet, expected, sizeof(packet));
    assert(olibssh_chachapoly_crypt(&ctx, 0x01020305, packet, packet, 65, 4, 0) != 0);
    assert(memcmp(packet, expected, sizeof(packet)) == 0);
    olibssh_chachapoly_cleanup(&ctx);
    assert(olibssh_chachapoly_init(&ctx, key, sizeof(key) - 1) != 0);
    olibssh_chachapoly_cleanup(&ctx);
    puts("PASS: ChaCha20 reference packet, sequence reset, encrypted length, and rejection before decryption");
}

#endif

static void test_aead_transport(void)
{
    const char *ciphers[] = {"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
#if !OUTERSSH_APPLE_CRYPTO
                             "chacha20-poly1305@openssh.com",
#endif
    };
    const size_t fragments[] = {1, 4, 15, 16, 17, 23, 4096, 65536};
    for(size_t i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); i++) {
        for(size_t j = 0; j < sizeof(fragments) / sizeof(fragments[0]); j++)
            test_aead_packets(ciphers[i], fragments[j], 0);
        for(int corruption = 1; corruption <= 2; corruption++) {
            test_aead_packets(ciphers[i], 23, corruption);
            test_aead_packets(ciphers[i], 65536, corruption);
        }
    }
    puts("PASS: enabled AEAD ciphers packet integrity, fragmented reads, write retries, and authentication rejection");
}

static void test_no_implicit_io(void)
{
    LIBSSH2_SESSION *session = new_session();
    session->socket_state = LIBSSH2_SOCKET_CONNECTED;
    OLIBSSHKeyExchange exchange = {0};
    phase = ADVANCE;
    unsigned sends = send_calls, receives = receive_calls;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    assert(send_calls == sends && receive_calls == receives);
    assert(exchange.packet[0] == SSH_MSG_KEXINIT);
    assert(exchange.packet_length > 17);
    const unsigned char *packet = exchange.packet;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    assert(exchange.packet == packet);

    unsigned char *input = LIBSSH2_ALLOC(session, 1);
    input[0] = SSH_MSG_KEXINIT;
    assert(olibssh_key_exchange_receive(session, &exchange, input, 1) == 0);
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    assert(exchange.input_packet == input);
    assert(send_calls == sends && receive_calls == receives);
    olibssh_key_exchange_cleanup(session, &exchange);
    assert(olibssh_session_free(session) == 0);
    assert(live_allocations == 0);
}

static void test_cookie_failure(void)
{
    LIBSSH2_SESSION *session = new_session();
    session->socket_state = LIBSSH2_SOCKET_CONNECTED;
    OLIBSSHKeyExchange exchange = {0};
    phase = ADVANCE;
    fail_random = 1;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_FAILED);
    assert(libssh2_session_last_errno(session) == LIBSSH2_ERROR_RANDGEN);
    fail_random = 0;
    olibssh_key_exchange_cleanup(session, &exchange);
    assert(olibssh_session_free(session) == 0);
    assert(live_allocations == 0);
}

static void test_interrupted_startup_exchange(void)
{
    for(int stop_during_write = 0; stop_during_write < 2; stop_during_write++) {
        LIBSSH2_SESSION *session = new_session();
        OLIBSSHKeyExchange exchange = {0};
        session->socket_state = LIBSSH2_SOCKET_CONNECTED;
        capture_send = fragment_io = 1;
        phase = ADVANCE;
        assert(olibssh_key_exchange_advance(session, &exchange) ==
               OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
        phase = WRITE_PACKET;
        int rc;
        do {
            rc = olibssh_key_exchange_write(session, &exchange);
            assert(rc == 0 || rc == LIBSSH2_ERROR_EAGAIN);
        } while(!stop_during_write && rc == LIBSSH2_ERROR_EAGAIN);
        if(!stop_during_write) {
            phase = ADVANCE;
            assert(olibssh_key_exchange_advance(session, &exchange) ==
                   OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT);
        }
        olibssh_key_exchange_cleanup(session, &exchange);
        assert(olibssh_session_free(session) == 0);
        assert_no_allocations();
        capture_send = fragment_io = 0;
    }
}

static unsigned exchange_deliveries;

static int consume_test_exchange_packet(LIBSSH2_SESSION *session,
    OLIBSSHKeyExchange *exchange)
{
    unsigned char *packet = exchange->state->key_state.data;
    assert(packet && packet[0] == SSH_MSG_KEXDH_REPLY);
    assert(exchange->state->key_state.data_len == 1);
    LIBSSH2_FREE(session, packet);
    exchange->state->key_state.data = NULL;
    exchange_deliveries++;
    exchange->step = OLIBSSH_KEY_EXCHANGE_COMPLETE;
    return 0;
}

static void test_exchange_delivery(void)
{
    for(int scenario = 0; scenario < 6; scenario++) {
        LIBSSH2_SESSION *session = new_session();
        OLIBSSHKeyExchange exchange = {0};
        unsigned char *packet = LIBSSH2_ALLOC(session, 1);
        packet[0] = SSH_MSG_KEXINIT;
        if(scenario == 0) {
            assert(olibssh_key_exchange_receive(session, &exchange, packet, 1) == 0);
            assert(exchange.input_packet == packet && exchange.state == NULL);
            unsigned char *duplicate = LIBSSH2_ALLOC(session, 1);
            duplicate[0] = SSH_MSG_KEXINIT;
            assert(olibssh_key_exchange_receive(session, &exchange, duplicate, 1) ==
                   LIBSSH2_ERROR_PROTO);
            assert(exchange.input_packet == packet);
        }
        else if(scenario == 1 || scenario == 2) {
            packet[0] = SSH_MSG_NEWKEYS;
            assert(olibssh_key_exchange_receive(session, &exchange, packet,
                                                scenario == 1 ? 1 : 0) ==
                   LIBSSH2_ERROR_PROTO);
            assert(exchange.input_packet == NULL);
        }
        else {
            exchange.state = LIBSSH2_ALLOC(session, sizeof(*exchange.state));
            *exchange.state = (OLIBSSHKeyExchangeState){.owner = &exchange};
            expect_exchange_packet(&exchange, SSH_MSG_KEXDH_REPLY,
                &exchange.state->key_state.data, &exchange.state->key_state.data_len,
                consume_test_exchange_packet);
            exchange_deliveries = 0;
            if(scenario == 3) {
                packet[0] = SSH_MSG_NEWKEYS;
                assert(olibssh_key_exchange_receive(session, &exchange, packet, 1) == 0);
                assert(olibssh_key_exchange_advance(session, &exchange) ==
                       OLIBSSH_KEY_EXCHANGE_FAILED);
                assert(exchange.error == LIBSSH2_ERROR_PROTO);
                assert(exchange_deliveries == 0);
            }
            else {
                if(scenario == 4) {
                    session->burn_optimistic_kexinit = 1;
                    packet[0] = SSH_MSG_KEXDH_INIT;
                    assert(olibssh_key_exchange_receive(session, &exchange, packet, 1) == 0);
                    assert(olibssh_key_exchange_advance(session, &exchange) ==
                           OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT);
                    assert(!session->burn_optimistic_kexinit && !exchange.input_packet);
                    assert(exchange_deliveries == 0);
                    packet = LIBSSH2_ALLOC(session, 1);
                }
                packet[0] = SSH_MSG_KEXDH_REPLY;
                assert(olibssh_key_exchange_receive(session, &exchange, packet, 1) == 0);
                assert(olibssh_key_exchange_advance(session, &exchange) ==
                       OLIBSSH_KEY_EXCHANGE_COMPLETE);
                assert(olibssh_key_exchange_advance(session, &exchange) ==
                       OLIBSSH_KEY_EXCHANGE_COMPLETE);
                assert(exchange_deliveries == 1);
            }
        }
        olibssh_key_exchange_cleanup(session, &exchange);
        assert(olibssh_session_free(session) == 0);
        assert_no_allocations();
    }
}

static void test_exchange_write_continuation(void)
{
    LIBSSH2_SESSION *session = new_session();
    session->socket_state = LIBSSH2_SOCKET_CONNECTED;
    OLIBSSHKeyExchange exchange = {0};
    phase = ADVANCE;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    assert(exchange.state->written == kexinit_written);
    capture_send = fragment_io = 1;
    send_calls = 2;
    unsigned attempts = 0;
    for(;;) {
        phase = WRITE_PACKET;
        int rc = olibssh_key_exchange_write(session, &exchange);
        assert(rc == 0 || rc == LIBSSH2_ERROR_EAGAIN);
        if(rc == 0)
            break;
        assert(++attempts < 10000);
        phase = ADVANCE;
        assert(olibssh_key_exchange_advance(session, &exchange) ==
               OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
        assert(exchange.state->written == kexinit_written);
        assert(exchange.state->received == NULL);
    }
    assert(attempts > 1);
    assert(exchange.state->written == NULL && exchange.state->next == kexinit_written);
    assert(exchange.packet == NULL && session->packet.ototal_num == 0);
    phase = ADVANCE;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT);
    assert(exchange.state->received == kexinit_received);
    assert(session->fullpacket_required_type == SSH_MSG_KEXINIT);
    unsigned char *packet = LIBSSH2_ALLOC(session, 1);
    packet[0] = SSH_MSG_KEXINIT;
    assert(olibssh_key_exchange_receive(session, &exchange, packet, 1) == 0);
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_FAILED);
    assert(exchange.error == LIBSSH2_ERROR_KEX_FAILURE);
    olibssh_key_exchange_cleanup(session, &exchange);
    assert(olibssh_session_free(session) == 0);
    assert_no_allocations();
    capture_send = fragment_io = 0;
}

static void test_exchange_write_failure(void)
{
    LIBSSH2_SESSION *session = new_session();
    session->socket_state = LIBSSH2_SOCKET_CONNECTED;
    OLIBSSHKeyExchange exchange = {0};
    phase = ADVANCE;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    capture_send = fragment_io = 1;
    send_calls = 0;
    phase = WRITE_PACKET;
    assert(olibssh_key_exchange_write(session, &exchange) == LIBSSH2_ERROR_EAGAIN);
    assert(session->packet.ototal_num > 0);
    fail_send = 1;
    assert(olibssh_key_exchange_write(session, &exchange) == LIBSSH2_ERROR_SOCKET_SEND);
    assert(exchange.step == OLIBSSH_KEY_EXCHANGE_FAILED);
    assert(exchange.state->next == NULL && exchange.state->received == NULL);
    phase = ADVANCE;
    assert(olibssh_key_exchange_advance(session, &exchange) ==
           OLIBSSH_KEY_EXCHANGE_FAILED);
    olibssh_key_exchange_cleanup(session, &exchange);
    assert(olibssh_session_free(session) == 0);
    assert_no_allocations();
    capture_send = fragment_io = fail_send = 0;
}

static void test_method_cancellation(void)
{
    for(size_t i = 0; libssh2_kex_methods[i]; i++) {
        const LIBSSH2_KEX_METHOD *method = libssh2_kex_methods[i];
        if(!method->exchange_keys)
            continue;
        for(int receive_reply = 0; receive_reply < 2; receive_reply++) {
            LIBSSH2_SESSION *session = new_session();
            session->kex = method;
            session->socket_state = LIBSSH2_SOCKET_CONNECTED;
            OLIBSSHKeyExchange exchange = {0};
            exchange.state = LIBSSH2_ALLOC(session, sizeof(*exchange.state));
            *exchange.state = (OLIBSSHKeyExchangeState){
                .owner = &exchange, .cleanup = method->cleanup
            };
            phase = ADVANCE;
            assert(method->exchange_keys(session, &exchange.state->key_state) == 0);
            assert(exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
            if(receive_reply) {
                capture_send = 1;
                phase = WRITE_PACKET;
                assert(olibssh_key_exchange_write(session, &exchange) == 0);
                capture_send = 0;
                phase = ADVANCE;
                assert(olibssh_key_exchange_advance(session, &exchange) ==
                       OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT);
                unsigned char *packet = LIBSSH2_ALLOC(session, 1);
                packet[0] = exchange.state->expected_type;
                assert(olibssh_key_exchange_receive(session, &exchange, packet, 1) == 0);
                assert(olibssh_key_exchange_advance(session, &exchange) ==
                       OLIBSSH_KEY_EXCHANGE_FAILED);
            }
            olibssh_key_exchange_cleanup(session, &exchange);
            assert(olibssh_session_free(session) == 0);
            assert_no_allocations();
        }
    }
}

__attribute__((noinline))
static int send_eof_at_different_stack_depth(LIBSSH2_SESSION *session)
{
    volatile unsigned char stack_space[1024] = {0};
    const unsigned char packet[5] = {SSH_MSG_CHANNEL_EOF, 0, 0, 0, 7};
    int rc = olibssh_transport_write(session, packet, sizeof(packet), NULL, 0);
    assert(stack_space[0] == 0);
    return rc;
}

static void test_eof_retry(void)
{
    LIBSSH2_SESSION *session = new_session();
    session->socket_state = LIBSSH2_SOCKET_CONNECTED;
    capture_send = fragment_io = 1;
    send_calls = 2;
    phase = WRITE_PACKET;
    assert(olibssh_transport_resume_write(session) == LIBSSH2_ERROR_BAD_USE);
    assert(send_eof_at_different_stack_depth(session) == LIBSSH2_ERROR_EAGAIN);
    unsigned sends_before_rejected_start = send_calls;
    assert(send_eof_at_different_stack_depth(session) == LIBSSH2_ERROR_BAD_USE);
    assert(send_calls == sends_before_rejected_start);
    int result = LIBSSH2_ERROR_EAGAIN;
    for (unsigned attempt = 0; attempt < 100 && result == LIBSSH2_ERROR_EAGAIN; attempt++) {
        result = olibssh_transport_resume_write(session);
    }
    assert(result == 0);
    assert(session->packet.ototal_num == 0);
    assert(olibssh_transport_resume_write(session) == LIBSSH2_ERROR_BAD_USE);
    assert(olibssh_session_free(session) == 0);
    assert(live_allocations == 0);
    capture_send = fragment_io = 0;
}

#ifdef SSH_REKEY_REACTOR_TEST
typedef enum {
    HOLD_KEEPALIVE, RESUME_EXCHANGE, OPEN_CHANNEL, RELAY_TRAFFIC, FINAL_EXCHANGE, WAIT_FAILURE
} ReactorTestStage;

typedef struct {
    SSHReactor *reactor;
    SSHReactorChannelToken channel_token;
    unsigned char session_id[MAX_SHA_DIGEST_LEN];
    size_t session_id_length;
    otsource_t monitor;
    ssh_test_semaphore_t finished;
    ReactorTestStage stage;
    const char *ending;
    uint64_t hold_until;
    uint64_t deadline;
    otsocket_t browser_socket;
    int relay_socket;
    size_t sent, received;
    size_t validation_started_at;
} ReactorTest;

static const char reactor_test_key;

static void reactor_destroyed(void *opaque)
{
    ReactorTest *test = opaque;
    ssh_test_semaphore_signal(test->finished);
}

static void finish_reactor_test(ReactorTest *test)
{
    SSHReactor *reactor = test->reactor;
    reactor->destruction_completion = reactor_destroyed;
    reactor->destruction_context = test;
    otsource_cancel(test->monitor);
    otsource_release(test->monitor);
    otsocket_close(test->browser_socket);
    test->reactor = NULL;
    active_reactor = NULL;
    destroy_reactor_on_queue(reactor);
}

static unsigned char payload_byte(size_t offset)
{
    return (unsigned char)((offset * 137 + offset / 251) & 255);
}

static bool exchange_relay_data(ReactorTest *test)
{
    const size_t total = 256 * 1024;
    const size_t send_limit = test->validation_started_at ? total : 8192;
    unsigned char bytes[4096];
    if (test->sent < send_limit) {
        size_t count = send_limit - test->sent;
        if(count > sizeof(bytes))
            count = sizeof(bytes);
        for(size_t i = 0; i < count; i++)
            bytes[i] = payload_byte(test->sent + i);
        ssize_t rc = otsocket_send(test->browser_socket, bytes, count, 0);
        if(rc > 0)
            test->sent += (size_t)rc;
        else
            assert(rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    }
    for(;;) {
        ssize_t rc = otsocket_recv(test->browser_socket, bytes, sizeof(bytes), 0);
        if(rc < 0) {
            assert(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        assert(rc > 0 && test->received + (size_t)rc <= total);
        for(ssize_t i = 0; i < rc; i++)
            assert(bytes[i] == payload_byte(test->received + (size_t)i));
        test->received += (size_t)rc;
    }
    return test->sent == total && test->received == total;
}

// Advance one exchange operation at a time so teardown can occur precisely
// after our NEWKEYS write, before the peer's NEWKEYS has been consumed.
static void advance_final_exchange(ReactorTest *test)
{
    SSHReactor *reactor = test->reactor;
    OLIBSSHKeyExchange *exchange = &reactor->key_exchange;
    if(exchange->step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT) {
        bool newkeys = exchange->packet[0] == SSH_MSG_NEWKEYS;
        int rc = olibssh_key_exchange_write(reactor->session, exchange);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return;
        assert(rc == 0);
        assert(outersshpriv_reactor_advance_key_exchange(reactor) == 0);
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
        if(!newkeys)
            return;
        assert(exchange->step == OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT);
        if(strcmp(test->ending, "timeout") == 0) {
            otsource_set_timer(reactor->key_exchange_timeout_timer,
                OTTIME_NOW, OTTIME_FOREVER, 0);
            test->stage = WAIT_FAILURE;
        }
        else if(strcmp(test->ending, "disconnect") == 0) {
            // The peer is no longer reachable while we await its NEWKEYS.
            assert(otsocket_shutdown(reactor->socket, SHUT_RDWR) == 0);
            test->stage = WAIT_FAILURE;
            outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
            outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
            // Buffered input needs no new readiness event.
            if(olibssh_transport_has_buffered_input(reactor->session))
                key_exchange_socket_became_readable(reactor);
        }
        else {
            assert(strcmp(test->ending, "cancel") == 0);
            finish_reactor_test(test);
        }
    }
    else {
        assert(exchange->step == OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT);
        int rc = olibssh_transport_read(reactor->session, reactor);
        assert(rc >= 0 || rc == LIBSSH2_ERROR_EAGAIN);
        if(rc >= 0) {
            assert(outersshpriv_reactor_advance_key_exchange(reactor) == 0);
            outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
            outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
        }
    }
}

static void relay_channel_opened(SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken token, SSHReactorChannelOpenResult result, uint32_t reason)
{
    (void)pending;
    (void)reason;
    assert(result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED);
    ReactorTest *test = otqueue_get_specific(&reactor_test_key);
    unsigned char request[21] = {SSH_MSG_CHANNEL_REQUEST};
    unsigned char *cursor = request + 1;
    _libssh2_store_u32(&cursor, reactor->channels[token].remote_id);
    _libssh2_store_str(&cursor, "exec", 4);
    *cursor++ = 0;
    _libssh2_store_str(&cursor, "cat", 3);
    assert(cursor == request + sizeof(request));
    assert(outersshpriv_reactor_queue_protocol_response(reactor, request, sizeof(request)));
    reactor->channels[token].purpose = SSH_CHANNEL_PURPOSE_RELAY;
    SSHRelay *relay = ssh_relay_create(test->relay_socket, 1, 1,
                                     SSH_RELAY_TARGET_TCP, "cat", 3, 0);
    assert(relay);
    SSHReactorRelayHandle handle = {0};
    assert(add_relay(reactor, &handle, (SSHReactorRelayHandle){0},
                     token, relay, SSH_RELAY_DETACHED) == 0);
    outersshpriv_reactor_update_relay_read_source(reactor, outersshpriv_reactor_slot_for_handle(reactor, handle));
    outersshpriv_reactor_update_relay_write_source(reactor, outersshpriv_reactor_slot_for_handle(reactor, handle));
    test->stage = RELAY_TRAFFIC;

}

static void check_reactor(void *opaque)
{
    ReactorTest *test = opaque;
    SSHReactor *reactor = test->reactor;
    outersshpriv_reactor_assert_queue(reactor);
    if(outersshpriv_reactor_monotonic_time_nanoseconds() >= test->deadline) {
        fprintf(stderr, "Reactor test stalled: stage=%d exchange=%d lifecycle=%d "
                "sent=%zu received=%zu reads=%d writes=%d waiting_write=%d "
                "actions=%zu completed=%u buffered=%d\n",
                test->stage, reactor->key_exchange.step, reactor->lifecycle,
                test->sent, test->received, reactor->read_socket_source_is_resumed,
                reactor->write_socket_source_is_resumed,
                reactor->key_exchange_waiting_for_write, reactor->write_action_count,
                completed_exchanges, olibssh_transport_has_buffered_input(reactor->session));
        abort();
    }
    if(test->stage == WAIT_FAILURE) {
        if(reactor->lifecycle != SSH_REACTOR_LIFECYCLE_FAILED)
            return;
        assert(reactor->key_exchange_timeout_timer == NULL);
        assert(outersshpriv_reactor_session_has_failed(reactor));
        finish_reactor_test(test);
        return;
    }
    assert(outersshpriv_reactor_accepts_work(reactor));
    switch(test->stage) {
    case HOLD_KEEPALIVE:
        assert(reactor->keepalive_timeout_timer == NULL);
        assert(reactor->keepalive_pending && reactor->has_pending_global_request);
        if(outersshpriv_reactor_monotonic_time_nanoseconds() < test->hold_until)
            return;
        test->stage = RESUME_EXCHANGE;
        start_reactor_on_queue(reactor);
        return;
    case RESUME_EXCHANGE:
        if(completed_exchanges == 0)
            return;
        assert(reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_IDLE);
        assert(reactor->key_exchange_timeout_timer == NULL);
        assert(reactor->keepalive_timeout_timer != NULL);
        assert(reactor->keepalive_pending && reactor->has_pending_global_request);
        // Retire the synthetic outstanding request after checking its new timer.
        clear_keepalive(reactor);
        reactor->has_pending_global_request = false;
        test->stage = OPEN_CHANNEL;
        assert(outersshpriv_reactor_open_session_channel(reactor, &test->channel_token, 5000,
            (SSHReactorPendingChannelOpen){.finished = relay_channel_opened}) == 0);
        return;
    case OPEN_CHANNEL:
        return;
    case RELAY_TRAFFIC:
        if (test->received >= 4096 && test->validation_started_at == 0) {
            // Hold a synthetic validation reply while this established relay
            // transfers the rest of its data and rekeys repeatedly.
            test->validation_started_at = test->received;
            reactor->has_pending_global_request = true;
            reactor->keepalive_pending = true;
            reactor->keepalive_timeout_milliseconds = 5000;
            if (!reactor->key_exchange_waiting_for_write &&
                reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_IDLE) {
                assert(outersshpriv_reactor_start_keepalive_timeout(reactor) == 0);
            }
        }
        if (!exchange_relay_data(test) ||
            reactor->key_exchange.step != OLIBSSH_KEY_EXCHANGE_IDLE ||
            reactor->write_action_count != 0) {
            return;
        }
        assert(test->validation_started_at != 0);
        assert(test->received - test->validation_started_at >= 128 * 1024);
        assert(reactor->has_pending_global_request);
        clear_keepalive(reactor);
        reactor->has_pending_global_request = false;
        // Only the first exchange was client-initiated. Real channel traffic
        // must have caused at least two additional, server-initiated exchanges.
        assert(completed_exchanges >= 3);
        assert(reactor->session->session_id_len == test->session_id_length);
        assert(memcmp(reactor->session->session_id, test->session_id, test->session_id_length) == 0);
        assert(data_reads_during_write > 0);
        assert(kex_reads_during_write > 0);
        assert(outersshpriv_reactor_begin_key_exchange(reactor) == 0);
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
        test->stage = FINAL_EXCHANGE;
        return;
    case FINAL_EXCHANGE:
        advance_final_exchange(test);
        return;
    case WAIT_FAILURE:
        abort();
    }
}

static void start_reactor_test(void *opaque)
{
    ReactorTest *test = opaque;
    SSHReactor *reactor = test->reactor;
    // Model an already-written keepalive whose response has not yet arrived.
    reactor->keepalive_pending = true;
    reactor->has_pending_global_request = true;
    reactor->keepalive_timeout_milliseconds = 100;
    assert(outersshpriv_reactor_start_keepalive_timeout(reactor) == 0);
    assert(outersshpriv_reactor_begin_key_exchange(reactor) == 0);
    assert(reactor->keepalive_timeout_timer == NULL);
    test->hold_until = outersshpriv_reactor_monotonic_time_nanoseconds() + 300 * NSEC_PER_MSEC;
    test->deadline = outersshpriv_reactor_monotonic_time_nanoseconds() + 55 * NSEC_PER_SEC;
    test->monitor = otsource_create(
        OTSOURCE_TYPE_TIMER, 0, reactor->queue);
    assert(test->monitor);
    otsource_set_context(test->monitor, test);
    otsource_set_event_handler(test->monitor, check_reactor);
    otsource_set_timer(test->monitor, OTTIME_NOW,
                              NSEC_PER_MSEC, 0);
    otsource_activate(test->monitor);
}

static void run_reactor(SSHReactor *reactor, const char *ending)
{
    int browser[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, browser) == 0);
    assert(fcntl(browser[0], F_SETFL, O_NONBLOCK) == 0);
    ReactorTest test = {
        .reactor = reactor,
        .browser_socket = browser[0],
        .relay_socket = browser[1],
        .finished = ssh_test_semaphore_create(0),
        .ending = ending
    };
    assert(test.reactor && test.finished);
    test.session_id_length = reactor->session->session_id_len;
    assert(test.session_id_length > 0 && test.session_id_length <= sizeof(test.session_id));
    memcpy(test.session_id, reactor->session->session_id, test.session_id_length);
    active_reactor = test.reactor;
    phase = REACTOR_IO;
    otqueue_set_specific(test.reactor->queue, &reactor_test_key, &test);
    otqueue_async(test.reactor->queue, &test, start_reactor_test);
    assert(ssh_test_semaphore_wait(test.finished,
        60 * NSEC_PER_SEC) == 0);
    assert(test.reactor == NULL);
    assert_no_allocations();
    ssh_test_semaphore_destroy(test.finished);
}
#endif

#ifdef SSH_REKEY_REACTOR_TEST
static void initial_authentication_finished(void *context, OuterSSHError error)
{
    if (error.domain != OUTERSSH_ERROR_NONE) {
        fprintf(stderr, "reactor authentication failed: %d (%.*s)\n", error.ssh_error_code,
            (int)error.message_length, error.message);
    }
    assert(error.domain == OUTERSSH_ERROR_NONE);
    assert(!active_reactor->started && active_reactor->phase == SSH_REACTOR_PHASE_NONE);
    ssh_test_semaphore_signal(context);
}

static void initial_handshake_finished(void *context, int error)
{
    if (error != 0) {
        char *message = NULL;
        libssh2_session_last_error(active_reactor->session, &message, NULL, 0);
        fprintf(stderr, "reactor handshake failed: %d (%s)\n", error, message ? message : "");
    }
    assert(error == 0);
    assert(!active_reactor->started && active_reactor->phase == SSH_REACTOR_PHASE_NONE);
    ssh_test_semaphore_signal(context);
}
#endif

int main(int argc, char **argv)
{
    (void)argv;
    assert(argc == 5 || argc == 6);
    signal(SIGPIPE, SIG_IGN);
    assert(libssh2_init(0) == 0);
#if !OUTERSSH_APPLE_CRYPTO
    test_chacha_packet_vector();
#endif
    test_aead_transport();
    test_initial_strict_packet_order();
#ifndef SSH_REKEY_REACTOR_TEST
    test_direct_channel_packets();
    puts("PASS: direct packet delivery without libssh2 channels or packet-list nodes");
#endif
    test_no_implicit_io();
    test_cookie_failure();
    test_interrupted_startup_exchange();
    test_eof_retry();
    test_exchange_delivery();
    test_exchange_write_continuation();
    test_method_cancellation();
    test_exchange_write_failure();
    puts("PASS: exchange packet ownership, exact-once continuations, malformed replies, and method cancellation");
    if(getenv("SSH_TRANSPORT_TEST_ONLY")) {
        libssh2_exit();
        return 0;
    }

#ifndef SSH_REKEY_REACTOR_TEST
    libssh2_exit();
#else
    otsocket_t sockets[2];
    int listener = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    assert(otsocket_bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t address_length = sizeof(address);
    assert(otsocket_getsockname(listener, (struct sockaddr *)&address, &address_length) == 0);
    assert(otsocket_listen(listener, 1) == 0);
    sockets[0] = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(sockets[0] >= 0);
    assert(otsocket_connect(sockets[0], (struct sockaddr *)&address, sizeof(address)) == 0);
    sockets[1] = otsocket_accept(listener, NULL, NULL);
    assert(sockets[1] >= 0);
    otsocket_close(listener);
    pid_t child = fork();
    assert(child >= 0);
    if(child == 0) {
        char authorized_keys[4096];
        char kex_algorithms[256];
        assert(snprintf(kex_algorithms, sizeof(kex_algorithms),
                        "KexAlgorithms=%s", argv[3]) < (int)sizeof(kex_algorithms));
        assert(snprintf(authorized_keys, sizeof(authorized_keys),
                        "AuthorizedKeysFile=%s.pub", argv[2]) <
               (int)sizeof(authorized_keys));
        otsocket_close(sockets[0]);
        assert(dup2(sockets[1], STDIN_FILENO) == STDIN_FILENO);
        assert(dup2(sockets[1], STDOUT_FILENO) == STDOUT_FILENO);
        otsocket_close(sockets[1]);
        execl("/usr/sbin/sshd", "sshd", "-i", "-e", "-f", "/dev/null",
              "-h", argv[1], "-o", "UsePAM=no",
              "-o", authorized_keys, "-o", "StrictModes=no",
              "-o", kex_algorithms,
              "-o", "RekeyLimit=1K",
              "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR",
              (char *)NULL);
        _exit(127);
    }
    otsocket_close(sockets[1]);
    LIBSSH2_SESSION *session = new_session();
    assert(libssh2_session_method_pref(session, LIBSSH2_METHOD_KEX, argv[3]) == 0);
    if(getenv("SSH_REKEY_TRACE"))
        libssh2_trace(session, LIBSSH2_TRACE_KEX | LIBSSH2_TRACE_TRANS);
    assert(libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_CS, argv[4]) == 0);
    assert(libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_SC, argv[4]) == 0);
    phase = INITIAL_HANDSHAKE;
    fragment_io = 1;
    assert(otsocket_set_nonblocking(sockets[0], true) == 0);
    olibssh_handshake_set_socket(session, sockets[0]);
    SSHReactor *reactor = ssh_test_reactor_create(sockets[0], session);
    assert(reactor != NULL);
    active_reactor = reactor;
    ssh_test_semaphore_t handshaken = ssh_test_semaphore_create(0);
    outersshpriv_reactor_handshake(reactor, initial_handshake_finished, handshaken);
    assert(ssh_test_semaphore_wait(handshaken, 20 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(handshaken);
    assert(completed_exchanges == 1);
    completed_exchanges = 0;
    assert(!(session->state & LIBSSH2_STATE_INITIAL_KEX));

    struct passwd *user = getpwuid(getuid());
    assert(user);
    FILE *key_file = fopen(argv[2], "rb");
    assert(key_file != NULL);
    assert(fseek(key_file, 0, SEEK_END) == 0);
    long key_length = ftell(key_file);
    assert(key_length > 0 && fseek(key_file, 0, SEEK_SET) == 0);
    char *key = malloc((size_t)key_length);
    assert(key != NULL && fread(key, 1, (size_t)key_length, key_file) == (size_t)key_length);
    fclose(key_file);
    ssh_test_semaphore_t authenticated = ssh_test_semaphore_create(0);
    outersshpriv_reactor_authenticate(reactor, (SSHAuthenticationRequest){
        .username = user->pw_name, .username_length = strlen(user->pw_name),
        .credentials = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
            .private_key = key, .private_key_length = (size_t)key_length},
        .timeout_milliseconds = 15000
    }, initial_authentication_finished, authenticated);
    assert(ssh_test_semaphore_wait(authenticated, 20 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(authenticated);
    free(key);
    assert(strcmp(libssh2_session_methods(session, LIBSSH2_METHOD_KEX), argv[3]) == 0);
    assert(strcmp(libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_CS), argv[4]) == 0);
    assert(strcmp(libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC), argv[4]) == 0);
    assert(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
    fragment_io = 1;
    run_reactor(reactor, argc == 6 ? argv[5] : "cancel");
    kill(child, SIGTERM);
    int status;
    assert(waitpid(child, &status, 0) == child);
    libssh2_exit();
    printf("PASS: %s / %s: %u reactor rekeys, %u data reads and %u KEXINITs during partial writes, relay integrity, keepalive pause/resume, NEWKEYS %s\n",
           argv[3], argv[4], completed_exchanges, data_reads_during_write,
           kex_reads_during_write, argc == 6 ? argv[5] : "cancel");
#endif
    return 0;
}
