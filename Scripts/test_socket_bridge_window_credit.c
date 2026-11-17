#include <assert.h>
#include "SSHReactorSocketBridge.c"

static size_t consumed;
int outersshpriv_reactor_consume_channel_bytes(SSHReactor *reactor, SSHChannelState *state,
                                              SSHReactorChannelToken token, size_t count)
{
    (void)reactor; (void)state; (void)token;
    consumed += count;
    return 0;
}
void outersshpriv_reactor_update_channel_write_source(SSHReactor *reactor) { (void)reactor; }
void outersshpriv_reactor_fail(SSHReactor *reactor, SSHReactorOperation operation, int error)
{
    (void)reactor; (void)operation; (void)error;
    assert(false);
}
int main(void)
{
    SSHReactor reactor = {0};
    SSHChannelState channel = {0};
    reactor.channels = &channel;
    SocketBridge bridge = {0};
    unsigned char partial_header[7] = {0};
    assert(outersshpriv_helper_frame_parser_append(&bridge.parser, partial_header, sizeof(partial_header)));
    bridge.uncredited_byte_count = 2 * 1024 * 1024;
    bridge.pending_local_output_byte_count = 32768;
    assert(outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(&reactor, &bridge));
    assert(consumed == 2 * 1024 * 1024 - 32768 - sizeof(partial_header));
    assert(bridge.uncredited_byte_count == 32768 + sizeof(partial_header));
    size_t prior = consumed;
    assert(outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(&reactor, &bridge));
    assert(consumed == prior);
    bridge.pending_local_output_byte_count = 0;
    assert(outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(&reactor, &bridge));
    assert(bridge.uncredited_byte_count == sizeof(partial_header));
    outersshpriv_helper_frame_parser_deinitialize(&bridge.parser);
    assert(outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(&reactor, &bridge));
    assert(consumed == 2 * 1024 * 1024 && bridge.uncredited_byte_count == 0);
    bridge.uncredited_byte_count = 10;
    bridge.pending_local_output_byte_count = 20;
    assert(outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(&reactor, &bridge));
    assert(bridge.uncredited_byte_count == 10);
    return 0;
}
