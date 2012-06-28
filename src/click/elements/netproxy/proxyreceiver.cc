/*
 * proxyreceiver.{cc,hh}
 * Ian Rose <ianrose@eecs.harvard.edu>
 */

#include <click/config.h>
#include "proxyreceiver.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "proxyreceiver.hh"
#include "../wifiutil.hh"
#include "../argos/net_proto.h"
CLICK_DECLS

/*
 * Public Class Methods
 */

ProxyReceiver::ProxyReceiver(int sock, const struct sockaddr_in *addr,
    size_t bufsize, ProxyServer *server)
{
    _sock = sock;
    _addr = *addr;
    _server = server;
    _is_closed = false;

    // allocate a little extra space for compression overhead
    _inbuf = buffer_create(bufsize + 5*1024);
    _msgbuf = buffer_create(bufsize);
    _bytes_recv = 0;
    _pkts_recv = 0;

    _reported_mem_drop = false;
    _headroom = Packet::default_headroom;
    _log = NULL;

    assert(_inbuf != NULL);
    assert(_msgbuf != NULL);
    assert(bufsize > 0);
}

ProxyReceiver::~ProxyReceiver()
{
    close();
    buffer_destroy(_inbuf);
    buffer_destroy(_msgbuf);
    _inbuf = NULL;
    _msgbuf = NULL;
}

void
ProxyReceiver::close()
{
    if (_is_closed) return;
    _is_closed = true;
    _server->handle_close(_sock);

    do {
        if (::close(_sock) == -1) {
            if (errno == EINTR)
                continue;
            else
                if (_log != NULL) _log->strerror("close");
        }
    } while (0);
}

void
ProxyReceiver::selected(int fd)
{
    assert(fd == _sock);

    size_t space = buffer_remaining(_inbuf);

    // if the space available in the inbuf is small, that makes for inefficient
    // recv() calls, so compact the buffer to create more space
    if (space < (16*1024)) {
        buffer_compact(_inbuf);
        space = buffer_remaining(_inbuf);
    }

    assert(space > 0);

    ssize_t len = recv(_sock, buffer_tail(_inbuf), space, 0);
    if (len == -1) {
        switch (errno) {
        case EAGAIN:
            // this is odd because we should not have been selected(), but its
            // nothing terrible so we issue a warning instead of an error
            _log->warning("recv() failed with EAGAIN");
            // do not shut down network connection
            break;

        case ECONNRESET:
        case ETIMEDOUT:
            // these errors can happen as a normal consequence of network links
            // going up and down so we don't report them as an errorm but we
            // still need to shut down the connection because its dead now
            // (ETIMEDOUT is documented in the socket(2) man page, not recv(2))
            _log->info("recv: %s", strerror(errno));
            close();
            break;

        default:
            // all other errors are unexpected; they probably indicate a
            // programming error so we issue critical-level errors
            _log->critical("recv: %s", strerror(errno));
            close();
            break;
        }
    }
    else if (len == 0) {
        _log->info("EOF received");
        close();
    }
    else {
        // recv() succeeded
        assert(len > 0);

        int rv = buffer_expand(_inbuf, len);
        assert(rv == len);
        _bytes_recv += len;

        // now try to parse some complete messages out of inbuf
        if (process_buffer(_inbuf)) {
            // if inbuf is now empty, compact it so that we'll have maximal room
            // available for future recvs
            if (buffer_len(_inbuf) == 0)
                buffer_compact(_inbuf);

            // If the inbuf doesn't have any more room, then that's a problem
            // because it means that we have a partial message in the buffer but
            // there is no room to receiver the rest of the message (so that it
            // can then be processed and removed).  First we try to compact the
            // buffer; if that doesn't work then the buffer must be totally full
            // from beginning to end which means that this message is
            // oversized.
            if (buffer_remaining(_inbuf) == 0) {
                buffer_compact(_inbuf);

                if (buffer_remaining(_inbuf) == 0) {
                    _log->warning("inbuf completely full after process_buffer()"
                        "; buffer too small for received message?");
                    abort();  // for now, abort to debug this error
                    close();
                }
            }
        } else {
            // something went wrong in process_buffer()
            close();
        }
    }
}

/*
 * Private Methods
 */

bool
ProxyReceiver::decompress_packets(uint8_t algorithm, const u_char *inptr,
    uint32_t inlen, u_char *outptr, uint32_t orig_len)
{
    String alg_name;
    uint32_t outlen = 0;

    switch (algorithm) {
    case ARGOS_NET_COMPRESS_NONE:
        alg_name = "memcpy";
        memcpy(outptr, inptr, inlen);
        outlen = inlen;
        break;

    case ARGOS_NET_COMPRESS_LZO: {
        alg_name = "LZO";
        /*
        lzo_uint lzo_outlen = orig_len;  // initial value doesn't seem to matter
        int rv = lzo1x_decompress(inptr, inlen, outptr, &lzo_outlen, NULL);
        if (rv != LZO_E_OK) {
            // according to LZO documentation, this "should never happen"
            _log->critical("lzo1x_decompress failed: %d", rv);
            return false;
        }
        outlen = lzo_outlen;
        */
        _log->error("block compressed by unsupported algorithm (LZO)");
        return false;
    }
    case ARGOS_NET_COMPRESS_QUICKLZ: {
        alg_name = "QuickLZ";

#ifdef ARGOS_NETPROXY_SAFE
        // sanity check: compressed data should always meet a minimum size
        if (inlen < QLZ_MIN_COMPRESS_SIZE) {
            _log->critical("QuickLZ error.  msg-size=%u which is too small (min=%d)",
                inlen, QLZ_MIN_COMPRESS_SIZE);
            return false;
        }

        // sanity check: the compressed data can self-report its compressed and
        // decompressed size so make sure those match this function's arguments
        size_t qlz_in = qlz_size_compressed((const char*)inptr);
        size_t qlz_out = qlz_size_decompressed((const char*)inptr);
        if (qlz_in != inlen) {
            _log->critical("QuickLZ error.  msg-size=%u, but qlz_size_compressed=%u",
                inlen, qlz_in);
            return false;
        }
        if (qlz_out != orig_len) {
            _log->critical("QuickLZ error.  msg-orig-len=%u, but qlz_size_decompressed=%u",
                orig_len, qlz_out);
            return false;
        }
#endif  // #ifdef ARGOS_NETPROXY_SAFE

        outlen = qlz_decompress((const char*)inptr, outptr, _qlz_scratch);
        break;
    }
    default:
        _log->error("block compressed by unknown algorithm: %d", algorithm);
        return false;
    }

    if (outlen != orig_len) {
        // uh oh - this is bad
        _log->critical("%s decompression returned %u bytes, expected %u",
            alg_name.c_str(), outlen, orig_len);
        return false;
    }

    int rv = buffer_expand(_msgbuf, orig_len);
    assert(rv == (int)orig_len);

    return true;
}

Packet *
ProxyReceiver::deserialize_packet(u_char *buffer, size_t data_len, uint32_t headroom)
{
    const struct argos_net_clickpkt_msg *header =
        (const struct argos_net_clickpkt_msg *)buffer;
    uint32_t hdr_len = sizeof(struct argos_net_clickpkt_msg);
    uint32_t total_len = ntohl(header->msglen);
    uint32_t buf_len = total_len - hdr_len;
    u_char *body = buffer + hdr_len;

    assert(ntohs(header->msgtype) == ARGOS_NET_CLICKPKT_MSGTYPE);
    assert(total_len <= data_len);

    Packet *p;

    try {
        p = Packet::make(headroom, body, buf_len, 0);
    }
    catch (std::bad_alloc &ex) {
        errno = ENOMEM;
        return NULL;
    }

    p->set_packet_type_anno((Packet::PacketType)header->packet_type);
    p->set_timestamp_anno(Timestamp::make_usec(ntohl(header->ts_sec),
            ntohl(header->ts_usec)));

    int32_t mac_offset = ntohl(header->mac_offset);
    int32_t net_offset = ntohl(header->net_offset);
    int32_t trans_offset = ntohl(header->trans_offset);

    if (mac_offset != ARGOS_NET_CLICKPKT_UNDEF) {
        p->set_mac_header(p->data() + mac_offset);
    }
    if (net_offset != ARGOS_NET_CLICKPKT_UNDEF) {
        // Packet class uses a weird interface here (can't set transport header
        // independently of the network header)
        if (trans_offset == ARGOS_NET_CLICKPKT_UNDEF) {
            p->set_network_header(p->data() + net_offset, 0);
            p->clear_transport_header();
        } else {
            // trans_offset != ARGOS_NET_CLICKPKT_UNDEF
            p->set_network_header(p->data() + net_offset, trans_offset - net_offset);
        }
    }
    else if (trans_offset != ARGOS_NET_CLICKPKT_UNDEF) {
        p->set_network_header(p->data() + trans_offset, 0);
        p->clear_network_header();
    }

    memcpy(p->anno_u8(), header->anno, Packet::anno_size);
    return p;
}

bool
ProxyReceiver::process_buffer(struct buffer *buf)
{
    // repeatedly parse messages out of the buffer until its empty or a partial
    // message is encountered
    while (buffer_len(buf) >= sizeof(struct argos_net_minimal_msg)) {
        struct argos_net_minimal_msg *header =
            (struct argos_net_minimal_msg *)buffer_head(buf);

        uint16_t msgtype = ntohs(header->msgtype);
        uint32_t msglen = ntohl(header->msglen);

        // check that message type and length are valid
        if (ARGOS_NET_VALIDATE_MSGTYPE(msgtype) == 0) {
            _log->critical("invalid message type received; type=%hu, len=%u",
                msgtype, msglen);
            return false;
        }

        if (ARGOS_NET_VALIDATE_MSGLEN(msgtype, msglen) == 0) {
            _log->critical("invalid message len received; type=%hu, len=%u",
                msgtype, msglen);
            return false;
        }

        if (msglen > buffer_len(buf)) {
            // entire message not yet received
            if (msglen > buffer_size(buf)) {
                // error - message is bigger than the entire inbuf
                _log->error("inbuf (len=%u) too small for msgtype %hu (len=%u)",
                    buffer_size(buf), msgtype, msglen);
                return false;
            }

            // wait for more bytes to arrive on socket
            _log->debug("%u bytes of partial message received: type=%hu, len=%u",
                buffer_len(buf), msgtype, msglen);
            break;
        }

        // full message received
        _log->debug("complete message received: type=%hu, len=%u", msgtype, msglen);

        switch (msgtype) {
        case ARGOS_NET_COMPRESS_MSGTYPE: {
            if (buf == _msgbuf) {
                _log->error("COMPRESS message encountered while processing msgbuf");
                return false;
            }

            assert(buf == _inbuf);
            assert(buffer_len(_msgbuf) == 0);

            struct argos_net_compress_msg *msg =
                (struct argos_net_compress_msg*)header;

            uint32_t origlen = ntohl(msg->orig_len);

            if (buffer_remaining(_msgbuf) < origlen) {
                _log->error("msgbuf (len=%u) too small for new compression block"
                    " (len=%u)", origlen);
                return false;
            }

            size_t hdrlen = sizeof(struct argos_net_compress_msg);
            size_t blocklen = msglen - hdrlen;
            uint8_t *compressed_data = buffer_head(buf) + hdrlen;

            // check for message corruption if a crc32 was included by the
            // sender
            if (msg->crc32_used) {
                uint32_t orig_crc32 = ntohl(msg->crc32);
                uint32_t real_crc32 = wifi_calc_crc32(compressed_data, blocklen);

                if (orig_crc32 != real_crc32) {
                    _log->critical("CRC32 failure on COMPRESS message");
                    return false;
                }
            }

            bool ok = decompress_packets(msg->algorithm, compressed_data,
                blocklen, buffer_tail(_msgbuf), origlen);

            if (ok) {
                // process the uncompressed messages that decompress_packets()
                // added to _msgbuf
                if (process_buffer(_msgbuf) == false)
                    return false;

                // process_buffer *should* consume everything from _msgbuf
                assert(buffer_len(_msgbuf) == 0);
                buffer_compact(_msgbuf);
            } else {
                // decompression failed
                return false;
            }
            break;
        }

        case ARGOS_NET_CLICKPKT_MSGTYPE: {
            Packet *p = deserialize_packet(buffer_head(buf), buffer_len(buf), _headroom);
            if (p == NULL) {
                // to avoid spamming the log, we only ever report this once
                // (timeout would be better, but this is simple and hopefully
                // won't have to occur)
                if ((errno == ENOMEM) && !_reported_mem_drop) {
                    _reported_mem_drop = true;
                    _log->warning("deserialize_packet: %s", strerror(errno));
                } else {
                    _log->error("deserialize_packet: %s", strerror(errno));
                }

                // note - do not return false as we want to keep up with the
                // incoming data even if we don't have memory to process it
            } else {
                _server->handle_packet(p, &_addr);
                _pkts_recv++;
            }
            break;
        }
        default:
            _log->critical("unsupported message received (type=%hu)", msgtype);
            return false;
        }

        int rv = buffer_discard(buf, msglen);
        assert(rv == (int)msglen);
    }

    return true;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(buffer quicklz WifiUtil)
ELEMENT_PROVIDES(proxyreceiver)
