#include <argp.h>
#include <arpa/inet.h>
#include <dtp_config.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <quiche.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "helper.h"
#include "uthash.h"

/***** Argp configs START *****/

const char *argp_program_version = "server-libev 0.0.1";
static char doc[] = "libev mpdtp server";
static char args_doc[] =
    "SERVER_IP1 SERVER_PORT1 SERVER_IP2 SERVER_PORT2 DTP_CONFIG";

static struct argp_option options[] = {
    {"log", 'l', "FILE", 0, "log file with debug and error info"},
    {"out", 'o', "FILE", 0, "output file with received file info"},
    {0}};

struct arguments {
    FILE *log;
    FILE *out;
    char *args[5];
};

static struct arguments args;

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 'l':
            arguments->log = fopen(arg, "w+");
            break;
        case 'o':
            arguments->out = fopen(arg, "w+");
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 5) argp_usage(state);
            arguments->args[state->arg_num] = arg;
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 5) argp_usage(state);
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

/***** Argp configs END *****/

/***** DTP configs START *****/

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350   // UDP
#define MAX_BLOCK_SIZE 10000000  // QUIC
#define TIME_SIZE 8

int MAX_SEND_TIMES;

#define MAX_TOKEN_LEN                                        \
    sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) + \
        QUICHE_MAX_CONN_ID_LEN

struct connections {
    uint64_t socks[2];

    struct conn_io *h;

    uint32_t configs_len;
    dtp_config *configs;
};

struct pacer {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint64_t t_last;
    uint64_t can_send;
    bool done_writing;
    ev_timer pacer_timer;
};

struct conn_io {
    ev_timer timer;
    ev_timer sender;

    struct pacer pacers[2];
    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    uint32_t send_round;
    bool MP_conn_finished;

    UT_hash_handle hh;
    struct connections *conns;
};

static quiche_config *config = NULL;
static struct connections *conns = NULL;

// Use static variable to find conn_io for second path
// connection for now. It is better to send QUIC info
// instead of only a string "Second".
static struct conn_io *conn_io_outside = NULL;

uint8_t server_pcid[LOCAL_CONN_ID_LEN];
uint8_t client_pcid[LOCAL_CONN_ID_LEN];

/***** DTP configs END *****/

/***** libev callback declare START *****/

static void timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void flush_packets(struct ev_loop *loop, struct conn_io *conn_io,
                          uint8_t path);
static void flush_packets_0(struct ev_loop *loop, ev_timer *pacer_timer,
                            int revents);
static void flush_packets_1(struct ev_loop *loop, ev_timer *pacer_timer,
                            int revents);
static void sender_cb(struct ev_loop *loop, ev_timer *w, int revents);

/***** libev callback declare START *****/

/***** Utilities START *****/

#define log(level, ...)                                    \
    do {                                                   \
        fprintf(args.log, "[%s] %s: ", (level), __func__); \
        fprintf(args.log, __VA_ARGS__);                    \
        fprintf(args.log, "\n");                           \
    } while (0)

#define log_debug(...) log("DEBUG", __VA_ARGS__)

#define log_error(...) log("ERROR", __VA_ARGS__)

#define log_info(...) log("INFO ", __VA_ARGS__)

#define dump_file(...)                  \
    do {                                \
        fprintf(args.out, __VA_ARGS__); \
    } while (0)

static void quiche_debug_log(const char *line, void *argp) {
    // log_debug("%s", line);
}

/***** Utilities END *****/

/***** QUIC Utilities START *****/

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
        memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static struct conn_io *create_conn(struct ev_loop *loop, uint8_t *odcid,
                                   size_t odcid_len) {
    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        log_error("failed to allocate connection IO");
        return NULL;
    }

    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        log_error("failed to open /dev/urandom: %s", strerror(errno));
        return NULL;
    }

    ssize_t rand_len = read(rng, conn_io->cid, LOCAL_CONN_ID_LEN);
    if (rand_len < 0) {
        log_error("failed to create connection ID: %s", strerror(errno));
        return NULL;
    }

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN, odcid,
                                      odcid_len, config);
    if (conn == NULL) {
        log_error("failed to create connection");
        return NULL;
    }

    conn_io->conn = conn;
    conn_io->conns = conns;
    conn_io->send_round = 0;
    for (size_t i = 0; i < 2; i++) {
        conn_io->pacers[i].t_last = getCurrentTime_mic();
        conn_io->pacers[i].can_send = 1350;
        conn_io->pacers[i].done_writing = false;
    }

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;
    // TODO: might need a timer to shutdown if no connection?
    // ev_timer_start(loop, &conn_io->timer);

    conn_io->pacers[0].pacer_timer.data = conn_io;
    conn_io->pacers[1].pacer_timer.data = conn_io;
    ev_init(&conn_io->pacers[0].pacer_timer, flush_packets_0);
    ev_init(&conn_io->pacers[1].pacer_timer, flush_packets_1);

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    log_info("new connection");

    return conn_io;
}

u_char tos(u_int ddl, u_int prio) {
    u_char d, p;

    // 0x64 100ms
    // 0xC8 200ms
    // 0x1F4 500ms
    // 0x3E8 1m
    // 0xEA60 1min
    if (ddl < 0x64) {
        d = 5;
    } else if (ddl < 0xC8) {
        d = 4;
    } else if (ddl < 0x1F4) {
        d = 3;
    } else if (ddl < 0x3E8) {
        d = 2;
    } else if (ddl < 0xEA60) {
        d = 1;
    } else {
        d = 0;
    }

    if (prio < 2) {
        p = 5 - prio;
    } else if (prio < 4) {
        p = 3;
    } else if (prio < 8) {
        p = 2;
    } else if (prio < 16) {
        p = 1;
    } else {
        p = 0;
    }

    return (d > p) ? d : p;
}

void set_tos(int ai_family, int sock, int tos) {
    switch (ai_family)
    {
        case AF_INET:
            if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(int)) < 0)
                fprintf(stderr, "Warning: Cannot set TOS!\n");
            break;

        case AF_INET6:
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(int)) < 0)
                fprintf(stderr, "Warning: Cannot set TOS!\n");
            break;

        default:
            break;
    }
}

/***** QUIC Utilities END *****/

/***** libev callback START *****/

static void send_packet(int sock, const struct sockaddr *addr,
                        socklen_t addr_len, const void *buf, size_t size, int tos) {
    uint64_t t = getCurrentTime_mic();
    uint8_t *out_time = (uint8_t *)&t;
    uint8_t out_with_time[MAX_DATAGRAM_SIZE + TIME_SIZE];
    memcpy(out_with_time, out_time, TIME_SIZE);
    memcpy(out_with_time + TIME_SIZE, buf, size);
    size += TIME_SIZE;
    set_tos(addr->sa_family, sock, tos);
    ssize_t sent = sendto(sock, out_with_time, size, 0, addr, addr_len);
    if (sent < 0) {
        log_error("sendto error: %s", strerror(errno));
        return;
    }
    log_debug("sent %zd bytes", sent);
    return;
}

static void flush_packets(struct ev_loop *loop, struct conn_io *conn_io,
                          uint8_t path) {
    log_debug("---------- flush_packets path %d ----------", path);

    static uint8_t out[MAX_DATAGRAM_SIZE];

    double pacing_rate = quiche_conn_get_pacing_rate(conn_io->conn, path);
    log_debug("pacing_rate %lf", pacing_rate);

    if (conn_io->pacers[path].done_writing) {
        conn_io->pacers[path].can_send = 1350;
        conn_io->pacers[path].t_last = getCurrentTime_mic();
        conn_io->pacers[path].done_writing = false;
        conn_io->pacers[path].pacer_timer.repeat = 99999.0;
        ev_timer_again(loop, &conn_io->pacers[path].pacer_timer);
    }
    while (true) {
        uint64_t t_now = getCurrentTime_mic();
        uint64_t can_send_increase =
            (pacing_rate * (t_now - conn_io->pacers[path].t_last)) / 8000000.0;
        log_debug("rate %lf now %ld last %ld sub %ld inc %ld", pacing_rate,
                  t_now, conn_io->pacers[path].t_last,
                  (t_now - conn_io->pacers[path].t_last), can_send_increase);
        conn_io->pacers[path].can_send += can_send_increase;
        conn_io->pacers[path].t_last = t_now;
        if (conn_io->pacers[path].can_send < 1350) {
            log_debug("path %d can_send %lu < 1350", path,
                      conn_io->pacers[path].can_send);
            conn_io->pacers[path].pacer_timer.repeat = 0.001;
            ev_timer_again(loop, &conn_io->pacers[path].pacer_timer);
            break;
        } else {
            uint64_t deadline, priority;
            ssize_t written =
                quiche_conn_send(conn_io->conn, out, sizeof(out), path, &deadline, &priority);

            if (written > 0) {
                log_debug("quiche_conn_send written %zd bytes", written);
                int t = tos(deadline, priority) << 5;
                send_packet(
                    conn_io->conns->socks[path],
                    (const struct sockaddr *)&conn_io->pacers[path].addr,
                    conn_io->pacers[path].addr_len, out, written, t);
                conn_io->pacers[path].can_send -= written;
            } else if (written < -1) {
                log_error("failed to create packet on path %d written %zd",
                          path, written);
                return;
            } else if (written == QUICHE_ERR_DONE) {
                log_debug("path %d done writing", path);
                conn_io->pacers[path].done_writing = true;
                break;
            }
        }
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9;
    log_debug("ts: %lf", t);
    t = t < 0.0000001 ? 0.0000001 : t;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);

    quiche_stats stats;
    quiche_conn_stats(conn_io->conn, &stats);
    log_debug(
        "-----recv=%zu sent=%zu lost_init=%zu lost_subseq=%zu rtt_init=%" PRIu64
        "ns rtt_subseq=%" PRIu64 "ns-----",
        stats.recv, stats.sent, stats.lost_init, stats.lost_subseq,
        stats.rtt_init, stats.rtt_subseq);
    log_debug("conn establish %d", quiche_conn_is_established(conn_io->conn));
}

static void flush_packets_0(struct ev_loop *loop, ev_timer *pacer_timer,
                            int revents) {
    flush_packets(loop, pacer_timer->data, 0);
}

static void flush_packets_1(struct ev_loop *loop, ev_timer *pacer_timer,
                            int revents) {
    flush_packets(loop, pacer_timer->data, 1);
}

static void recv_cb(struct ev_loop *loop, ev_io *w, int revents, uint8_t path) {
    struct conn_io *tmp, *conn_io = NULL;
    static uint8_t buf_with_time[MAX_BLOCK_SIZE];
    static uint8_t read_time[TIME_SIZE];
    static uint8_t buf[MAX_BLOCK_SIZE];
    static uint8_t out_process[MAX_DATAGRAM_SIZE];
    static uint8_t first_pkt_of_second_path[] = "Second";

    log_debug("---------- recv_cb path %d----------", path);

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);

        ssize_t nread =
            recvfrom(conns->socks[path], buf_with_time, sizeof(buf_with_time),
                     0, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (nread == 0) {
            log_error("no message to read");
            return;
        }
        if (nread < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                log_debug("recv would block");
                break;
            }

            log_error("recvfrom error: %s", strerror(errno));
            return;
        }

        char host[NI_MAXHOST], service[NI_MAXSERV];
        int res = getnameinfo((struct sockaddr *)&peer_addr, peer_addr_len,
                              host, NI_MAXHOST, service, NI_MAXSERV,
                              NI_NUMERICHOST | NI_NUMERICSERV);
        if (res == 0) {
            log_info("Received %zd bytes from %s:%s", nread, host, service);
        } else {
            log_error("getnameinfo error: %s", gai_strerror(res));
        }

        // get trans time
        memcpy(read_time, buf_with_time, TIME_SIZE);
        uint64_t t1 = *(uint64_t *)read_time;
        uint64_t t2 = getCurrentTime_mic();
        log_debug("send: %lu recv: %lu\nclient to server trans time: %lu", t1,
                  t2, t2 - t1);

        // get one way delay
        memcpy(read_time, buf_with_time + TIME_SIZE, TIME_SIZE);
        uint64_t owd = *(uint64_t *)read_time;
        log_debug("one way delay %lu", owd);

        // copy to buf
        nread -= 2 * TIME_SIZE;
        memcpy(buf, (buf_with_time + 2 * TIME_SIZE), nread);

        if (memcmp(buf, first_pkt_of_second_path,
                   sizeof(first_pkt_of_second_path)) == 0) {
            log_info("##### recv from second path #####");

            if (conn_io_outside != NULL && !conn_io_outside->MP_conn_finished) {
                memcpy(&conn_io_outside->pacers[1].addr, &peer_addr,
                       sizeof(struct sockaddr_storage));
                conn_io_outside->pacers[1].addr_len = peer_addr_len;

                log_debug("second path addr set");

                quiche_conn_second_path_is_established(conn_io_outside->conn);
                conn_io_outside->MP_conn_finished = true;

                // after two paths built, blocks are sent.
                // start sending immediately and repeat every 50ms
                ev_timer_init(&conn_io_outside->sender, sender_cb, 0.1, 0.050);
                ev_timer_start(loop, &conn_io_outside->sender);
                conn_io_outside->sender.data = conn_io_outside;

                return;
            }
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, nread, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        log_debug("rc: %d token_len %lu", rc, token_len);
        if (rc < 0) {
            log_error("failed to parse header");
            return;
        }

        // MP: Mapping peer's pdcid to host's mscid and find conn_io
        uint8_t mscid[QUICHE_MAX_CONN_ID_LEN];
        size_t mscid_len = sizeof(mscid);

        int found = 0;
        HASH_ITER(hh, conns->h, conn_io, tmp) {
            found = mp_mapping_pcid_to_mcid(conn_io->conn, dcid, dcid_len,
                                            mscid, &mscid_len);
            if (found) {  // Mapping is success
                log_debug("conn_io found");
                break;
            }
        }

        if (found) {
            HASH_FIND(hh, conns->h, mscid, mscid_len, conn_io);
            log_debug("found true, conn_io==NULL %d", conn_io == NULL);
        }

        // cannot find conn_io
        if (conn_io == NULL) {
            log_debug("version: %X", version);

            if (!quiche_version_is_supported(version)) {
                log_debug("version negotiation");
                ssize_t written =
                    quiche_negotiate_version(scid, scid_len, dcid, dcid_len,
                                             out_process, sizeof(out_process));
                log_debug("negotiatie written %ld", written);
                if (written < 0) {
                    log_error(
                        "failed to create version negotiation packet: %zd",
                        written);
                    return;
                }
                send_packet(conns->socks[path], (struct sockaddr *)&peer_addr,
                            peer_addr_len, out_process, written, 7);
                return;
            }

            if (token_len == 0) {
                log_debug("stateless retry");

                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len, token,
                           &token_len);

                ssize_t written = quiche_retry(
                    scid, scid_len, dcid, dcid_len, dcid, dcid_len, token,
                    token_len, out_process, sizeof(out_process));
                log_debug("retry written %ld", written);
                if (written < 0) {
                    log_error("failed to create retry packet: %zd", written);
                    return;
                }
                send_packet(conns->socks[path], (struct sockaddr *)&peer_addr,
                            peer_addr_len, out_process, written, 7);
                return;
            }

            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                                odcid, &odcid_len)) {
                log_error("invalid address validation token");
                return;
            }

            conn_io = create_conn(loop, odcid, odcid_len);
            conn_io_outside = conn_io;
            if (conn_io == NULL) {
                log_error("create conn failed");
                return;
            }
            log_info("conn created");

            memcpy(&conn_io->pacers[0].addr, &peer_addr, peer_addr_len);
            conn_io->pacers[0].addr_len = peer_addr_len;

            // MP: Create Second Path
            initiate_second_path(conn_io->conn, server_pcid, LOCAL_CONN_ID_LEN,
                                 client_pcid, LOCAL_CONN_ID_LEN);
        }

        if (memcmp(&conn_io->pacers[path].addr, &peer_addr, peer_addr_len) !=
            0) {
            log_error("recv weird message on path %d, sockaddr not equal",
                      path);
            return;
        }

        quiche_conn_get_path_one_way_delay_update(conn_io->conn, owd / 1000.0,
                                                  path);

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, nread, path);
        if (done == QUICHE_ERR_DONE) {
            log_debug("QUICHE done reading");
            break;
        }
        if (done < 0) {
            log_error("failed to process QUIC packet: %zd", done);
            return;
        }

        log_debug("quiche_conn_recv %zd bytes", done);

        quiche_stats stats;
        quiche_conn_stats(conn_io->conn, &stats);
        log_debug(
            "-----recv=%zu sent=%zu lost_init=%zu lost_subseq=%zu "
            "rtt_init=%" PRIu64 "ns rtt_subseq=%" PRIu64 "ns-----",
            stats.recv, stats.sent, stats.lost_init, stats.lost_subseq,
            stats.rtt_init, stats.rtt_subseq);
    }

    // TODO: libuv flush_packets_pacing here
    HASH_ITER(hh, conns->h, conn_io, tmp) {
        // TODO: libev flush_egress here
        flush_packets(loop, conn_io, 0);
        flush_packets(loop, conn_io, 1);

        if (quiche_conn_is_closed(conn_io->conn)) {
            log_debug("conn_is_closed *****");
            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);
            ev_timer_stop(loop, &conn_io->sender);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }

    return;
}

static void on_recv_0(struct ev_loop *loop, ev_io *w, int revents) {
    recv_cb(loop, w, revents, 0);
}

static void on_recv_1(struct ev_loop *loop, ev_io *w, int revents) {
    recv_cb(loop, w, revents, 1);
}

static void sender_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    log_debug("---------- sender_cb ----------");

    if (quiche_conn_is_established(conn_io->conn)) {
        log_debug("quiche_conn_is_established true");
        int deadline = 0;
        int priority = 0;
        int block_size = 0;
        static uint8_t buf[MAX_BLOCK_SIZE];

        deadline = conn_io->conns->configs[conn_io->send_round].deadline;
        priority = conn_io->conns->configs[conn_io->send_round].priority;
        block_size = conn_io->conns->configs[conn_io->send_round].block_size;

        if (block_size > MAX_BLOCK_SIZE) {
            block_size = MAX_BLOCK_SIZE;
        }

        uint64_t stream_id = 4 * (conn_io->send_round + 1) + 1;

        log_debug("stream_id %lu ddl %d prio %d blk %d", stream_id, deadline,
                  priority, block_size);

        ssize_t stream_send_written =
            quiche_conn_stream_send_full(conn_io->conn, stream_id, buf,
                                         block_size, true, deadline, priority);
        if (stream_send_written < 0) {
            log_error("failed to send data round %d", conn_io->send_round);
        } else {
            log_debug("send round %d stream_send_written %zd",
                      conn_io->send_round, stream_send_written);
        }

        conn_io->send_round++;
        if (conn_io->send_round >= MAX_SEND_TIMES) {
            ev_timer_stop(loop, &conn_io->sender);
        }

        log_debug("flush packets");
        if (conn_io->MP_conn_finished) {
            flush_packets(loop, conn_io, 0);
            flush_packets(loop, conn_io, 1);
        }
    }
}

static void timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    log_debug("---------- timeout_cb ----------");

    quiche_conn_on_timeout(conn_io->conn);
    if (conn_io->MP_conn_finished) {
        flush_packets(loop, conn_io, 0);
        flush_packets(loop, conn_io, 1);
    }

    if (quiche_conn_is_closed(conn_io->conn)) {
        log_info("connection closed");
        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        ev_timer_stop(loop, &conn_io->sender);
        ev_timer_stop(loop, &conn_io->pacers[0].pacer_timer);
        ev_timer_stop(loop, &conn_io->pacers[1].pacer_timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);
    }
    return;
}

/***** libev callback END *****/

int64_t init_udp_server(const char *addr, const char *port) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};

    struct addrinfo *ai;
    if (getaddrinfo(addr, port, &hints, &ai) != 0) {
        log_error("failed to resolve addrport: %s", strerror(errno));
        return -1;
    }

    int64_t sock =
        socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK, ai->ai_protocol);
    if (sock < 0) {
        log_error("failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
        log_error("failed to bind socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    freeaddrinfo(ai);

    return sock;
}

int main(int argc, char *argv[]) {
    args.out = stdout;
    args.log = stderr;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    log_info(
        "SERVER_IP1 %s SERVER_PORT1 %s SERVER_IP2 %s SERVER_PORT2 %s "
        "DTP_CONFIG %s\n",
        args.args[0], args.args[1], args.args[2], args.args[3], args.args[4]);

    /***** MP: Init PCID value *****/
    memset(server_pcid, 0x22, sizeof(server_pcid));
    memset(client_pcid, 0x33, sizeof(client_pcid));
    /*******************************/

    struct connections c;
    c.h = NULL;
    c.socks[0] = init_udp_server(args.args[0], args.args[1]);
    c.socks[1] = init_udp_server(args.args[2], args.args[3]);

    int cfgs_len;
    struct dtp_config *cfgs = NULL;
    cfgs = parse_dtp_config(args.args[4], &cfgs_len, &MAX_SEND_TIMES);
    if (cfgs == NULL) {
        log_error("No valid DTP configuration");
        close(c.socks[0]);
        close(c.socks[1]);
        return -1;
    }
    if (cfgs_len <= 0) {
        log_error("Invalid length DTP configuration");
        close(c.socks[0]);
        close(c.socks[1]);
        return -1;
    }
    c.configs = cfgs;
    c.configs_len = cfgs_len;

    conns = &c;

    quiche_enable_debug_logging(quiche_debug_log, NULL);

    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        log_error("failed to create config");
        close(c.socks[0]);
        close(c.socks[1]);
        free(cfgs);
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, "./cert.crt");
    quiche_config_load_priv_key_from_pem_file(config, "./cert.key");
    quiche_config_set_application_protos(
        config, (uint8_t *)"\x05hq-25\x05hq-24\x05hq-23\x08http/0.9", 21);

    quiche_config_set_max_idle_timeout(config, 15000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000000);
    quiche_config_set_initial_max_streams_bidi(config, 1000000000);
    quiche_config_set_initial_max_streams_uni(config, 1000000000);
    quiche_config_set_disable_active_migration(config, true);
    quiche_config_verify_peer(config, false);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

    ev_io watcher[2];
    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher[0], on_recv_0, c.socks[0], EV_READ);
    ev_io_init(&watcher[1], on_recv_1, c.socks[1], EV_READ);
    watcher[0].data = &c;
    watcher[1].data = &c;
    ev_io_start(loop, &watcher[0]);
    ev_io_start(loop, &watcher[1]);

    ev_loop(loop, 0);

    close(c.socks[0]);
    close(c.socks[1]);
    free(cfgs);
    quiche_config_free(config);

    fclose(args.log);
    fclose(args.out);

    return 0;
}