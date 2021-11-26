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

const char *argp_program_version = "client-libev 0.0.1";
static char doc[] = "libev mpdtp client";
static char args_doc[] =
    "SERVER_IP1 SERVER_PORT1 SERVER_IP2 SERVER_PORT2 "
    "CLIENT_IP1 CLIENT_PORT1 CLIENT_IP2 CLIENT_PORT2";

static struct argp_option options[] = {
    {"log", 'l', "FILE", 0, "log file with debug and error info"},
    {"out", 'o', "FILE", 0, "output file with received file info"},
    {0}};

struct arguments {
    FILE *log;
    FILE *out;
    char *args[8];
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
            if (state->arg_num >= 8) argp_usage(state);
            arguments->args[state->arg_num] = arg;
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 8) argp_usage(state);
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

static uint64_t chunk_before_deadline = 0;
static uint64_t recv_num = 0;

#define MAX_TOKEN_LEN                                        \
    sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) + \
        QUICHE_MAX_CONN_ID_LEN

struct conn_io {
    ev_timer timer;

    ev_io *watchers[2];
    int socks[2];

    quiche_conn *conn;

    bool first_udp_packet;
};

// MP: PCID (default for second path)
uint8_t server_pcid[LOCAL_CONN_ID_LEN];
uint8_t client_pcid[LOCAL_CONN_ID_LEN];

// MP: server -> client one way delay
uint64_t one_way_delay = 0;

uint64_t t_start = 0;
uint64_t t_end = 0;

/***** DTP configs END *****/

/***** libev callback declare START *****/

static void timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void flush_packets(struct ev_loop *loop, struct conn_io *conn_io,
                          uint8_t path);

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
        fprintf(args.out, "\n");        \
    } while (0)

static void quiche_debug_log(const char *line, void *argp) {
    // log_debug("%s", line);
}

/***** Utilities END *****/

/***** libev callback START *****/

static void send_packet(int sock, const void *buf, size_t size) {
    uint64_t t = getCurrentTime_mic();
    uint8_t *out_time = (uint8_t *)&t;
    uint8_t out_with_time[MAX_DATAGRAM_SIZE + 2 * TIME_SIZE];
    memcpy(out_with_time, out_time, TIME_SIZE);
    out_time = (uint8_t *)&one_way_delay;
    memcpy(out_with_time + TIME_SIZE, out_time, TIME_SIZE);
    memcpy(out_with_time + 2 * TIME_SIZE, buf, size);
    size += 2 * TIME_SIZE;
    ssize_t sent = send(sock, out_with_time, size, 0);
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

    while (true) {
        uint64_t deadline, priority;
        ssize_t written =
            quiche_conn_send(conn_io->conn, out, sizeof(out), path, &deadline, &priority);

        if (written > 0) {
            log_debug("quiche_conn_send written %zd bytes", written);
            send_packet(conn_io->socks[path], out, written);
        } else if (written < -1) {
            log_error("failed to create packet on path %d written %zd", path,
                      written);
            return;
        } else if (written == QUICHE_ERR_DONE) {
            log_debug("path %d done writing", path);
            break;
        }
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9;
    log_debug("ts: %lf", t);
    t = t < 0.0000001 ? 0.0000001 : t;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);

    if (quiche_conn_is_established(conn_io->conn) &&
        !conn_io->first_udp_packet) {
        // connection建立起来之后，启动handshake of second path.
        log_debug("Send first packet of second path");
        uint8_t out[MAX_DATAGRAM_SIZE] = "Second";
        send_packet(conn_io->socks[1], out, sizeof("Second"));
        conn_io->first_udp_packet = true;
    }

    log_debug("conn establish %d", quiche_conn_is_established(conn_io->conn));

    return;
}

static void recv_cb(struct ev_loop *loop, ev_io *w, int revents, uint8_t path) {
    struct conn_io *conn_io = w->data;
    static uint8_t buf_with_time[MAX_BLOCK_SIZE];
    static uint8_t buf[MAX_BLOCK_SIZE];
    static uint8_t read_time[TIME_SIZE];

    log_debug("---------- recv_cb path %d----------", path);

    int recv_count_once = 0;

    while (true) {
        ssize_t nread =
            recv(conn_io->socks[path], buf_with_time, sizeof(buf_with_time), 0);
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
        log_debug("nread %lu", nread);

        // get trans time
        memcpy(read_time, buf_with_time, TIME_SIZE);
        uint64_t t1 = *(uint64_t *)read_time;
        uint64_t t2 = getCurrentTime_mic();
        log_debug("send: %lu recv: %lu\nserver to client trans time: %lu", t1,
                  t2, t2 - t1);

        // copy to buf
        nread -= TIME_SIZE;
        memcpy(buf, buf_with_time + TIME_SIZE, nread);

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

        recv_count_once += 1;
    }

    log_debug("recv_count_once %d", recv_count_once);

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t stream_id = 0;
        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);
        while (quiche_stream_iter_next(readable, &stream_id)) {
            log_debug("stream %lu", stream_id);

            bool fin = false;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, stream_id,
                                                       buf, sizeof(buf), &fin);

            if (recv_len < 0) {
                log_error("stream_recv error %zd", recv_len);
                break;
            }

            if (fin) {
                t_end = getCurrentTime_mic();
                log_debug("stream_recv %zd bytes", recv_len);
                int64_t bct = quiche_conn_get_bct(conn_io->conn, stream_id);
                uint64_t block_size, block_priority, block_deadline;
                quiche_conn_get_block_info(conn_io->conn, stream_id,
                                           &block_size, &block_priority,
                                           &block_deadline);
                // uint64_t goodbytes =
                //     quiche_conn_get_good_recv(conn_io->conn, stream_id);

                log_info("stream %lu received completely", stream_id);
                log_info("recv at %lu, bct %ld", getCurrentTime_mic(), bct);
                recv_num += 1;
                log_info("recv_num %lu", recv_num);

                // TODO: Might need to use goodbytes
                if (bct <= 200) {
                    chunk_before_deadline += 1;
                    log_info("chunk_before_deadline %lu",
                             chunk_before_deadline);
                }

                dump_file("%lu,%ld,%lu,%lu,%lu", stream_id, bct, block_size,
                          block_priority, block_deadline);
            } else {
                log_debug("stream_recv %zd bytes", recv_len);
            }

            static const uint8_t echo[] = "echo\n";
            if (quiche_conn_stream_send(conn_io->conn, stream_id, echo,
                                        sizeof(echo), false) < sizeof(echo)) {
                log_error("failed to echo back");
            }
        }
        quiche_stream_iter_free(readable);
    }

    if (quiche_conn_is_closed(conn_io->conn)) {
        log_debug("connection closed");

        quiche_stats stats;
        quiche_conn_stats(conn_io->conn, &stats);
        log_info(
            "recv=%zu sent=%zu lost_init=%zu "
            "lost_subseq=%zu rtt_init=%" PRIu64 "ns rtt_subseq=%" PRIu64
            "ns recv_num %ld end-start time %luns",
            stats.recv, stats.sent, stats.lost_init, stats.lost_subseq,
            stats.rtt_init, stats.rtt_subseq, recv_num, t_end - t_start);

        ev_break(loop, EVBREAK_ONE);
        return;
    }

    flush_packets(loop, conn_io, path);

    return;
}

static void on_recv_0(struct ev_loop *loop, ev_io *w, int revents) {
    recv_cb(loop, w, revents, 0);
}

static void on_recv_1(struct ev_loop *loop, ev_io *w, int revents) {
    recv_cb(loop, w, revents, 1);
}

static void timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    log_debug("---------- timeout_cb ----------");

    quiche_conn_on_timeout(conn_io->conn);

    flush_packets(loop, conn_io, 0);
    flush_packets(loop, conn_io, 1);

    if (quiche_conn_is_closed(conn_io->conn)) {
        log_info("connection closed");
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);
        log_info(
            "recv=%zu sent=%zu lost_init=%zu "
            "lost_subseq=%zu rtt_init=%" PRIu64 "ns rtt_subseq=%" PRIu64
            "ns recv_num %ld end-start time %luns",
            stats.recv, stats.sent, stats.lost_init, stats.lost_subseq,
            stats.rtt_init, stats.rtt_subseq, recv_num, t_end - t_start);

        ev_break(loop, EVBREAK_ONE);
    }
    return;
}

/***** libev callback END *****/

int64_t init_udp_client(const char *peer_addr, const char *peer_port,
                        const char *self_addr, const char *self_port) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};

    struct addrinfo *peer, *self;
    if (getaddrinfo(peer_addr, peer_port, &hints, &peer) != 0) {
        log_error("failed to resolve peer addrport: %s", strerror(errno));
        return -1;
    }

    if (getaddrinfo(self_addr, self_port, &hints, &self) != 0) {
        log_error("failed to resolve self addrport: %s", strerror(errno));
        return -1;
    }

    int sock = socket(self->ai_family, self->ai_socktype | SOCK_NONBLOCK,
                      self->ai_protocol);
    if (sock < 0) {
        log_error("failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (bind(sock, self->ai_addr, self->ai_addrlen) < 0) {
        log_error("failed to bind socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (connect(sock, peer->ai_addr, peer->ai_addrlen) < 0) {
        log_error("failed to connect socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    freeaddrinfo(peer);
    freeaddrinfo(self);

    return sock;
}

int main(int argc, char *argv[]) {
    args.out = stdout;
    args.log = stderr;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    log_info(
        "SERVER_IP1 %s SERVER_PORT1 %s SERVER_IP2 %s SERVER_PORT2 %s "
        "CLIENT_IP1 %s CLIENT_PORT1 %s CLIENT_IP2 %s CLIENT_PORT2 %s\n",
        args.args[0], args.args[1], args.args[2], args.args[3], args.args[4],
        args.args[5], args.args[6], args.args[7]);

    /***** MP: Init PCID value *****/
    memset(server_pcid, 0x22, sizeof(server_pcid));
    memset(client_pcid, 0x33, sizeof(client_pcid));
    /*******************************/

    struct conn_io c;
    c.socks[0] =
        init_udp_client(args.args[0], args.args[1], args.args[4], args.args[5]);
    c.socks[1] =
        init_udp_client(args.args[2], args.args[3], args.args[6], args.args[7]);

    quiche_enable_debug_logging(quiche_debug_log, NULL);

    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        log_error("failed to create config");
        close(c.socks[0]);
        close(c.socks[1]);
        return -1;
    }

    quiche_config_set_application_protos(
        config, (uint8_t *)"\x05hq-25\x05hq-24\x05hq-23\x08http/0.9", 15);

    quiche_config_set_max_idle_timeout(config, 15000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000000);
    quiche_config_set_initial_max_streams_bidi(config, 1000000000);
    quiche_config_set_initial_max_streams_uni(config, 1000000000);
    quiche_config_set_disable_active_migration(config, true);
    quiche_config_verify_peer(config, false);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

    if (getenv("SSLKEYLOGFILE")) {
        quiche_config_log_keys(config);
    }

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        log_error("failed to open /dev/urandom: %s", strerror(errno));
        close(c.socks[0]);
        close(c.socks[1]);
        return -1;
    }
    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        log_error("failed to create connection ID: %s", strerror(errno));
        close(c.socks[0]);
        close(c.socks[1]);
        return -1;
    }
    dump_file("Stream,bct,size,priority,deadline");

    quiche_conn *conn = quiche_connect(args.args[0], (const uint8_t *)scid,
                                       sizeof(scid), config);

    t_start = getCurrentTime_mic();

    if (conn == NULL) {
        log_error("failed to create connection");
        close(c.socks[0]);
        close(c.socks[1]);
        return -1;
    }

    c.conn = conn;
    c.first_udp_packet = false;

    initiate_second_path(c.conn, client_pcid, LOCAL_CONN_ID_LEN, server_pcid,
                         LOCAL_CONN_ID_LEN);

    ev_io watcher[2];
    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher[0], on_recv_0, c.socks[0], EV_READ);
    ev_io_init(&watcher[1], on_recv_1, c.socks[1], EV_READ);
    watcher[0].data = &c;
    watcher[1].data = &c;
    c.watchers[0] = &watcher[0];
    c.watchers[1] = &watcher[1];
    ev_io_start(loop, &watcher[0]);
    ev_io_start(loop, &watcher[1]);

    ev_init(&c.timer, timeout_cb);
    c.timer.data = &c;

    flush_packets(loop, &c, 0);
    log_debug("sock start");

    ev_loop(loop, 0);

    close(c.socks[0]);
    close(c.socks[1]);
    quiche_conn_free(conn);
    quiche_config_free(config);

    fclose(args.log);
    fclose(args.out);

    return 0;
}