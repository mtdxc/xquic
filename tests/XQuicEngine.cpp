/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <event2/event.h>
#include <inttypes.h>
#include "XQuicEngine.h"
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include "platform.h"
#include <string>
#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/wait.h>
#else
#include <io.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"event.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Iphlpapi.lib")
#endif

#define XQC_FIRST_OCTET 1

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_ALPN_TRANSPORT "transport"

#define XQC_MAX_LOG_LEN 2048

struct event_base *eb;
double g_copa_ai = 1.0;
double g_copa_delta = 0.05;
int g_echo = 0;
int g_send_body_size = 1024 * 1024;
int g_send_body_size_defined = 0;
int g_save_body = 0;
int g_read_body = 0;
int g_test_case;
int g_ipv6 = 0;
int g_batch = 0;
int g_lb_cid_encryption_on = 0;
char g_write_file[256];
char g_read_file[256];
char g_log_path[256];
char g_session_ticket_file[] = "session_ticket.key";
char g_host[64] = "test.xquic.com";
char g_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[256];
char g_sid[XQC_MAX_CID_LEN];
char g_lb_cid_enc_key[XQC_LB_CID_KEY_LEN];
size_t g_sid_len = 0;
size_t g_lb_cid_enc_key_len = 0;
static uint64_t last_snd_ts;

int ReadFileContent(const char* path, std::string& content) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END);
    int len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    content.resize(len);
    int ret = fread(&content[0], 1, len, fp);
    if (ret != len) {
        printf("fread error %d!=%d", ret, len);
        content.resize(ret);
    }
    fclose(fp);
    return ret;
}

static void writeLine(const char* line, FILE* fp) {
    if (!fp) return;
    int len = strlen(line);
    if (!len) return;
    fwrite(line, len, 1, fp);
    if (line[len - 1] != '\n')
        fwrite("\n", 1, 1, fp);
}

static void writeFile(const char* path, const char* data, size_t len) {
    FILE * fp = fopen(path, "wb");
    int write_size = fwrite(data, 1, len, fp);
    if (len != write_size) {
        printf("save error\n");
    }
    fclose(fp);
    return;
}

int writeSocket(int fd, const void* buf, size_t size, const struct sockaddr * peer_addr, socklen_t peer_addrlen)
{
    ssize_t res;
    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_server_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }

    do {
        set_last_sys_errno(0);
        res = sendto(fd, (char*)buf, size, 0, peer_addr, peer_addrlen);
        printf("xqc_server_send write %zd, %s\n", res, strerror(get_last_sys_errno()));
        if (res < 0) {
            printf("xqc_server_write_socket err %zd %s\n", res, strerror(get_last_sys_errno()));
            if (get_last_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }

        }
    } while ((res < 0) && (EINTR == get_last_sys_errno()));

    return res;
}

void XQuicEngine::Destory()
{
    if (server_engine) {
        xqc_h3_ctx_destroy(server_engine);
        xqc_engine_destroy(server_engine);
        server_engine = nullptr;
    }
    if (client_engine) {
        xqc_h3_ctx_destroy(client_engine);
        xqc_engine_destroy(client_engine);
        client_engine = nullptr;
    }
    if (keylog_fd) {
        fclose(keylog_fd);
        keylog_fd = nullptr;
    }
    if (log_fd) {
        fclose(log_fd);
        log_fd = nullptr;
    }
}

XQuicEngine ctx;

int
xqc_server_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    XQuicStream *user_stream = (XQuicStream *) user_data;

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* priority: echo > specified size > specified file > default size */
        if (g_echo) {
            user_stream->send_body = (char*)malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;

        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = (char*)malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;

            }  else {
                user_stream->send_body = (char*)malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_stream_send(stream, (unsigned char*)user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%" PRIu64 "\n", user_stream->send_offset);
        }
    }

    if (g_test_case == 12 /* test linger close */
        && user_stream->send_offset == user_stream->send_body_len)
    {
        XQuicConn *user_conn = (XQuicConn*)xqc_get_conn_user_data_by_stream(stream);
        xqc_conn_close(ctx.server_engine, &user_conn->cid);
        printf("xqc_conn_close\n");
    }

    return 0;
}



int
xqc_server_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    int ret = xqc_server_stream_send(stream, user_data);
    return ret;
}

int
xqc_server_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    XQuicStream *user_stream = (XQuicStream *) user_data;

    if (g_echo && user_stream->recv_body == NULL) {
        user_stream->recv_body = (char*)malloc(MAX_BUF_SIZE);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;
    ssize_t read;
    ssize_t read_sum = 0;
    do {
        read = xqc_stream_recv(stream, (unsigned char*)buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }
        read_sum += read;

        /* write received body to file */
        if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }

        if (save) {
            fflush(user_stream->recv_body_fp);
        }

        /* write received body to memory */
        if (g_echo) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    if (fin) {
        xqc_server_stream_send(stream, user_data);
    }
    return 0;
}

#define MAX_HEADER 100

int
xqc_server_request_send(xqc_h3_request_t *h3_request, XQuicStream *user_stream)
{
    ssize_t ret = 0;
    int header_cnt = 6;
    xqc_http_header_t header[MAX_HEADER] = {
        {
            {":method", 7},
            {"POST", 4},
            0,
        },
        {
            {":scheme", 7},
            {g_scheme, strlen(g_scheme)},
            0,
        },
        {
            {"host", 4},
            {g_host, strlen(g_host)},
            0,
        },
        {
            {":path", 5},
            {g_path, strlen(g_path)},
            0,
        },
        {
            {"content-type", 12},
            {"text/plain", 10},
            0,
        },
        {
            {":status", 7},
            {"200", 3},
            0,
        },
    };

    xqc_http_headers_t headers = {
        header, header_cnt,
    };

    int header_only = 0;
    if (g_echo && user_stream->recv_body_len == 0) {
        header_only = 1;
    }

    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;

        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

        if (header_only) {
            return 0;
        }
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* priority: echo > specified size > specified file > default size */
        if (g_echo) {
            user_stream->send_body = (char*)malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;

        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = (char*)malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;

            } else {
                user_stream->send_body = (char*)malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_body) {
        memset(user_stream->send_body, 0, user_stream->send_body_len);
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, (unsigned char*)user_stream->send_body + user_stream->send_offset,
                                       user_stream->send_body_len - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_h3_request_send_body sent:%zd, offset=%" PRIu64 "\n", ret, user_stream->send_offset);
        }
    }

    if (g_test_case == 12 /* test linger close */
        && user_stream->send_offset == user_stream->send_body_len)
    {
        XQuicConn *user_conn = (XQuicConn*)xqc_h3_get_conn_user_data_by_request(h3_request);
        xqc_h3_conn_close(ctx.server_engine, &user_conn->cid);
        printf("xqc_h3_conn_close\n");
    }

    return 0;
}


int
xqc_server_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    XQuicStream *user_stream = (XQuicStream *) user_data;
    return xqc_server_request_send(h3_request, user_stream);
}

int
xqc_server_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    //DEBUG;
    int ret;
    unsigned char fin = 0;
    XQuicStream *user_stream = (XQuicStream *) user_data;

    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n", (char *)headers->headers[i].name.iov_base, (char *)headers->headers[i].value.iov_base);
        }

        user_stream->header_recvd++;

        if (fin) {
            /* only header. request received, start processing business logic. */
            xqc_server_request_send(h3_request, user_stream);
            return 0;
        }

        /* continue to receive body */
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {

        if (g_echo && user_stream->recv_body == NULL) {
            user_stream->recv_body = (char*)malloc(MAX_BUF_SIZE);
            if (user_stream->recv_body == NULL) {
                printf("recv_body malloc error\n");
                return -1;
            }
        }

        int save = g_save_body;
        if (save && user_stream->recv_body_fp == NULL) {
            user_stream->recv_body_fp = fopen(g_write_file, "wb");
            if (user_stream->recv_body_fp == NULL) {
                printf("open error\n");
                return -1;
            }
        }

        char buff[4096] = {0};
        size_t buff_size = 4096;
        ssize_t read;
        ssize_t read_sum = 0;
        do {
            read = xqc_h3_request_recv_body(h3_request, (unsigned char*)buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;

            } else if (read < 0) {
                printf("xqc_h3_request_recv_body error %zd\n", read);
                return 0;
            }

            read_sum += read;

            /* write received body to file */
            if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
                printf("fwrite error\n");
                return -1;
            }

            if (save) {
                fflush(user_stream->recv_body_fp);
            }

            /* write received body to memory */
            if (g_echo) {
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
            }
            user_stream->recv_body_len += read;

        } while (read > 0 && !fin);

        printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;
        printf("h3 fin only received\n");
    }

    if (fin) {
        xqc_server_request_send(h3_request, user_stream);
    }

    return 0;
}

void XQuicEngine::sockRead()
{
    //DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    uint64_t recv_time;

#ifdef __linux__
    int batch = 0; /* packets are not necessarily on the same connection */
    if (batch) {
#define VLEN 100
#define BUFSIZE XQC_PACKET_TMP_BUF_LEN
#define TIMEOUT 10
        struct sockaddr_in6 pa[VLEN];
        struct mmsghdr msgs[VLEN];
        struct iovec iovecs[VLEN];
        char bufs[VLEN][BUFSIZE+1];
        struct timespec timeout;
        int retval;

        do {
            memset(msgs, 0, sizeof(msgs));
            for (int i = 0; i < VLEN; i++) {
                iovecs[i]bufs[i];
                iovecs[i]BUFSIZE;
                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &pa[i];
                msgs[i].msg_hdr.msg_namelen = peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = xqc_now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                if (xqc_engine_packet_process(server_engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                              (struct sockaddr *) (&pa[i]), peer_addrlen,
                                              (xqc_msec_t) recv_time, NULL) != XQC_OK)
                {
                    printf("xqc_server_read_handler: packet process err\n");
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    do {
        recv_size = recvfrom(fd, (char*)packet_buf, sizeof(packet_buf), 0, 
            (struct sockaddr *) &peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_last_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_last_sys_errno()));
            break;
        }

        /* amplification limit */
        if (g_test_case == 8) {
            static int loss_num = 0;
            loss_num++;
            /* continuous loss to make server at amplification limit */
            if (loss_num >= 2 && loss_num <= 10) {
                continue;
            }
        }

        recv_sum += recv_size;

        recv_time = xqc_now();
        //printf("xqc_server_read_handler recv_size=%zd, recv_time=%llu, now=%llu, recv_total=%d\n", recv_size, recv_time, now(), ++g_recv_total);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->peer_addr.sin_addr), ntohs(ctx->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));*/
        if (xqc_engine_packet_process(server_engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&local_addr), local_addrlen,
                                      (struct sockaddr *) (&peer_addr), peer_addrlen,
                                      (xqc_msec_t) recv_time, NULL) != XQC_OK)
        {
            printf("xqc_server_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);

finish_recv:
    printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(server_engine);
}

static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    ctx.local_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    struct sockaddr *saddr = (struct sockaddr *)&ctx.local_addr;
    int size;
    int optval;

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_last_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, (u_long*)&optval) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }
#endif

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    if (type == AF_INET6) {
        memset(saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)saddr;
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        addr_v6->sin6_addr = in6addr_any;

    } else {
        memset(saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        addr_v4->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, saddr, ctx.local_addrlen) < 0) {
        printf("bind socket failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static ssize_t
xqc_server_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf, size_t cid_buflen, void *engine_user_data)
{
    ssize_t              cid_buf_index = 0, i;
    ssize_t              cid_len, sid_len, nonce_len;
    xqc_quic_lb_ctx_t   *quic_lb_ctx;
    xqc_flag_t           encrypt_cid_on;
    uint8_t              out_buf[XQC_MAX_CID_LEN];
    quic_lb_ctx = &(ctx.quic_lb_ctx);
    cid_len = quic_lb_ctx->cid_len;
    sid_len = quic_lb_ctx->sid_len;
    nonce_len = cid_len - sid_len - XQC_FIRST_OCTET;

    if (sid_len < 0 || sid_len > cid_len || cid_len > cid_buflen) {
        return XQC_ERROR;
    }

    cid_buf[cid_buf_index] = quic_lb_ctx->conf_id;
    cid_buf_index += XQC_FIRST_OCTET;

    memcpy(cid_buf + cid_buf_index, quic_lb_ctx->sid_buf, sid_len);
    cid_buf_index += sid_len;

    for (i = cid_buf_index; i < cid_len; i++) {
        cid_buf[i] = (uint8_t)rand();
    }

    memcpy(out_buf, cid_buf, cid_len);

    encrypt_cid_on = quic_lb_ctx->lb_cid_enc_on;
    if (encrypt_cid_on) {
        int res = xqc_lb_cid_encryption(cid_buf, sid_len + nonce_len, out_buf, XQC_MAX_CID_LEN, quic_lb_ctx->lb_cid_key, XQC_LB_CID_KEY_LEN, ctx.server_engine);
        if (res != XQC_OK) {
            printf("|xquic|lb-cid encryption error|");
            return -XQC_EENCRYPT_LB_CID;
        }
    }
    
    memcpy(cid_buf, out_buf, cid_len);

    return cid_len;
}


#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
ssize_t xqc_server_write_mmsg(const struct iovec *msg_iov, unsigned int vlen,
                                const struct sockaddr *peer_addr,
                                socklen_t peer_addrlen, void *user)
{
    printf("write_mmsg!\n");
    const int MAX_SEG = 128;
    XQuicConn *user_conn = (XQuicConn *) user;
    ssize_t res = 0;
    int fd = ctx.fd;
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = (struct iovec *)&msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        set_last_sys_errno(0);
        res = sendmmsg(fd, mmsg, vlen, 0);
        if (res < 0) {
            printf("sendmmsg err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}
#endif

void XQuicLogCB(xqc_log_level_t lvl, const void *buf, size_t count, void *user_data) {
    auto engine = (XQuicEngine*)user_data;
    writeLine((const char*)buf, engine->log_fd);
}

void XQuicEngine::Listen(unsigned char* port, ConnCB cb)
{

}

void XQuicEngine::Connect(const char* servAddr, unsigned char* port, ConnCB cb)
{
    XQuicConn* user_conn = new XQuicConn;
    //user_conn_t *user_conn = xqc_client_user_conn_create(server_addr, server_port, transport);
    if (user_conn == NULL) {
        printf("xqc_client_user_conn_create error\n");
        return;
    }
    
#if 0
    std::string token;
    int token_len = XQC_MAX_TOKEN_LEN; // 
    token_len = ReadFileContent("xqc_token", token);
    if (token_len > 0) {
        user_conn->token = token.data();
        user_conn->token_len = token_len;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    if (g_verify_cert) {
        conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_NEED_VERIFY;
        if (g_verify_cert_allow_self_sign) {
            conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        }
    }

    std::string session_ticket_data, tp_data;

    int session_len = ReadFileContent("test_session", session_ticket_data);
    int tp_len = ReadFileContent("tp_localhost", tp_data);

    if (session_len < 0 || tp_len < 0 || use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;

    }
    else {
        conn_ssl_config.session_ticket_data = session_ticket_data.data();
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data.data();
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }


    const xqc_cid_t *cid;
    if (user_conn->h3) {
        cid = xqc_h3_connect(client_engine, &conn_settings, user_conn->token, user_conn->token_len,
            g_host, g_no_crypt, &conn_ssl_config, user_conn->peer_addr,
            user_conn->peer_addrlen, user_conn);
    }
    else {
        cid = xqc_connect(client_engine, &conn_settings, user_conn->token, user_conn->token_len,
            "127.0.0.1", g_no_crypt, &conn_ssl_config, user_conn->peer_addr,
            user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);
    }
#endif
}

int XQuicEngine::Init(char c_cong_ctl, char c_log_level, bool server)
{
    keylog_fd = fopen("./skeys.log", "a+");
    log_fd = fopen(g_log_path, "a+");

    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    std::string g_session_ticket_key;
    if (server) {
        engine_ssl_config.private_key_file = "./server.key";
        engine_ssl_config.cert_file = "./server.crt";
        int ticket_key_len = ReadFileContent(g_session_ticket_file, g_session_ticket_key);
        if (ticket_key_len < 0) {
            engine_ssl_config.session_ticket_key_data = NULL;
            engine_ssl_config.session_ticket_key_len = 0;
        }
        else {
            engine_ssl_config.session_ticket_key_data = &g_session_ticket_key[0];
            engine_ssl_config.session_ticket_key_len = ticket_key_len;
        }
    }

    xqc_engine_callback_t callback = { 0 };
    callback.set_event_timer = [](xqc_msec_t wake_after, void *user_data) {
        XQuicEngine *ctx = (XQuicEngine *)user_data;
        struct timeval tv;
        tv.tv_sec = wake_after / 1000000;
        tv.tv_usec = wake_after % 1000000;
        // event_add(ctx->ev_engine, &tv);
        // and call xqc_engine_main_logic(ctx->engine);
    };
    callback.log_callbacks = { XQuicLogCB, XQuicLogCB };
    callback.keylog_cb = [](const char *line, void *engine_user_data) {
        auto engine = (XQuicEngine*)engine_user_data;
        writeLine(line, engine->keylog_fd);
    };

    xqc_transport_callbacks_t tcbs = { 0 };
    if (server) {
        tcbs.server_accept = [](xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
        {
            DEBUG;
            XQuicConn *user_conn = new XQuicConn;
            user_conn->engine = engine;
            xqc_conn_set_transport_user_data(conn, user_conn);

            xqc_int_t ret = xqc_conn_get_peer_addr(conn, (struct sockaddr *)&user_conn->peer_addr,
                sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);
            if (ret != XQC_OK) {
                return -1;
            }

            memcpy(&user_conn->cid, cid, sizeof(*cid));
            return 0;
        };
    }
    else {
        tcbs.save_token = [](const unsigned char *token, uint32_t token_len,
            void *conn_user_data) {
            writeFile("xqc_token", (const char*)token, token_len);
        };
        tcbs.save_session_cb = [](const char *data, size_t data_len, void *conn_user_data) {
            writeFile("test_session", data, data_len);
        };
        tcbs.save_tp_cb = [](const char *data, size_t data_len, void *conn_user_data) {
            writeFile("tp_localhost", data, data_len);
        };
        tcbs.conn_closing = [](xqc_connection_t *conn,
            const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data)
        {
            printf("conn closing: %d\n", err_code);
            return XQC_OK;
        };
    }
    tcbs.write_socket = [](const unsigned char *buf, size_t size,
        const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
    {
        XQuicConn *user_conn = (XQuicConn*)user_data; //user_data may be empty when "reset" is sent
        return writeSocket(ctx.fd, buf, size, peer_addr, peer_addrlen);
    };
    tcbs.conn_update_cid_notify = [](xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
    {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn *)user_data;
        memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

        printf("====>RETIRE SCID:%s\n", xqc_scid_str(retire_cid));
        printf("====>SCID:%s\n", xqc_scid_str(new_cid));
        printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.server_engine, new_cid));
    };
    tcbs.cert_verify_cb = [](const unsigned char *certs[],
        const size_t cert_len[], size_t certs_len, void *conn_user_data) {
        /* self-signed cert used in test cases, return >= 0 means success */
        return 0;
    };
    tcbs.stateless_reset = [](const unsigned char *buf, size_t size,
        const struct sockaddr *peer_addr, socklen_t peer_addrlen,
        const struct sockaddr *local_addr, socklen_t local_addrlen,
        void *user_data)
    {
        XQuicConn *user_conn = (XQuicConn*)user_data; //user_data may be empty when "reset" is sent
        return writeSocket(ctx.fd, buf, size, peer_addr, peer_addrlen);
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    uint32_t cong_flags = 0;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
        cong_flags = XQC_BBR_FLAG_NONE;
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR_FLAG_RTTVAR_COMPENSATION;
        }
#endif
    }
#ifndef XQC_DISABLE_RENO
    else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    }
#endif
    else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    }
    else if (c_cong_ctl == 'P') {
        cong_ctrl = xqc_copa_cb;
    }
#ifdef XQC_ENABLE_BBR2
    else if (c_cong_ctl == 'B') {
        cong_ctrl = xqc_bbr2_cb;
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
    else {
        printf("unknown cong_ctrl, option is b, r, c\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings;
    conn_settings.pacing_on = 1;
    conn_settings.cong_ctrl_callback = cong_ctrl;
    conn_settings.cc_params.customize_on = 1;
    conn_settings.cc_params.init_cwnd = 32;
    conn_settings.cc_params.cc_optimization_flags = cong_flags;
    conn_settings.cc_params.copa_delta_ai_unit = 1.0;
    conn_settings.cc_params.copa_delta_base = 0.05;

    conn_settings.spurious_loss_detect_on = 0;
    if (!server) {
        conn_settings.proto_version = XQC_VERSION_V1;
        conn_settings.spurious_loss_detect_on = 0;
        conn_settings.keyupdate_pkt_threshold = 0;
    }
    xqc_server_set_conn_settings(&conn_settings);

    xqc_engine_type_t engine_type = server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, engine_type) < 0) {
        return -1;
    }
    switch (c_log_level) {
    case 'e': config.cfg_log_level = XQC_LOG_ERROR; break;
    case 'i': config.cfg_log_level = XQC_LOG_INFO; break;
    case 'w': config.cfg_log_level = XQC_LOG_WARN; break;
    case 's': config.cfg_log_level = XQC_LOG_STATS; break;
    case 'd': config.cfg_log_level = XQC_LOG_DEBUG; break;
    default: config.cfg_log_level = XQC_LOG_DEBUG;
    }
    // test generate cid
    if (server) {
        callback.cid_generate_cb = xqc_server_cid_generate;
        config.cid_negotiate = 1;
        config.cid_len = XQC_MAX_CID_LEN;
    }

    auto engine = xqc_engine_create(engine_type, &config, &engine_ssl_config,
        &callback, &tcbs, this);
    if (engine == NULL) {
        printf("error create engine\n");
        return -1;
    }
    if (server) {
        server_engine = engine;
    }
    else {
        client_engine = client_engine;
    }
    initAlp();
    initH3();

    if (g_test_case == 10) {
        xqc_h3_engine_set_max_field_section_size(engine, 10000000);
    }
    return 0;
}

int XQuicEngine::initH3()
{
    xqc_h3_conn_callbacks_t conn_cbs = { 0 };
    conn_cbs.h3_conn_create_notify = [](xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
    {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn*)conn_user_data;
        if (!user_conn) { // server
            user_conn = new XQuicConn;
            xqc_h3_conn_set_user_data(h3_conn, user_conn);

            xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&user_conn->peer_addr,
                sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);

            memcpy(&user_conn->cid, cid, sizeof(*cid));
        }
        else { // client
            xqc_h3_conn_settings_t settings = { 0 };
            settings.max_field_section_size = 512;
            settings.qpack_max_table_capacity = 4096;
            settings.qpack_blocked_streams = 32;
            xqc_h3_conn_set_settings(h3_conn, &settings);
        }
        if (user_conn->onOpen)
            user_conn->onOpen();
        return 0;
    };
    conn_cbs.h3_conn_close_notify = [](xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data) {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn*)conn_user_data;
        user_conn->printStats();
        if (user_conn->onClose)
            user_conn->onClose();
        delete user_conn;
        return 0;
    };
    conn_cbs.h3_conn_handshake_finished = [](xqc_h3_conn_t *h3_conn, void *conn_user_data)
    {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn *)conn_user_data;
        xqc_conn_stats_t stats;
        if (user_conn->getStats(stats))
           printf("0rtt_flag:%d\n", stats.early_data_flag);
        //xqc_h3_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
    };
    conn_cbs.h3_conn_ping_acked = [](xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data)
    {
        DEBUG;
        if (ping_user_data) {
            printf("====>ping_id:%d\n", *(int *)ping_user_data);

        }
        else {
            printf("====>no ping_id\n");
        }
    };
    xqc_h3_request_callbacks_t req_cbs = { 0 };
    req_cbs.h3_request_create_notify = [](xqc_h3_request_t *h3_request, void *user_data)
    {
        DEBUG;
        XQuicStream *user_stream = new XQuicStream;
        user_stream->h3_request = h3_request;
        xqc_h3_request_set_user_data(h3_request, user_stream);
        if (user_stream->onOpen)
            user_stream->onOpen();
        return 0;
    };
    req_cbs.h3_request_close_notify = [](xqc_h3_request_t *h3_request, void *user_data)
    {
        DEBUG;
        XQuicStream *user_stream = (XQuicStream*)user_data;
        if (user_stream->onClose)
            user_stream->onClose();
        delete user_stream;
        return 0;
    };
    req_cbs.h3_request_write_notify = xqc_server_request_write_notify;
    req_cbs.h3_request_read_notify = xqc_server_request_read_notify;
    req_cbs.h3_request_write_notify = [](xqc_h3_request_t *h3_request, void *user_data) {
        XQuicStream *user_stream = (XQuicStream*)user_data;
        if (user_stream->onWriteResp)
            user_stream->onWriteResp();
        return 0;
    };
    req_cbs.h3_request_read_notify = [](xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data) {
        XQuicStream *user_stream = (XQuicStream*)user_data;
        if (user_stream->onReadReq)
            user_stream->onReadReq(flag);
        return 0;
    };

    /* register http3 callbacks */
    xqc_h3_callbacks_t h3_cbs = { conn_cbs, req_cbs };
    /* init http3 context */
    xqc_int_t ret = xqc_h3_ctx_init(server_engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
    }
    return ret;
}

int XQuicEngine::initAlp()
{
    /* register transport callbacks */
    xqc_conn_callbacks_t conn_cbs;
    conn_cbs.conn_create_notify = [](xqc_connection_t *conn, const xqc_cid_t *cid,
        void *conn_user_data, void *conn_proto_data)
    {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn *)conn_proto_data;
        if(user_conn->onOpen)
            user_conn->onOpen();
        return 0;
    };
    conn_cbs.conn_close_notify = [](xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
    {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn *)conn_proto_data;
        if (user_conn->onClose)
            user_conn->onClose();
        delete user_conn;
        return 0;
    };
    conn_cbs.conn_handshake_finished = [](xqc_connection_t *conn, void *user_data, void *conn_proto_data)
    {
        DEBUG;
        XQuicConn *user_conn = (XQuicConn *)user_data;
    };
    xqc_stream_callbacks_t stream_cbs;
    stream_cbs.stream_create_notify = [](xqc_stream_t *stream, void *user_data)
    {
        DEBUG;
        XQuicStream *user_stream = new XQuicStream;
        user_stream->stream = stream;
        xqc_stream_set_user_data(stream, user_stream);
        if (user_stream->onOpen)
            user_stream->onOpen();
        return 0;
    };
    stream_cbs.stream_close_notify = [](xqc_stream_t *stream, void *user_data)
    {
        DEBUG;
        XQuicStream *user_stream = (XQuicStream*)user_data;
        if (user_stream->onClose)
            user_stream->onClose();
        delete user_stream;
        return 0;
    };
    stream_cbs.stream_read_notify = xqc_server_stream_read_notify;
    stream_cbs.stream_write_notify = xqc_server_stream_write_notify;
    stream_cbs.stream_read_notify = [](xqc_stream_t *stream, void *user_data) {
        XQuicStream *user_stream = (XQuicStream*)user_data;
        if (user_stream->onRead)
            user_stream->onRead();
        return 0;
    };
    stream_cbs.stream_write_notify = [](xqc_stream_t *stream, void *user_data) {
        XQuicStream *user_stream = (XQuicStream*)user_data;
        if (user_stream->onWrite)
            user_stream->onWrite();
        return 0;
    };;
    xqc_app_proto_callbacks_t ap_cbs = { conn_cbs, stream_cbs };
    return xqc_engine_register_alpn(server_engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs);
}

void usage(int argc, char *argv[]) {
    char *prog = argv[0];
    char *const slash = strrchr(prog, '/');
    if (slash) {
        prog = slash + 1;
    }
    printf(
"Usage: %s [Options]\n"
"\n"
"Options:\n"
"   -p    Server port.\n"
"   -e    Echo. Send received body.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic P:copa B:bbr2 bbr+ bbr2+\n"
"   -A    Copa parameter (additive increase unit)\n"
"   -D    Copa paramter (delta)\n"
"   -C    Pacing on.\n"
"   -s    Body size to send.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority e > s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -x    Test case ID\n"
"   -6    IPv6\n"
"   -b    batch\n"
"   -S    server sid\n"
"   -E    load balance id encryption on\n"
"   -K    load balance id encryption key\n"
"   -o    Output log file path, default ./slog\n"
, prog);
}


int main1() {

    int server_port = TEST_PORT;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    int pacing_on = 0;
    strncpy(g_log_path, "./slog", sizeof(g_log_path));

    //eb = event_base_new();
    //ctx.ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, &ctx);

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
    if (g_batch) {
        tcbs.write_mmsg = xqc_server_write_mmsg,
        config.sendmmsg_on = 1;
    }
#endif

    /* test server cid negotiate */
    if (g_test_case == 1 || g_test_case == 5 || g_test_case == 6 || g_sid_len != 0) {

        if (g_lb_cid_enc_key_len == 0) {
            int i = 0;
            for (i = 0; i < XQC_LB_CID_KEY_LEN; i++) {
                g_lb_cid_enc_key[i] = (uint8_t)rand();
            }
            
        }
    }

    /* for lb cid generate */
    memcpy(ctx.quic_lb_ctx.sid_buf, g_sid, g_sid_len);
    memcpy(ctx.quic_lb_ctx.lb_cid_key, g_lb_cid_enc_key, XQC_LB_CID_KEY_LEN);
    ctx.quic_lb_ctx.lb_cid_enc_on = g_lb_cid_encryption_on;
    ctx.quic_lb_ctx.sid_len = g_sid_len;
    ctx.quic_lb_ctx.conf_id = 0;
    ctx.quic_lb_ctx.cid_len = XQC_MAX_CID_LEN;

    ctx.fd = xqc_server_create_socket(TEST_ADDR, server_port);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    // ctx.ev_socket = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, &ctx);
    // event_add(ctx.ev_socket, NULL);
    last_snd_ts = 0;
    // event_base_dispatch(eb);
    getchar();
    ctx.Destory();
    return 0;
}

bool XQuicConn::getStats(xqc_conn_stats_t& stat)
{
    stat = xqc_conn_get_stats(engine, &cid);
    return true;
}

void XQuicConn::printStats()
{
    xqc_conn_stats_t stats;
    if (getStats(stats)) {
        printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%" PRIu64 " early_data_flag:%d, conn_err:%d, ack_info:%s\n",
            stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);
    }
}

XQuicStream* XQuicConn::CreateStream()
{
    XQuicStream *user_stream = new XQuicStream;
    // user_stream->user_conn = this;
    user_stream->stream = xqc_stream_create(engine, &cid, user_stream);
    if (user_stream->stream == NULL) {
        printf("xqc_stream_create error\n");
        delete user_stream;
        return nullptr;
    }
    return user_stream;
}

void XQuicConn::Close()
{
    if (engine)
        xqc_conn_close(engine, &cid);
}

void XQuicStream::Close()
{
    if (stream) {
        xqc_stream_close(stream);
        stream = nullptr;
    }
    if (h3_request) {
        xqc_h3_request_close(h3_request);
        h3_request = nullptr;
    }
}

xqc_stream_id_t XQuicStream::id()
{
    if (stream)
        return xqc_stream_id(stream);
    if (h3_request)
        return xqc_h3_stream_id(h3_request);
}

int XQuicStream::Recv(unsigned char *buf, size_t size, uint8_t *fin)
{

    if (!stream) return -1;
    return xqc_stream_recv(stream, buf, recv_body_len, fin);
}

int XQuicStream::Send(unsigned char *buf, size_t size, uint8_t fin)
{
    if (!stream) return -1;
    return xqc_stream_send(stream, buf, size, fin);
}

int XQuicStream::SendHeader(xqc_http_headers_t *headers, uint8_t fin)
{
    if (!h3_request) return -1;
    xqc_h3_request_send_headers(h3_request, headers, fin);
}

int XQuicStream::RecvHeader(xqc_http_headers_t** head, uint8_t *fin)
{
    if (!h3_request) return -1;
    auto header = xqc_h3_request_recv_headers(h3_request, fin);
    if (header) {
        *head = header;
        return 1;
    }
    return 0;
}

int XQuicStream::SendBody(unsigned char *buf, size_t size, uint8_t fin)
{
    if (!h3_request) return -1;
    return xqc_h3_request_send_body(h3_request, buf, size, fin);
}

int XQuicStream::RecvBody(unsigned char *buf, size_t size, uint8_t *fin)
{
    if (!h3_request) return -1;
    return xqc_h3_request_recv_body(h3_request, buf, size, fin);
}

bool XQuicStream::getH3Stats(xqc_request_stats_t& stat)
{
    if (h3_request) {
        xqc_h3_request_get_stats(h3_request);
        return true;
    }
    return false;
}

