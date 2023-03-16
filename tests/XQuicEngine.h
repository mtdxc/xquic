#pragma once
#include <stdint.h>
#include <functional>
#include <xquic/xquic_typedef.h>
//#include <xquic/xquic.h>
typedef struct xqc_conn_stats_s xqc_conn_stats_t;
typedef struct xqc_request_stats_s xqc_request_stats_t;
typedef struct xqc_http_headers_s xqc_http_headers_t;

struct xqc_quic_lb_ctx_t {
    uint8_t    sid_len;
    uint8_t    sid_buf[XQC_MAX_CID_LEN];
    uint8_t    conf_id;
    uint8_t    cid_len;
    uint8_t    cid_buf[XQC_MAX_CID_LEN];
    uint8_t    lb_cid_key[XQC_LB_CID_KEY_LEN];
    int        lb_cid_enc_on;
};

using EventCB = std::function<void()>;
struct XQuicStream {
    xqc_stream_t       *stream = nullptr;
    xqc_h3_request_t   *h3_request = nullptr;

    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char               *send_body = nullptr;
    size_t              send_body_len;
    size_t              send_body_max;
    char               *recv_body = nullptr;
    size_t              recv_body_len;
    // body写文件
    FILE               *recv_body_fp = nullptr;

    ~XQuicStream() {
        free(recv_body);
        free(send_body);
    }
    // common cbs
    EventCB onOpen;
    EventCB onClose;
    // stream cb
    EventCB onRead;
    EventCB onWrite;
    // h3 cbs
    std::function<void(int flag)> onReadReq;
    EventCB onWriteResp;

    // interface
    void Close();
    // return stream id
    xqc_stream_id_t id();

    // stream api
    int Recv(unsigned char *buf, size_t size, uint8_t *fin);
    int Send(unsigned char *buf, size_t size, uint8_t fin);

    // h3 interface
    int SendHeader(xqc_http_headers_t *headers, uint8_t fin);
    int RecvHeader(xqc_http_headers_t** head, uint8_t *fin);
    int SendBody(unsigned char *buf, size_t size, uint8_t fin);
    int RecvBody(unsigned char *buf, size_t size, uint8_t *fin);
    bool getH3Stats(xqc_request_stats_t& stat);
};

struct XQuicConn {
    xqc_engine_t        *engine;
    struct sockaddr_storage  peer_addr;
    socklen_t            peer_addrlen;
    xqc_cid_t            cid;
    // api
    bool getStats(xqc_conn_stats_t& stat);
    void printStats();
    XQuicStream* CreateStream();
    void Close();
    EventCB onOpen;
    EventCB onClose;
};
typedef std::function<void(XQuicConn*)> ConnCB;

struct XQuicEngine {
    int initH3();
    int initAlp();
    void sockRead();
public:
    // 作为服务器
    void Listen(unsigned char* port, ConnCB cb);
    // 作为客户端
    void Connect(const char* servAddr, unsigned char* port, ConnCB cb);
    int Init(char c_cong_ctl, char log, bool server);
    void Destory();
    int fd;
    struct sockaddr_storage  local_addr;
    socklen_t            local_addrlen;
    //struct event        *ev_socket; // sock fd
    //struct event        *ev_engine; // timer
    xqc_engine_t        *server_engine = nullptr;
    xqc_engine_t        *client_engine = nullptr;
    FILE*                log_fd;
    FILE*                keylog_fd;
    xqc_quic_lb_ctx_t    quic_lb_ctx;
};

