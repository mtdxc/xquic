# QUIC Transport APIs
## 宏
### 内存限制
#### XQC_SUPPORT_VERSION_MAX
XQUIC支持的最大版本号. 当前 XQUIC 支持 draft-29 和 QUIC version 1.

#### XQC_RESET_TOKEN_MAX_KEY_LEN
XQUIC支持的无状态重置stateless reset token的最大长度

#### XQC_MAX_SEND_MSG_ONCE
xqc_send_mmsg_pt回调发送的最大iovec数

#### XQC_MAX_CID_LEN/XQC_MIN_CID_LEN
连接id的最大和最小长度

### Default Configurations
#### XQC_TLS_CIPHERS
缺省tls cipher列表, 当应用层没指定时使用它.

#### XQC_TLS_GROUPS
缺省tls curves列表, 当应用层没指定时使用它.

### Values
#### XQC_TRUE/XQC_FALSE
Values for xqc_bool_t, stands for boolean values.

#### XQC_SOCKET_ERROR/XQC_SOCKET_EAGAIN
write_socket和write_mmsg回调函数返回的错误码.

## Enums
### xqc_engine_type_t
引擎类型，相对于应用层的c/s角色
**​**

- XQC_ENGINE_SERVER (0x00) Server role.
- XQC_ENGINE_CLIENT (0x01) Client Role.

### xqc_proto_version_t
xquic支持的QUIC版本.
**​**

|name|value| desc|
--|--|--
XQC_IDRAFT_INIT_VER | (0x00) | Initial version
XQC_VERSION_V1 | (0x01) | Version defined by RFC 9000.
XQC_IDRAFT_VER_29 | (0x02) | Draft version 29.
XQC_IDRAFT_VER_NEGOTIATION | (0x03) | Version not supported, and shall be negotiated.
XQC_VERSION_MAX || Support version count.

### xqc_cert_verify_flag_e
证书验证选项

- XQC_TLS_CERT_FLAG_NEED_VERIFY (0x00) : 验证证书.
- XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED (0x01) : 允许自签名证书.

### xqc_0rtt_flag_t
Statistics flag of 0-RTT packets during the lifetime of QUIC connection.
|name|value| desc|
--|--|--
| XQC_0RTT_NONE | (0x00) | No 0-RTT packets were sent or received.|
| XQC_0RTT_ACCEPT | (0x01) | 0-RTT packets were accepted.|
| XQC_0RTT_REJECT | (0x02) | 0-RTT packets were rejected.|

## Types
### xqc_engine_t
xquic engine 管理连接、alpn注册、通用环境配置和回调函数。xqc_engine_t实例由_**xqc_engine_create**_创建，并由 by _**xqc_engine_destroy**_ 释放.

所有xquic机制依赖 xqc_engint_t, 包含创建QUIC连接.
当使用xquic, engine必须是第一个创建的对象，且是最后一个释放的.


### xqc_connection_t
xquic connection, stands for QUIC connection.


### xqc_stream_t
xquic stream, stands for QUIC stream.


### xqc_msec_t/xqc_usec_t
时间戳定义，代表毫秒和微秒.


## 回调函数
xquic将它的回调函数分成两类: 引擎回调函数 和 连接回调函数.

- 引擎回调函数 主要处理环境事件，比如定时器、日志和时间戳等.
- 连接回调函数 主要处理连接事件，如连接创建, 

**ALPN 实现建议**
考虑到ALPN的实现, xquic将 连接回调函数 分成 Transport回调函数 和 ALPN回调函数.

- Transport回调函数：是QUIC传输协议事件集合的抽象, 主要包括在不同应用层协议(Application-Layer-Protocol，以下简称ALP)间的QUIC传输协议的公共属性，比如session ticket、write socket、stateless reset等。不管有什么ALPN，这些回调函数将直接与应用层交互。

- ALPN回调函数 主要涉及连接和流数据的概念，包括连接事件回调函数和流事件回调函数。这些回调函数将先与ALP交互，然后ALP将定义它与上层应用的交互方式.

由于 Transport回调函数 是可重用的，对这些回调函数进行分类，将有助于减少实施新的应用层协议(ALP)时的工作量。

### 引擎回调函数
#### xqc_timestamp_pt
```
typedef xqc_usec_t (*xqc_timestamp_pt)(void);
```
默认情况下，xquic 将使用 _**gettimeofday**_ 来获取时间。不幸的是，在某些操作系统上，此函数的结果可能不精确，应用层可能会通过其他方法获得精确的时间戳。
xqc_timestamp_pt 回调函数允许应用层设置自己的时间戳，尤其是在嵌入式系统上。当进行拥塞控制、设置定时器时会触发此函数，必须返回以微秒为单位的时间戳。

设置这个回调函数是可选的，如果不设置，xquic 将使用 _**gettimeofday**_ 来获取时间戳。

#### xqc_set_event_timer_pt
```
typedef void (*xqc_set_event_timer_pt)(xqc_usec_t wake_after, void *engine_user_data);
```
xquic 没有定时器的实现, 但将通过 **_xqc_set_event_timer_pt_** 函数来通知应用层启动一个定时器。应用层将实现定时器，并在定时器超时时，调用 **_xqc_engine_main_logic_**.

必须设置此回调函数。

#### xqc_cid_generate_pt
```
typedef ssize_t (*xqc_cid_generate_pt)(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
    size_t cid_buflen, void *engine_user_data);
```
CID生成回调函数，在创建新连接或生成新连接id时触发。 
**_ori_cid_** 参数在创建连接时为NULL，在退出或生成新cid时为之前生成的原始cid。
The **_ori_cid_** parameter will be NULL when creating connection, and be the original cid generated before when retiring it or generating a new cid.

此回调是可选的。如果不设置此回调，xquic会自己生成cid。

#### xqc_keylog_pt
```
typedef void (*xqc_keylog_pt)(const char *line, void *engine_user_data);
```
TLS keylog 回调, 被Wireshark用来解密QUIC数据包, 当有新的early traffic secret/handshake traffic secret/traffic secret可用时触发，并通过参数 _line_ 传给应用层。

此回调函数是可选的。


#### xqc_log_write_err/xqc_log_write_stat
```
void (*xqc_log_write_err)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
void (*xqc_log_write_stat)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
```
xquic日志回调函数. 
- **_xqc_log_write_err_** 当存在一个指定等级的xquic错误日志时触发 
- **_xqc_log_write_stat_** 在rtt更新或关闭连接时调用.

此回调函数是可选的。

### QUIC 连接回调函数
#### xqc_socket_write_pt/xqc_send_mmsg_pt
```
typedef ssize_t (*xqc_socket_write_pt)(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
typedef ssize_t (*xqc_send_mmsg_pt)(const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
```
写套接口回调函数, 当需要写数据到网络时触发. 应用层应立即发送数据给对方. 

xquic提供两个写数据回调, xqc_socket_write_pt 一有QUIC数据包就触发, 而 xqc_send_mmsg_pt 将可能以多个QUIC包来触发, 这些数据包存放在 _msg_iov_ 参数中.

xqc_send_mmsg_pt设计成使用sendmmsg, 以提供更好性能, 最大包数由 **_XQC_MAX_SEND_MSG_ONCE_** 定义. 当使用这个特性时, 应用层必须设置这个回调，并要求在初始化 xqc_engine_t 时，打开  **_xqc_config_t_** 中的 **_sendmmsg_on_** 参数.

应用层必须至少实现一个回调函数，如果应用层选择使用 xqc_send_mmsg_pt，它还必须启用 xqc_config_t 中的 sendmmsg_on 参数。


#### xqc_server_accept_pt
```
typedef int (*xqc_server_accept_pt)(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data);
```
接受QUIC连接回调函数，当服务器初始化新连接时触发。应用层由此决定是否接受该连接，通过返回 -1 拒绝连接，而返回其他表示接受。

这个回调函数在服务器中是必选的。

#### xqc_stateless_reset_pt
```
typedef ssize_t (*xqc_stateless_reset_pt)(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data);
```
无状态重置回调函数，当处理一个与QUIC连接无关的UDP包时触发。

这个回调函数是可选的，如没设置，将忽略导致无状态重置事件的数据包。


#### xqc_conn_notify_pt
```
typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data);
```
QUIC 连接事件回调。这是QUIC连接事件的通用签名，包括连接的创建和关闭，在创建或关闭QUIC连接时触发。

这个回调函数是必须的, 和 Application-Layer-Protocols 相关.


#### xqc_stream_notify_pt
```
typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *strm_user_data);
```
通用流回调函数定义，将在流创建、关闭、读取数据、写入数据事件时调用。这些事件回调函数在 xqc_stream_callbacks_t 中定义。

应用层必须实现这些在 xqc_stream_callbacks_t 中定义的回调函数。


#### xqc_save_token_pt
```
typedef void (*xqc_save_token_pt)(const unsigned char *token, uint32_t token_len,
    void *conn_user_data);
```
QUIC 新令牌回调，将在接收到 NEW_TOKEN 帧时触发。应用层应在此回调函数中，将数据保存到设备中，并使用该令牌作为今后连接的参数。
该令牌在今后连接中用做地址验证。

强烈建议客户端实现此回调函数。


#### xqc_save_session_pt
```
typedef void (*xqc_save_string_pt)(const char *data, size_t data_len, void *conn_user_data);
typedef xqc_save_string_pt xqc_save_session_pt;
```
QUIC session ticket回调函数，将在收到新的session ticket时触发。应用层应在此回调函数中，将数据保存到设备，并在未来的连接中利用这些恢复数据，来使用恢复和 0-RTT 功能。

强烈建议客户端实现此回调函数。


#### xqc_save_trans_param_pt
```
typedef void (*xqc_save_string_pt)(const char *data, size_t data_len, void *conn_user_data);
typedef xqc_save_string_pt xqc_save_trans_param_pt;
```
QUIC 传输参数回调函数, will be triggered on receiving server's Transport Parameters in Encrypted Extensions. 应用层应在此回调函数中，将数据保存到设备, 并在未来的连接中利用这些恢复的数据，来使用恢复和 0-RTT 功能。
xquic 定义自己的传输参数格式，这也是可读的.

强烈建议客户端实现此回调函数。


#### xqc_handshake_finished_pt
```
typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *conn_user_data);
```
握手完成回调函数，当QUIC连接握手完成时触发，即TLS协议栈既发送一个Finished消息，又验证了peer的Finished消息。
握手状态对于 QUIC 连接来说至关重要，握手完成事件一般用于统计和调试。

强烈建议实现此回调函数。

#### xqc_conn_ping_ack_notify_pt
```
typedef void (*xqc_conn_ping_ack_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *ping_user_data, void *conn_user_data);
```

收到应用层发送的ping响应的通知. xquic有一个缺省的 max_idle_timeout(120秒), 并提供 xqc_conn_send_ping 接口来主动发送PING帧来保活. 此回调函数将在收到和处理一个由应用层发送的ping帧的响应时触发, 只是用于通知ping成功.

注意：PING 帧可能会丢失且无法恢复，也可能没有 ACK，应用层不应一直等待 ping 的 ack 通知，如果连接持续很长时间，这可能会消耗大量内存。

强烈建议客户端实现此回调函数。

#### xqc_conn_update_cid_notify_pt
```
typedef void (*xqc_conn_update_cid_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *conn_user_data);
```
连接ID更新通知回调，当SCID改变时调用。应用层必须记住来自此回调函数的 new_cid。

此回调函数是必选的。

#### xqc_cert_verify_pt
```
typedef int (*xqc_cert_verify_pt)(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *conn_user_data);
```
证书验证回调函数，将在收到对方的证书时调用。

此回调函数是可选的。

## 数据类型
### xqc_log_callbacks_t
xqc_log_callbacks_t 是 xquic 日志回调函数的集合.
#### 
#### xqc_log_write_err
```
void (*xqc_log_write_err)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
```
Trace日志回调函数, 包含 XQC_LOG_FATAL, XQC_LOG_ERROR, XQC_LOG_WARN, XQC_LOG_STATS, XQC_LOG_INFO, XQC_LOG_DEBUG, xquic会输出高于或等于配置级别的日志。

#### xqc_log_write_stat
统计日志回调函数，在写入XQC_LOG_REPORT或XQC_LOG_STATS级别的日志时触发。主要在连接和流关闭时触发


### xqc_engine_callback_t
xquic 引擎回调函数集合.

### xqc_transport_callbacks_t
xqc_transport_callbacks_t 是 xquic 传输回调函数集合. 这些回调函数被设计成可在不同的ALP实现中重复使用。


### xqc_app_proto_callbacks_t
#### xqc_conn_callbacks_t
QUIC连接回调函数, 属于ALPN-Callback-Function category. ALP将始终关注基本连接事件，例如创建和关闭.

ALP可能定义它自己的连接事件. 这些函数将先将连接事件通知给ALP, 然后ALP将转换成自己定义的事件.


#### xqc_stream_callbacks_t
QUIC流回调函数, 属于ALPN-Callback-Function category. QUIC流数据是ALP的内容, 对于每个ALP会有自己的术语和定义.

此外，ALP 实现应定义其与应用层的接口，然后将QUIC传输事件转换成它自己的事件。

### xqc_config_t
xquic 的通用配置，用于初始化引擎。

### xqc_conn_settings_t
#### xqc_cc_params_t
拥塞控制设置参数。

#### xqc_cong_ctrl_callback_t
拥塞控制回调函数定义，应用层可包括自己的拥塞控制算法，通过实现这个结构中的回调函数，然后将它传给 xquic: passing the implementation to xquic by _**xqc_server_set_conn_settings**_ or _**xqc_connect**_ interfaces with _**xqc_conn_settings_t**_ parameter.

#### xqc_conn_ssl_config_t
xquic 连接的 SSL 配置，主要用于 xquic 客户端。

#### xqc_linger_t
xquic 引入了类似 tcp 的SO_LINGER选项的机制，将延迟连接关闭，直到所有缓冲数据发送完毕。

### xqc_conn_stats_t
QUIC连接统计信息，包括传输数据的发送和接收、网络使用估计、early data、连接错误等。

详见 _**xqc_conn_get_stats**_.

## 接口
### 引擎接口
#### xqc_engine_create
```
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type,
    const xqc_config_t *engine_config,
    const xqc_engine_ssl_config_t *ssl_config,
    const xqc_engine_callback_t *engine_callback,
    const xqc_transport_callbacks_t *transport_cbs,
    void *user_data);
```
xqc_engine_create 创建一个新的 xqc_engine_t 对象.

应用层可在一个进程中创建一个或多个engine，但多个引擎不得共享一个线程，因为 xquic 是单线程的。

#### xqc_engine_destroy
```
void xqc_engine_destroy(xqc_engine_t *engine);
```
销毁引擎对象。

销毁引擎时，如果有任何可用的连接，引擎将立即关闭并销毁连接。

#### xqc_engine_register_alpn
```
xqc_int_t xqc_engine_register_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *ap_cbs);
```
ALP被设计为可扩展的，并且可以用作插件，以提供更大的灵活性。ALPN 注册是应用层协议的抽象。

一个xquic引擎支持注册多个ALP，以ALP名称为key，不同的ALP必须有不同的名称。

一旦注册了，相关ALP的上下文就设置好了，在引擎对象的生命周期内不需要更多的操作。当在服务器注册时，这个ALP将在收到来自客户端的ClientHello时使用，用以协商Application-Layer-Protocol。

应用层可通过实现xqc_app_proto_callbacks_t，来可扩展ALP
Applications can extend Application-Layer-Protocols by implementing xqc_app_proto_callbacks_t on their terms and definitions on QUIC connection and stream data.

#### xqc_engine_unregister_alpn
```
xqc_int_t xqc_engine_unregister_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len);
```
反注册ALP, 以ALP名字为key


#### xqc_engine_get_default_config
```
xqc_int_t xqc_engine_get_default_config(xqc_config_t *config, xqc_engine_type_t engine_type);
```
获取 xquic 引擎的默认配置。

#### xqc_engine_set_config
```
xqc_int_t xqc_engine_set_config(xqc_engine_t *engine, const xqc_config_t *engine_config);
```
配置 engine. 

#### xqc_server_set_conn_settings
```
void xqc_server_set_conn_settings(const xqc_conn_settings_t *settings);
```
为 xquic 连接设置默认设置。新配置将对新创建的连接有效。


#### xqc_engine_set_log_level
```
void xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level);
```
设置引擎的日志级别。这可以在引擎的生命周期内随时调用。


#### xqc_engine_finish_recv/xqc_engine_recv_batch
```
void xqc_engine_finish_recv(xqc_engine_t *engine);
void xqc_engine_recv_batch(xqc_engine_t *engine, xqc_connection_t *conn);
```
从套接字接收所有数据并触发引擎事件流程。

#### xqc_dcid_str_by_scid
```
unsigned char *xqc_dcid_str_by_scid(xqc_engine_t *engine, const xqc_cid_t *scid);
```
通过源连接id(scid)获取连接的目的连接id(dcid).

如果 SCID 无效，将返回 NULL。

#### xqc_engine_config_get_cid_len
```
uint8_t xqc_engine_config_get_cid_len(xqc_engine_t *engine);
```
获取配置的源连接id长度


### 连接接口
#### xqc_connect
```
const xqc_cid_t *xqc_connect(xqc_engine_t *engine,
    const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len,
    const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const char *alpn, void *user_data);
```
创建客户端 QUIC 连接实例，并连接到服务器。

返回的_**xqc_cid_t**_ 是对端 QUIC 连接的源连接 id，作为连接的唯一标识存储。源连接id 将来可能会更改，应用层应修改其存储的 源连接id 值。

#### xqc_conn_close
```
xqc_int_t xqc_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);
```
关闭 xquic 连接实例。

_xqc_conn_close_ 将关闭连接。xquic 将发送 CONNECTION_CLOSE 帧给 peer 并等待销毁。应用层不得删除 与xquic连接相关的上下文，直到连接关闭回调函数被触发。（就是在连接关闭函数中才可安全销毁上下文）

#### xqc_conn_get_errno
```
xqc_int_t xqc_conn_get_errno(xqc_connection_t *conn);
```
获取指定连接的错误代码。


#### xqc_conn_set_transport_user_data
```
void xqc_conn_set_transport_user_data(xqc_connection_t *conn, void *user_data);
```
Set user_data for Transport callback functions.


#### xqc_conn_set_alp_user_data
```
void xqc_conn_set_alp_user_data(xqc_connection_t *conn, void *app_proto_user_data);
```
Set user_data for ALPN callback functions.  


#### xqc_conn_get_peer_addr
```
xqc_int_t xqc_conn_get_peer_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);
```
获取对端的地址信息.


#### xqc_conn_get_local_addr
```
xqc_int_t xqc_conn_get_local_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *local_addr_len);
```
获取本地端地址信息.


#### xqc_conn_send_ping
```
xqc_int_t xqc_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);
```
Send PING to keep alive.

#### xqc_conn_is_ready_to_send_early_data
```
xqc_bool_t xqc_conn_is_ready_to_send_early_data(xqc_connection_t *conn);
```
Check if early data is ready to send.


#### xqc_conn_continue_send
```
xqc_int_t xqc_conn_continue_send(xqc_engine_t *engine, const xqc_cid_t *cid);
```
继续发送。
如果write socket暂时不可用，数据会缓存在xquic中。当写事件再次准备就绪时，则调用xqc_conn_continue_send继续发送数据。

#### xqc_conn_get_stats
```
xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid);
```
获取连接的统计信息。


### 流接口
#### xqc_stream_create
```
xqc_stream_t *xqc_stream_create(xqc_engine_t *engine, const xqc_cid_t *cid, void *user_data);
```
创建一个QUIC流来发送数据.

#### xqc_stream_close
```
xqc_int_t xqc_stream_close(xqc_stream_t *stream);
```
关闭QUIC流.


#### xqc_stream_set_user_data
```
void xqc_stream_set_user_data(xqc_stream_t *stream, void *user_data);
```
Set stream layer user_data.


#### xqc_get_conn_user_data_by_stream
```
void *xqc_get_conn_user_data_by_stream(xqc_stream_t *stream);
```
获取与stream实例连接的user_data，可能是client在xqc_stream_create设置的参数，也可以是server在xqc_stream_set_user_data设置的参数。

#### xqc_stream_id
```
xqc_stream_id_t xqc_stream_id(xqc_stream_t *stream);
```
取得流的id.


#### xqc_stream_recv
```
ssize_t xqc_stream_recv(xqc_stream_t *stream, unsigned char *recv_buf, size_t recv_buf_size, uint8_t *fin);
```
从流中接受数据.


#### xqc_stream_send
```
ssize_t xqc_stream_send(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size, uint8_t fin);
```
往流发送数据.

应用层可以发送一个 single_data_len 为 0 的 fin STREAM 帧。
Application can send a single fin STREAM frame with send_data_len is 0.

### 全局接口
#### xqc_packet_parse_cid
```
xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid, uint8_t cid_len,
                               const unsigned char *buf, size_t size);
```
Get cid from payload of a UDP packet.
从 UDP 数据包的负载中获取 cid.

#### xqc_cid_is_equal
```
xqc_int_t xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src);
```
比对两个cid.
当相等，返回XQC_OK.

#### xqc_scid_str
```
unsigned char *xqc_scid_str(const xqc_cid_t *scid);
```
Transfer scid to human-readable string.

#### xqc_dcid_str
```
unsigned char *xqc_dcid_str(const xqc_cid_t *dcid);
```
Transfer dcid to human-readable string.


# HTTP/3 APIs
## Enums
### xqc_request_notify_flag_t

_xqc_h3_request_read_notify_pt_ 回调函数的读取通知标志。

#### XQC_REQ_NOTIFY_READ_NULL
读取标题标志，当没有内容可读时将设置此标志。

#### XQC_REQ_NOTIFY_READ_HEADER
读取标题标志，这将在处理第一个标头时设置。

#### XQC_REQ_NOTIFY_READ_BODY
读取主体标志，这将在处理数据帧时设置。

#### XQC_REQ_NOTIFY_READ_TRAILER
Read trailer section flag, this will be set when trailer HEADERS frame is processed. (\r\n?)

#### XQC_REQ_NOTIFY_READ_EMPTY_FIN
读取空的fin标记，在通知HEADERS和DATA的同时收到单个fin frame会触发该通知回调。该标志永远不会与其他标志一起设置。

### xqc_http3_nv_flag_t
xqc_h3_request_send_headers 中输入header的名称/值的标志，可用于优化动态表的使用。

#### XQC_HTTP_HEADER_FLAG_NONE
没有设置标志。使用默认策略编码header。

#### XQC_HTTP_HEADER_FLAG_NEVER_INDEX
header的名称和值应按文字编码，并且永远不会索引。

#### XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE
header的value是可变的，永远不能放入动态表中索引。这将减少动态表中的无用数据，并提高命中率。

有些header可能用的很频繁，但value不同，将这些value放入动态表中是一种浪费。应用层可以使用这个标志告诉QPACK不要把value放到动态表中。

## 类型
### xqc_h3_conn_t
HTTP/3 连接，依赖于 QUIC Transport 连接.

### xqc_h3_request_t
HTTP/3 请求流，依赖于 QUIC Transport 的双向流.

### 回调函数
#### xqc_h3_conn_notify_pt
```
typedef int (*xqc_h3_conn_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, 
    void *h3c_user_data);
```
http3 连接状态回调函数的定义。包括创建和关闭。


#### xqc_h3_handshake_finished_pt
```
typedef void (*xqc_h3_handshake_finished_pt)(xqc_h3_conn_t *h3_conn, void *h3c_user_data);
```
握手完成回调函数，在QUIC传输握手完成时触发。

#### xqc_h3_conn_ping_ack_notify_pt
```
typedef void (*xqc_h3_conn_ping_ack_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *ping_user_data, void *h3c_user_data);
```
Notification of PING frame acknowledgment from peer. 


#### xqc_h3_request_notify_pt
```
typedef int (*xqc_h3_request_notify_pt)(xqc_h3_request_t *h3_request, void *h3s_user_data);
```
通用请求通知回调，包括请求创建、关闭、写入事件。


#### xqc_h3_request_read_notify_pt
```
typedef int (*xqc_h3_request_read_notify_pt)(xqc_h3_request_t *h3_request, 
    xqc_request_notify_flag_t flag, void *h3s_user_data);
```
读数据回调，当收到并解码 整个 HEADERS 或 DATA 帧时触发。

详见 _xqc_request_notify_flag_t_.

## 数据类型
### xqc_http_header_t
http header的定义。
#### name/value
The name and value of a http header.

#### flags
Header flags of xqc_http3_nv_flag_t with OR operator, see xqc_http3_nv_flag_t.


### xqc_http_headers_t
- headers Array of headers.
- count Number of headers.
- capacity Capacity of headers.
- total_len Sum of the length of names and values in headers array.


### xqc_request_stats_t
请求流的统计信息。详见 _xqc_h3_request_get_stats_.
- send_body_size Total size of sent body.
- recv_body_size Total size of received body.
- send_header_size Total size of sent headers.
- recv_header_size Total size of received headers.
- stream_err http3 请求或 QUIC 传输流的错误代码.


### xqc_h3_conn_settings_t
HTTP/3 connection settings.
- max_field_section_size http3设置帧的SETTINGS_MAX_FIELD_SECTION_SIZE参数.
- max_pushes Max push streams, which is actually not used.
- qpack_max_table_capacity http3设置帧的SETTINGS_QPACK_MAX_TABLE_CAPACITY参数.
- qpack_blocked_streams http3设置帧的SETTINGS_QPACK_BLOCKED_STREAMS参数.


### xqc_h3_conn_callbacks_t
http3 连接事件的集合。

#### h3_conn_create_notify
http3 连接创建回调，服务器必选，客户端可选。

#### h3_conn_close_notify
http3 连接关闭回调。

#### h3_conn_handshake_finished
握手完成回调。这将在收到 HANDSHAKE_DONE 时触发。

#### h3_conn_ping_acked
ping ack回调。这将在 ping 被确认时触发。这个功能是可选的


### xqc_h3_request_callbacks_t
#### h3_request_create_notify
请求创建通知。它会在请求创建后触发，服务器端必填，客户端可选。

#### h3_request_close_notify
请求关闭通知。这将在请求关闭后触发。

#### h3_request_read_notify
请求读取通知回调。这将在收到 http 标头或正文后触发。

#### h3_request_write_notify
请求写入通知回调。触发后，用户可继续发送标题或正文


### xqc_h3_callbacks_t
http3 连接和请求回调函数的集合。这些回调函数介于http3层和应用层之间。

## 接口
### H3上下文接口
H3上下文保存http3层和应用层之间的回调函数地址。

#### xqc_h3_ctx_init
```
xqc_int_t xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs);
```
将 h3 上下文初始化为 xqc_engine_t，这必须在创建任何 http3 连接之前调用。

#### xqc_h3_ctx_destroy
```
xqc_int_t xqc_h3_ctx_destroy(xqc_engine_t *engine);
```
销毁 h3 上下文，调用此接口后，不得创建 h3 连接或 h3 请求。

#### xqc_h3_engine_set_max_dtable_capacity
```
void xqc_h3_engine_set_max_dtable_capacity(xqc_engine_t *engine, size_t capacity);
```
设置最大 h3 最大动态表容量。此功能只会影响之后创建的 h3 连接，现有的 h3 连接不会受到影响。


#### xqc_h3_engine_set_max_field_section_size
```
void xqc_h3_engine_set_max_field_section_size(xqc_engine_t *engine, size_t size);
```
Set max h3 field section size.


### H3连接接口
#### xqc_h3_connect
```
const xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);
```
创建一个 http3 连接实例。
这个接口主要是为客户端设计的。

#### xqc_h3_conn_close
```
xqc_int_t xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);
```
销毁一个 http 连接实例。


#### xqc_h3_conn_get_xqc_conn
```
xqc_connection_t *xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3c);
```
获取 xquic 的 Transport 连接的实例，h3 的实例依赖于该实例。


#### xqc_h3_conn_get_errno
```
xqc_int_t xqc_h3_conn_get_errno(xqc_h3_conn_t *h3c);
```
获取连接错误代码。


#### xqc_h3_conn_set_user_data
```
void xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3c, void *user_data);
```
为http3连接设置user_data，user_data可以是http3连接的应用层上下文。

#### xqc_h3_conn_set_settings
```
void xqc_h3_conn_set_settings(xqc_h3_conn_t *h3c, const xqc_h3_conn_settings_t *h3_conn_settings);
```
设置h3连接的设置，用户可在 h3_conn_create_notify 回调函数触发时调用该函数。

#### xqc_h3_conn_get_peer_addr
```
xqc_int_t xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);
```
获取对方地址信息，服务器应在 h3_conn_create_notify 触发时调用此方法。

#### xqc_h3_conn_get_local_addr
```
xqc_int_t xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr,  socklen_t addr_cap,
    socklen_t *local_addr_len);
```
获取本地地址信息，服务器应在 h3_conn_create_notify 触发时调用此方法。

#### xqc_h3_conn_send_ping
```
xqc_int_t xqc_h3_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);
```
向对端发送 PING，如果收到 ack，h3_conn_ping_acked 将回调 ping_user_data.

#### xqc_h3_conn_is_ready_to_send_early_data
```
xqc_bool_t xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3c);
```
检查在 h3 连接上是否可以发送早期数据。


#### xqc_h3_conn_set_qpack_dtable_cap
```
xqc_int_t xqc_h3_conn_set_qpack_dtable_cap(xqc_h3_conn_t *h3c, size_t capacity);
```
设置现有 h3 连接的动态表容量。
如果容量变小，新的容量无法容纳原动态表中已插入的条目，最早的条目将被擦除。


### H3请求接口
#### xqc_h3_request_create
```
xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid, 
    void *user_data);
```
创建一个 http3 请求。

#### xqc_h3_request_close
```
xqc_int_t xqc_h3_request_close(xqc_h3_request_t *h3_request);

```
关闭一个 http3 请求。
调用该接口后，会通过 h3_request_close_notify 回调函数通知http请求实例的销毁.

#### xqc_h3_request_get_stats
```
xqc_request_stats_t xqc_h3_request_get_stats(xqc_h3_request_t *h3_request);
```
获取h3请求的统计信息。应用层可以在请求被销毁之前随时调用此接口，但不可在 h3_request_close_notify 之后调用它。

#### xqc_h3_request_set_user_data
```
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request, void *user_data);
```
设置http3请求的user_data，作为请求回调函数的参数。
服务器应在 h3_request_create_notify 回调触发时设置 user_data，因为服务器的连接是被动创建的。

#### xqc_h3_request_send_headers
```
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, 
    xqc_http_headers_t *headers, uint8_t fin);
```
Send http headers to peer on a h3 request stream.


#### xqc_h3_request_send_body
```
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request, 
    unsigned char *data, size_t data_size, uint8_t fin);
```
Send http body to the peer on a h3 request stream.

#### xqc_h3_request_finish
```
ssize_t xqc_h3_request_finish(xqc_h3_request_t *h3_request);
```
在对端的方向上完成请求流。如果没发送fin，且应用层没有任何东西可发送，调用这个函数将发送一个只有 fin 的 QUIC STREAM 帧。这在使用 Trailer Section 属性时可能很有用。

如果 h3 请求流的发送缓冲区中有数据，则 fin 将附加在最后一个数据块上。
如果所有数据都已发送，xquic 将发送一个带有零长度数据并设置fin的 QUIC Transport STREAM 帧。

#### xqc_h3_request_recv_headers
```
xqc_http_headers_t *xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin);
```
从请求中获取头部. 这函数将在 h3_request_read_notify 回调触发后调用，且设了XQC_REQ_NOTIFY_READ_HEADER 或 XQC_REQ_NOTIFY_READ_TRAILER标记.

由于 一个 h3 请求流上只有 Header Section 和 Trailer Section，因此最多有 2 个 HEADERS 帧，因此应用层最多可收到 2 个Headers。

#### xqc_h3_request_recv_body
```
ssize_t xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf, 
    size_t recv_buf_size, uint8_t *fin);
```
从请求流中获取body数据. 此函数将在 h3_request_read_notify 回调触发后调用，且设有 XQC_REQ_NOTIFY_READ_BODY 标记.

可在一个 h3 请求流上发送多个数据帧，只要接收并解码一个数据帧，应用层都会收到通知。

xquic 将填充 输入的recv_buf，直到所有数据被复制 或 recv_buf_size 被用完，并返回实际复制的大小。

#### xqc_h3_get_conn_user_data_by_request
```
void *xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request);
```
通过请求获取连接的 user_data

#### xqc_h3_stream_id
```
xqc_stream_id_t xqc_h3_stream_id(xqc_h3_request_t *h3_request);
```
获取h3_request所依赖的QUIC传输流的stream_id。
