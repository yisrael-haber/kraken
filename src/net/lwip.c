#include "lwip.h"

#include "lwip/etharp.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/netifapi.h"
#include "lwip/pbuf.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define OUTPUT_CAPACITY 64
#define FRAME_CAPACITY 2048

struct kraken_lwip_interface {
    struct netif netif;
    uint8_t mac[6];
    uint16_t mtu;
    void *context;
};

struct output_frame {
    struct kraken_lwip_interface *iface;
    size_t length;
    uint8_t bytes[FRAME_CAPACITY];
};

static struct output_frame outputs[OUTPUT_CAPACITY];
static unsigned int read_index, write_index;
static sys_mutex_t output_mutex;
static int initialized;
static void *wake_context;
static void (*wake_callback)(void *);

static void ready(void *arg) { sys_sem_signal(arg); }

int kraken_lwip_init(void *context, void (*wake)(void *))
{
    if (!initialized) {
        sys_sem_t started;
        if (sys_sem_new(&started, 0) != ERR_OK) return -1;
        tcpip_init(ready, &started);
        sys_sem_wait(&started);
        sys_sem_free(&started);
        if (sys_mutex_new(&output_mutex) != ERR_OK) return -1;
        initialized = 1;
    }
    wake_context = context;
    wake_callback = wake;
    return 0;
}

void kraken_lwip_finish(void)
{
    sys_mutex_lock(&output_mutex);
    read_index = write_index;
    wake_callback = NULL;
    wake_context = NULL;
    sys_mutex_unlock(&output_mutex);
}

static err_t emit(struct netif *netif, struct pbuf *p)
{
    struct kraken_lwip_interface *iface = netif->state;
    err_t result = ERR_MEM;
    sys_mutex_lock(&output_mutex);
    if (p->tot_len <= FRAME_CAPACITY && write_index - read_index < OUTPUT_CAPACITY) {
        struct output_frame *item = &outputs[write_index++ % OUTPUT_CAPACITY];
        item->iface = iface;
        item->length = p->tot_len;
        if (pbuf_copy_partial(p, item->bytes, p->tot_len, 0) == p->tot_len)
            result = ERR_OK;
        else
            --write_index;
    }
    if (result == ERR_OK && wake_callback) wake_callback(wake_context);
    sys_mutex_unlock(&output_mutex);
    return result;
}

static err_t init_interface(struct netif *netif)
{
    struct kraken_lwip_interface *iface = netif->state;
    netif->name[0] = 'k';
    netif->name[1] = 'r';
    netif->hwaddr_len = 6;
    memcpy(netif->hwaddr, iface->mac, 6);
    netif->mtu = iface->mtu;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
    netif->output = etharp_output;
    netif->linkoutput = emit;
    return ERR_OK;
}

struct kraken_lwip_interface *kraken_lwip_add(const uint8_t ip[4], uint8_t prefix,
    const uint8_t *gateway, const uint8_t mac[6], uint16_t mtu, void *context)
{
    struct kraken_lwip_interface *iface = calloc(1, sizeof(*iface));
    ip4_addr_t local, mask, gw;
    uint32_t bits = prefix ? 0xffffffffU << (32 - prefix) : 0;
    if (!iface) return NULL;
    memcpy(iface->mac, mac, 6);
    iface->mtu = mtu;
    iface->context = context;
    IP4_ADDR(&local, ip[0], ip[1], ip[2], ip[3]);
    IP4_ADDR(&mask, bits >> 24, bits >> 16, bits >> 8, bits);
    if (gateway) IP4_ADDR(&gw, gateway[0], gateway[1], gateway[2], gateway[3]);
    else IP4_ADDR(&gw, 0, 0, 0, 0);
    if (netifapi_netif_add(&iface->netif, &local, &mask, &gw, iface,
            init_interface, tcpip_input) != ERR_OK) {
        free(iface);
        return NULL;
    }
    netifapi_netif_set_link_up(&iface->netif);
    netifapi_netif_set_up(&iface->netif);
    return iface;
}

void kraken_lwip_remove(struct kraken_lwip_interface *iface)
{
    unsigned int i;
    netifapi_netif_remove(&iface->netif);
    sys_mutex_lock(&output_mutex);
    for (i = read_index; i != write_index; ++i)
        if (outputs[i % OUTPUT_CAPACITY].iface == iface)
            outputs[i % OUTPUT_CAPACITY].iface = NULL;
    sys_mutex_unlock(&output_mutex);
    free(iface);
}

int kraken_lwip_input(struct kraken_lwip_interface *iface, const uint8_t *frame, size_t length)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
    if (!p) return -1;
    if (pbuf_take(p, frame, length) != ERR_OK || iface->netif.input(p, &iface->netif) != ERR_OK) {
        pbuf_free(p);
        return -1;
    }
    return 0;
}

int kraken_lwip_output(void **context, uint8_t *frame, size_t capacity)
{
    while (1) {
        struct output_frame *item;
        int length;
        sys_mutex_lock(&output_mutex);
        if (read_index == write_index) {
            sys_mutex_unlock(&output_mutex);
            return 0;
        }
        item = &outputs[read_index++ % OUTPUT_CAPACITY];
        if (!item->iface) {
            sys_mutex_unlock(&output_mutex);
            continue;
        }
        if (item->length > capacity) {
            sys_mutex_unlock(&output_mutex);
            return -1;
        }
        *context = item->iface->context;
        length = (int)item->length;
        memcpy(frame, item->bytes, item->length);
        sys_mutex_unlock(&output_mutex);
        return length;
    }
}

static void socket_address(struct sockaddr_in *out, const struct kraken_lwip_address *address)
{
    ip4_addr_t ip;
    memset(out, 0, sizeof(*out));
    IP4_ADDR(&ip, address->ip[0], address->ip[1], address->ip[2], address->ip[3]);
    out->sin_len = sizeof(*out);
    out->sin_family = AF_INET;
    out->sin_port = lwip_htons(address->port);
    out->sin_addr.s_addr = ip.addr;
}

int kraken_lwip_open(struct kraken_lwip_interface *iface, int kind, uint8_t protocol)
{
    struct ifreq device = {0};
    int fd = lwip_socket(AF_INET, kind, protocol);
    if (fd < 0) return -1;
    if (!netif_index_to_name(netif_get_index(&iface->netif), device.ifr_name) ||
        lwip_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &device, sizeof(device)) < 0 ||
        lwip_fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto fail;
    return fd;
fail:
    lwip_close(fd);
    return -1;
}

int kraken_lwip_call(int fd, int action, struct kraken_lwip_address *address,
    void *bytes, size_t length)
{
    struct sockaddr_in raw;
    socklen_t raw_length = sizeof(raw);
    int result;
    if (address) socket_address(&raw, address);
    switch (action) {
        case 0: result = lwip_connect(fd, (struct sockaddr *)&raw, raw_length); break;
        case 1: result = lwip_bind(fd, (struct sockaddr *)&raw, raw_length); break;
        case 2: result = lwip_listen(fd, (int)length); break;
        case 3: result = lwip_accept(fd, (struct sockaddr *)&raw, &raw_length); break;
        case 4: result = address
            ? lwip_sendto(fd, bytes, length, 0, (struct sockaddr *)&raw, raw_length)
            : lwip_send(fd, bytes, length, 0); break;
        case 5: result = lwip_recvfrom(fd, bytes, length, 0, (struct sockaddr *)&raw, &raw_length); break;
        case 6: result = lwip_close(fd); break;
        default: return -1;
    }
    if (result < 0) {
        if (action == 0 && errno == EISCONN) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY) return -2;
        return -1;
    }
    if (result >= 0 && address && (action == 3 || action == 5)) {
        memcpy(address->ip, &raw.sin_addr.s_addr, 4);
        address->port = lwip_ntohs(raw.sin_port);
    }
    if (result >= 0 && action == 3 && lwip_fcntl(result, F_SETFL, O_NONBLOCK) < 0) {
        lwip_close(result);
        return -1;
    }
    return result;
}

int kraken_lwip_send_header(struct kraken_lwip_interface *iface, const void *bytes, size_t length)
{
    struct pbuf *p;
    err_t result;
    if (length < 20 || length > iface->netif.mtu ||
        (((const uint8_t *)bytes)[0] >> 4) != 4) return -1;
    p = pbuf_alloc(PBUF_IP, length, PBUF_RAM);
    if (!p) return -1;
    if (pbuf_take(p, bytes, length) != ERR_OK) {
        pbuf_free(p);
        return -1;
    }
    LOCK_TCPIP_CORE();
    result = ip4_output_if(p, NULL, LWIP_IP_HDRINCL, 0, 0, 0, &iface->netif);
    UNLOCK_TCPIP_CORE();
    pbuf_free(p);
    return result == ERR_OK ? (int)length : -1;
}
