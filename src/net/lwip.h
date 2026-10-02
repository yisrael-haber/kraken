#ifndef KRAKEN_NET_LWIP_H
#define KRAKEN_NET_LWIP_H

#include <stddef.h>
#include <stdint.h>

struct kraken_lwip_interface;

struct kraken_lwip_address {
    uint8_t ip[4];
    uint16_t port;
};

int kraken_lwip_init(void *context, void (*wake)(void *));
void kraken_lwip_finish(void);
struct kraken_lwip_interface *kraken_lwip_add(const uint8_t ip[4], uint8_t prefix,
    const uint8_t *gateway, const uint8_t mac[6], uint16_t mtu, void *context);
void kraken_lwip_remove(struct kraken_lwip_interface *iface);
int kraken_lwip_input(struct kraken_lwip_interface *iface, const uint8_t *frame, size_t length);
int kraken_lwip_output(void **context, uint8_t *frame, size_t capacity);

int kraken_lwip_open(struct kraken_lwip_interface *iface, int kind, uint8_t protocol);
int kraken_lwip_call(int fd, int action, struct kraken_lwip_address *address,
    void *bytes, size_t length);
int kraken_lwip_send_header(struct kraken_lwip_interface *iface, const void *bytes, size_t length);

#endif
