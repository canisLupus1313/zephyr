/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>

#include <zephyr/zephyr.h>
#include <zephyr/net/socket_offload.h>

#include <errno.h>
#include "sockets_internal.h"

#include <openthread/message.h>
#include <openthread/udp.h>
#include <net/openthread.h>

#define SD_TO_OBJ(sd) ((void *)(sd + 1))
#define OBJ_TO_SD(obj) (((int)obj) - 1)
#define UDP_PORT 4242

static otUdpSocket sUdpSocket;

static int openthread_close(void *obj)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

static int openthread_bind(void *obj, const struct sockaddr *addr,
			   socklen_t addrlen)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

static int openthread_listen(void *obj, int backlog)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

void handleUdpReceive(void *aContext, otMessage *aMessage,
                      const otMessageInfo *aMessageInfo)
{
    OT_UNUSED_VARIABLE(aContext);
    OT_UNUSED_VARIABLE(aMessage);
    OT_UNUSED_VARIABLE(aMessageInfo);
}

static int openthread_connect(void *obj, const struct sockaddr *addr,
			      socklen_t addrlen)
{
	otSockAddr  listenSockAddr;
	struct openthread_context *context = openthread_get_default_context();
	printk("socket offloading %s\n", __func__);

	memset(&sUdpSocket, 0, sizeof(sUdpSocket));
    memset(&listenSockAddr, 0, sizeof(listenSockAddr));

    listenSockAddr.mPort    = UDP_PORT;

    otUdpOpen(context->instance, &sUdpSocket, handleUdpReceive, context->instance);
    otUdpBind(context->instance, &sUdpSocket, &listenSockAddr, OT_NETIF_THREAD);

    return 0;
}

static int openthread_setsockopt(void *obj, int level, int optname,
				 const void *optval, socklen_t optlen)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

static int openthread_getsockopt(void *obj, int level, int optname,
				 void *optval, socklen_t *optlen)
{
	printk("socket offloading %s\n", __func__);
	return 0;
}

static ssize_t openthread_recvfrom(void *obj, void *buf, size_t len, int flags,
				   struct sockaddr *from, socklen_t *fromlen)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

static ssize_t openthread_sendto(void *obj, const void *buf, size_t len,
				 int flags, const struct sockaddr *to,
				 socklen_t tolen)
{
	static const char UDP_DEST_ADDR[] = "fdde:ad00:beef::2";

	struct openthread_context *context = openthread_get_default_context();

	printk("socket offloading %s\n", __func__);


    otError       error = OT_ERROR_NONE;
    otMessage *   message;
    otMessageInfo messageInfo;
    otIp6Address  destinationAddr;

    memset(&messageInfo, 0, sizeof(messageInfo));

    otIp6AddressFromString(UDP_DEST_ADDR, &destinationAddr);
    messageInfo.mPeerAddr    = destinationAddr;
    messageInfo.mPeerPort    = UDP_PORT;

    message = otUdpNewMessage(context->instance, NULL);
    if (message == NULL) {
		error = OT_ERROR_NO_BUFS;
		goto exit;
	}

    error = otMessageAppend(message, (const char*)buf, len);
	if (error != OT_ERROR_NONE) {
		goto exit;
	}

    error = otUdpSend(context->instance, &sUdpSocket, message, &messageInfo);

 exit:
	printk("socket offloading %s error no: %d\n", __func__, error);

    if (error != OT_ERROR_NONE && message != NULL)
    {
        otMessageFree(message);
		return -1;
    }

    return len;
}

static ssize_t openthread_sendmsg(void *obj, const struct msghdr *msg,
				  int flags)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

static int openthread_getaddrinfo(const char *node, const char *service,
				  const struct zsock_addrinfo *hints,
				  struct zsock_addrinfo **res)
{
	printk("socket offloading %s\n", __func__);
	return 0;
}

static void openthread_freeaddrinfo(struct zsock_addrinfo *res)
{
	printk("socket offloading %s\n", __func__);
}

static int openthread_ioctl(void *obj, unsigned int request, va_list args)
{
	printk("socket offloading %s\n", __func__);
    return 0;
}

static ssize_t openthread_read(void *obj, void *buffer, size_t count)
{
	printk("socket offloading %s\n", __func__);
	return openthread_recvfrom(obj, buffer, count, 0, NULL, 0);
}

static ssize_t openthread_write(void *obj, const void *buffer,
					  size_t count)
{
	printk("socket offloading %s\n", __func__);
	return 0;
}

static int openthread_socket_accept(void *obj, struct sockaddr *addr,
			     socklen_t *addrlen)
{
	printk("socket offloading %s\n", __func__);
	return 0;
}

void openthread_sockets_init(void)
{
	printk("Hello socket offloading\n");
}

static bool openthread_is_supported(int family, int type, int proto)
{
	printk("socket offloading %s\n", __func__);
	return true;
}

static const struct socket_op_vtable openthread_socket_fd_op_vtable;

int openthread_socket_create(int family, int type, int proto)
{
	printk("socket offloading %s\n", __func__);
	int fd = z_reserve_fd();
	int sock;

	if (fd < 0) {
		printk("socket offloading %s fd not reserved\n", __func__);
		return -1;
	}

	sock = 3;
	if (sock < 0) {
		z_free_fd(fd);
		printk("socket offloading %s sock inccrrect\n", __func__);
		return -1;
	}

	z_finalize_fd(fd, SD_TO_OBJ(sock),
		      (const struct fd_op_vtable *)
					&openthread_socket_fd_op_vtable);

					    otSockAddr  listenSockAddr;

	return fd;
}

static const struct socket_op_vtable openthread_socket_fd_op_vtable = {
	.fd_vtable = {
		.read = openthread_read,
		.write = openthread_write,
		.close = openthread_close,
		.ioctl = openthread_ioctl,
	},
	.bind = openthread_bind,
	.connect = openthread_connect,
	.listen = openthread_listen,
	.accept = openthread_socket_accept,
	.sendto = openthread_sendto,
	.sendmsg = openthread_sendmsg,
	.recvfrom = openthread_recvfrom,
	.getsockopt = openthread_getsockopt,
	.setsockopt = openthread_setsockopt,
};


#ifdef CONFIG_NET_SOCKETS_OFFLOAD
NET_SOCKET_OFFLOAD_REGISTER(openthread, CONFIG_NET_SOCKETS_OFFLOAD_PRIORITY, AF_UNSPEC,
			    openthread_is_supported, openthread_socket_create);
#endif

const struct socket_dns_offload openthread_dns_ops = {
	.getaddrinfo = openthread_getaddrinfo,
	.freeaddrinfo = openthread_freeaddrinfo,
};
