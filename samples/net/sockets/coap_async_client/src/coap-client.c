/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_coap_client_sample, LOG_LEVEL_DBG);

#include <errno.h>
#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_client.h>

#include "net_private.h"

#define COAP_HOST "coap.me"
#define PEER_PORT "5683"
#define MAX_COAP_MSG_LEN 256

/* CoAP socket fd */
static int sock;

/* CoAP Options */
static const char *test_path = "test";
static const char *test_subpath = "path/sub1";
static const char *large_path = "large";
static const char *broken_path = "broken";
static const char *query_path = "query?whatsup";
static const char *separate_path = "separate";
static const char *large_update = "large-update";
static struct addrinfo *address;

static const char *short_payload = "testing";
static const char *test_payload = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";


#define BLOCK_WISE_TRANSFER_SIZE_GET 2048

K_SEM_DEFINE(coap_response, 0, 1);

void coap_callback(uint8_t code, size_t offset, size_t len, const uint8_t *payload, bool last_block,
		   void *user_data)
{	
        if (code == COAP_RESPONSE_CODE_CONTENT ||
	    code == COAP_RESPONSE_CODE_CHANGED ||
	    code == COAP_RESPONSE_CODE_DELETED ||
	    code == COAP_RESPONSE_CODE_CREATED) {
                if (len) {
			//LOG_DBG("Response received", payload);
                        printk("%s", payload);
                } else {
                        LOG_INF("Operation succcesfull\n");
                }
		if (last_block) {
			printk("\n");
			LOG_INF("Last packet received");
			k_sem_give(&coap_response);
		}
        } else {
		LOG_ERR("Error in response %d", code);
		k_sem_give(&coap_response);
	}
}

static int start_coap_client(void)
{

	static struct addrinfo hints;
	int st;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	st = getaddrinfo(COAP_HOST, PEER_PORT, &hints, &address);
	LOG_INF("getaddrinfo status: %d\n", st);

	if (st != 0) {
		LOG_ERR("Unable to resolve address, quitting\n");
		return -errno;
	}
	if (address == NULL) {
		LOG_ERR("Address not found\n");
		return -errno;
	}

	
	sock = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	return 0;
}

int send_coap_request(uint8_t method, const char *path, const char *payload)
{
	struct coap_client_request client_request = {
		.method = method,
		.confirmable = true,
		.path = path,
		.fmt = COAP_CONTENT_FORMAT_TEXT_PLAIN,
		.cb = coap_callback,
		.payload = NULL,
		.len = 0
	};

	if (payload != NULL) {
		client_request.payload = payload;
		client_request.len = strlen(payload);
	}

	while (coap_client_req(sock, address->ai_addr, &client_request, -1) == -EAGAIN) {
		LOG_INF("CoAP client busy");
		k_sleep(K_MSEC(500));
	}
	k_sem_take(&coap_response, K_FOREVER);

	return 0;
}

static int test_coap_msgs(void)
{
	uint8_t test_type = 0U;
	int r;

	while (1) {
		switch (test_type) {
		case 0:
			/* Test CoAP GET method */
			LOG_INF("\nCoAP client GET\n");
			r = send_coap_request(COAP_METHOD_GET, separate_path, NULL);
			if (r < 0) {
				return r;
			}

			break;
		case 1:
			/* Test CoAP PUT method */
			LOG_INF("\nCoAP client PUT\n");
			r = send_coap_request(COAP_METHOD_PUT, large_update, test_payload);
			if (r < 0) {
				return r;
			}

			break;
		case 2:
			/* Test CoAP POST method*/
			LOG_INF("\nCoAP client POST\n");
			r = send_coap_request(COAP_METHOD_POST, test_path, NULL);
			if (r < 0) {
				return r;
			}

			break;
		case 3:
			/* Test CoAP DELETE method*/
			LOG_INF("\nCoAP client DELETE\n");
			r = send_coap_request(COAP_METHOD_DELETE, test_path, NULL);
			if (r < 0) {
				return r;
			}

			break;
		case 4:
			/* Test blockwise transfer GET */
			LOG_INF("\nBlockwise transfer GET\n");
			r = send_coap_request(COAP_METHOD_GET, large_path, NULL);
			if (r < 0) {
				return r;
			}

			break;
		default:
			return 0;
		}
		test_type++;
	}

	return 0;
}

void main(void)
{
	int r;

	k_sleep(K_SECONDS(1));
	LOG_DBG("Start CoAP-client sample");
	r = start_coap_client();
	if (r < 0) {
		goto quit;
	}

	r = test_coap_msgs();
	if (r < 0) {
		goto quit;
	}

quit:
	(void)close(sock);
}
