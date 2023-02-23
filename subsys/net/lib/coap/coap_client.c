/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_coap, CONFIG_COAP_LOG_LEVEL);

#include <zephyr/net/socket.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_client.h>

#define COAP_VERSION 1
#define COAP_PATH_ELEM_DELIM '/'
#define COAP_PATH_ELEM_QUERY '?'
#define MAX_COAP_MSG_LEN CONFIG_COAP_ASYNC_CLIENT_BUFFER_SIZE
#define COAP_POOL_SLEEP 500
#define COAP_SEPARATE_TIMEOUT 6000
#define DEFAULT_RETRY_AMOUNT 5

static K_SEM_DEFINE(coap_client_recv_sem, 0, 1);
static atomic_t coap_client_recv_active;
static struct pollfd fds;
static struct coap_client_request *coap_request;
static int retry_count;
static struct coap_packet request;
static uint8_t request_token[COAP_TOKEN_MAX_LEN];
static int request_tkl;
static uint8_t send_buf[MAX_COAP_MSG_LEN];
static uint8_t recv_buf[MAX_COAP_MSG_LEN];
static struct coap_block_context recv_blk_ctx;
static struct coap_block_context send_blk_ctx;
static struct coap_pending pending;
static struct sockaddr address;
static socklen_t socklen;

static int coap_client_schedule_poll(int sock, struct coap_client_request *req, int retries)
{
	fds.fd = sock;
	fds.events = POLLIN;
	coap_request = req;
	retry_count = retries;

	k_sem_give(&coap_client_recv_sem);
	atomic_set(&coap_client_recv_active, 1);

	return 0;
}

static void reset_block_contexts()
{
	recv_blk_ctx.block_size = 0;
	recv_blk_ctx.total_size = 0;
	recv_blk_ctx.current = 0;

	send_blk_ctx.block_size = 0;
	send_blk_ctx.total_size = 0;
	send_blk_ctx.current = 0;
}

static int coap_client_init_path_options(struct coap_packet *pckt, const char *path)
{
	int ret=0;
	int path_start, path_end;
	int path_length;
	bool contains_query = false;

	path_start = 0;
	path_end = 0;
	path_length = strlen(path);
	for (int i = 0; i < path_length; i++) {
		path_end = i;
		if (path[i] == COAP_PATH_ELEM_DELIM) {
			/* Guard for preceding delimiters */
			if (path_start < path_end) {
				ret = coap_packet_append_option(pckt, COAP_OPTION_URI_PATH,
								path + path_start,
								path_end - path_start);
				if (ret < 0) {
					LOG_ERR("Failed to append path to CoAP message");
					goto out;
				}
			}
			/* Check if there is a new path after delimiter,
			 * if not, point to the end of string to not add
			 * new option after this
			 */
			if (path_length > i+1) {
				path_start = i+1;
			} else {
				path_start = path_length;
			}
		} else if (path[i] == COAP_PATH_ELEM_QUERY) {
			/* Guard for preceding delimiters */
			if (path_start < path_end) {
				ret = coap_packet_append_option(pckt, COAP_OPTION_URI_PATH,
								path + path_start,
								path_end - path_start);
				if (ret < 0) {
					LOG_ERR("Failed to append path to CoAP message");
					goto out;
				}
			}
			/* Rest of the path is query */
			contains_query = true;
			if (path_length > i+1) {
				path_start = i+1;
				break;
			} else {
				path_start = path_length;
			}
		}
	}
	path_end = path_length;

	if (path_start < path_end) {
		if (contains_query) {
			ret = coap_packet_append_option(&request, COAP_OPTION_URI_QUERY,
							path + path_start,
							path_end - path_start);
		} else {
			ret = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
							path + path_start,
							path_end - path_start);
		}

		if (ret < 0) {
			LOG_ERR("Failed to append path to CoAP message");
			goto out;
		}
	}

out:
	return ret;
}

static int coap_client_init_request(struct coap_client_request *req)
{
	int ret= 0;

	memset(send_buf, 0, sizeof(send_buf));
	ret = coap_packet_init(&request, send_buf, MAX_COAP_MSG_LEN, 1,
			       req->confirmable ? COAP_TYPE_CON : COAP_TYPE_NON_CON,
			       COAP_TOKEN_MAX_LEN, coap_next_token(), req->method,
			       coap_next_id());

	if (ret < 0) {
		LOG_ERR("Failed to init CoAP message %d", ret);
		goto out;
	}

	ret = coap_client_init_path_options(&request, req->path);

	if (ret < 0) {
		LOG_ERR("Failed to parse path to options %d", ret);
		goto out;
	}

	ret = coap_append_option_int(&request, COAP_OPTION_ACCEPT, req->fmt);

	/* Blockwise receive ongoing, request next block. */
	if (recv_blk_ctx.current > 0) {
		ret = coap_append_block2_option(&request, &recv_blk_ctx);

		if (ret < 0) {
			LOG_ERR("Failed to append block 2 option");
			goto out;
		}
	}

	if (req->payload) {
		uint16_t payload_len;
		uint16_t offset;

		/* Blockwise send ongoing, add block1 */
		if (send_blk_ctx.total_size > 0 ||
		   (request.max_len - request.offset < req->len + 1)) {

			if (send_blk_ctx.total_size == 0) {
				enum coap_block_size i;
				/* Find the largest block size to use */
				for (i = COAP_BLOCK_1024; i >= 0; i--)
				{
					if (coap_block_size_to_bytes(i) <=
					    (request.max_len - (request.offset + 1)))
					{
						break;
					}
				}

				coap_block_transfer_init(&send_blk_ctx, i, req->len);
			}
			ret = coap_append_block1_option(&request, &send_blk_ctx);

			if (ret < 0) {
				LOG_ERR("Failed to append block1 option");
				goto out;
			}
		}

		ret = coap_packet_append_payload_marker(&request);

		if (ret < 0) {
			LOG_ERR("Failed to append payload marker to CoAP message");
			goto out;
		}

		if (send_blk_ctx.total_size > 0) {
			uint16_t block_in_bytes = coap_block_size_to_bytes(send_blk_ctx.block_size);
			payload_len = send_blk_ctx.total_size - send_blk_ctx.current;
			if (payload_len > block_in_bytes) {
				payload_len = block_in_bytes;
			}
			offset = send_blk_ctx.current;
		} else {
			payload_len = req->len;
			offset = 0;
		}

		ret = coap_packet_append_payload(&request, req->payload + offset, payload_len);

		if (ret < 0) {
			LOG_ERR("Failed to append payload to CoAP message");
			goto out;
		}

		if (send_blk_ctx.total_size > 0) {
			coap_next_block(&request, &send_blk_ctx);
		}
	}
	request_tkl = coap_header_get_token(&request, request_token);
out:
	return ret;
}


int coap_client_req(int sock, const struct sockaddr *addr, struct coap_client_request *req,
		    int retries)
{
	int ret;

	/* Check if there is request already ongoing */
	if (coap_client_recv_active) {
		return -EAGAIN;
	}

	if (sock < 0 || req == NULL || req->path == NULL || addr == NULL) {
		return -EINVAL;
	}

	memcpy(&address, addr, sizeof(*addr));
	socklen = sizeof(address);

	if (retries == -1) {
		retries = DEFAULT_RETRY_AMOUNT;
	}

	ret = coap_client_init_request(req);
	if (ret < 0) {
		LOG_ERR("Failed to initialize coap request");
		return ret;
	}

	ret = coap_client_schedule_poll(sock, req, retries);
	if (ret < 0) {
		LOG_ERR("Failed to schedule polling");
		goto out;
	}

	ret = coap_pending_init(&pending, &request, &address, retries);

	if (ret < 0) {
		LOG_ERR("Failed to initialize pending struct");
		goto out;
	}

	coap_pending_cycle(&pending);

	ret = sendto(sock, request.data, request.offset, 0, &address, sizeof(address));

	if (ret < 0) {
		LOG_ERR("Transmission failed: %d", errno);
		goto out;
	}
out:
	return ret;
}

static int handle_poll()
{
	int ret = 0;

	while(1) {
		fds.revents = 0;
		/* rfc7252#section-5.2.2, use separate timeout value for a separate response */
		if (pending.timeout != 0) {
			ret = poll(&fds, 1, pending.timeout);
		} else {
			ret = poll(&fds, 1, COAP_SEPARATE_TIMEOUT);
		}

		if (ret < 0) {
			LOG_ERR("Error in poll:%d", errno);
			errno = 0;
			k_sleep(K_MSEC(COAP_POOL_SLEEP));
			return ret;
		} else if (ret == 0) {
			if (pending.timeout != 0 && coap_pending_cycle(&pending)) {
				LOG_ERR("Timeout in poll, retrying send");
				sendto(fds.fd, request.data, request.offset, 0, &address,
				       sizeof(address));
			} else {
				/* No more retries left, don't retry */
				LOG_ERR("Timeout in poll, no more retries");
				ret = -EFAULT;
				break;
			}
		} else {
			if (fds.revents & POLLERR) {
				LOG_ERR("Error in poll.. waiting a moment.");
				k_sleep(K_MSEC(COAP_POOL_SLEEP));
				ret = -EIO;
				break;
			}

			if (fds.revents & POLLHUP) {
				LOG_ERR("Error in poll: POLLHUP");
				ret = -ECONNRESET;
				break;
			}

			if (fds.revents & POLLNVAL) {
				LOG_ERR("Error in poll: POLLNVAL - fd not open");
				ret = -EINVAL;
				break;
			}

			if (!(fds.revents & POLLIN)) {
				LOG_ERR("Unknown poll error");
				ret = -EINVAL;
				break;
			} else {
				ret = 0;
				break;
			}
		}
	}

	return ret;
}

static bool token_compare(const struct coap_packet* req, const struct coap_packet* resp)
{
	uint8_t response_token[COAP_TOKEN_MAX_LEN];
	uint8_t response_tkl;

	response_tkl = coap_header_get_token(resp, response_token);

	if (request_tkl != response_tkl) {
		return false;
	}

	return memcmp(&request_token, &response_token, response_tkl) == 0;
}

static int recv_response(struct coap_packet* response)
{
	int len;
	int ret;

	memset(recv_buf, 0, sizeof(recv_buf));
	len = recvfrom(fds.fd, recv_buf, sizeof(recv_buf), MSG_DONTWAIT, &address, &socklen);

	if (len < 0) {
		LOG_ERR("Error reading response: %d", errno);
		return -EINVAL;
	} else if (len == 0) {
		LOG_ERR("Zero length recv");
		return -EINVAL;
	} else {
		LOG_DBG("Received %d bytes", len);
	}

	ret = coap_packet_parse(response, recv_buf, len, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		return ret;
	}

	return ret;
}

static void report_callback_error(int error_code)
{
	if (coap_request->cb) {
		coap_request->cb(error_code, 0, 0, NULL, true, NULL);
	}
}

static int send_ack(const struct coap_packet* req, uint8_t response_code)
{
	int ret;
	ret = coap_ack_init(&request, req, send_buf, MAX_COAP_MSG_LEN, response_code);

	if (ret < 0) {
		LOG_ERR("Failed to initialize CoAP ACK-message");
		return ret;
	}

	ret = sendto(fds.fd, request.data, request.offset, 0, &address, sizeof(address));
	if (ret < 0) {
		LOG_ERR("Error sending a CoAP ACK-message");
		return ret;
	}

	return 0;
}

static int send_reset(const struct coap_packet* req, uint8_t response_code)
{
	int ret;
	uint16_t id;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl;

	id = coap_header_get_id(req);
	tkl = response_code ? coap_header_get_token(req, token) : 0;
	ret = coap_packet_init(&request, send_buf, MAX_COAP_MSG_LEN, COAP_VERSION, COAP_TYPE_RESET,
			       tkl, token, response_code, id);

	if (ret < 0) {
		LOG_ERR("Error creating CoAP reset message");
		return ret;
	}

	ret = sendto(fds.fd, request.data, request.offset, 0, &address, sizeof(address));
	if (ret < 0) {
		LOG_ERR("Error sending CoAP reset message");
		return ret;
	}

	return 0;
}

static int handle_response(const struct coap_packet* response)
{
	int ret = 0;
	int response_type;
	static int offset = 0;
	int block_option;
	int block_num;
	bool blockwise_transfer = false;
	bool last_block = false;

	/* Handle different types, ACK might be separate or piggybacked
	 * CON and NCON contains a separate response, CON needs an empty response
	 * CON request results as ACK and possibly separate CON or NCON response
	 * NCON request results only as a separate CON or NCON message as there is no ACK
	 * With RESET, just drop gloves and call the callback.
	 */
	response_type = coap_header_get_type(response);

	/* Reset and Ack need to match the message ID with request */
	if ((response_type == COAP_TYPE_ACK || response_type == COAP_TYPE_RESET) &&
	     coap_header_get_id(response) != pending.id)  {
		LOG_ERR("Unexpected ACK or Reset");
		return -EFAULT;
	} else if (response_type == COAP_TYPE_RESET) {
		coap_pending_clear(&pending);
	}

	/* CON, NON_CON and piggybacked ACK need to match the token with original request */
	uint16_t payload_len;
	uint8_t response_code = coap_header_get_code(response);
	const uint8_t *payload = coap_packet_get_payload(response, &payload_len);

	/* Separate response */
	if (payload_len == 0 && response_type == COAP_TYPE_ACK && response_code == 0) {
		/* Set a timeout value and clear pending */
		coap_pending_clear(&pending);
		return 1;
	}

	/* Check for tokens */
	if (!token_compare(&request, response)) {
		LOG_ERR("Not matching tokens, respond with reset");
		ret = send_reset(response, COAP_RESPONSE_CODE_NOT_FOUND);
		return 1;
	}

	/* Send ack for CON */
	if (response_type == COAP_TYPE_CON) {
		ret = send_ack(response, COAP_RESPONSE_CODE_OK);
		if (ret < 0) {
			return ret;
		}
	}

	if (pending.timeout != 0) {
		coap_pending_clear(&pending);
	}

	/* Check if block2 exists */
	block_option = coap_get_option_int(response, COAP_OPTION_BLOCK2);
	if (block_option > 0) {
		blockwise_transfer = true;
		last_block = !GET_MORE(block_option);
		block_num = GET_BLOCK_NUM(block_option);

		if (block_num == 0) {
			coap_block_transfer_init(&recv_blk_ctx, COAP_BLOCK_128, 0);
			offset = 0;
		}

		ret = coap_update_from_block(response, &recv_blk_ctx);
		if (ret < 0) {
			LOG_ERR("Error updating block context");
		}
		coap_next_block(response, &recv_blk_ctx);
	} else {
		offset = 0;
		last_block = true;
	}

	/* Check if this was a response to last blockwise send */
	if (send_blk_ctx.total_size > 0) {
		blockwise_transfer = true;
		if (send_blk_ctx.total_size == send_blk_ctx.current) {
			last_block = true;
		} else {
			last_block = false;
		}
	}

	/* Call user callback */
	if (coap_request->cb) {
		uint8_t result_code = coap_header_get_code(response);
		coap_request->cb(result_code, offset, payload_len, payload,
				 last_block, coap_request->user_data);

		/* Update the offset for next callback in a blockwise transfer */
		if (blockwise_transfer) {
			offset += payload_len;
		}
	}

	/* If this wasn't last block, send the next request */
	if (blockwise_transfer && !last_block) {
		ret = coap_client_init_request(coap_request);

		if (ret < 0) {
			LOG_ERR("Error creating a CoAP request");
			goto fail;
		}

		if (pending.timeout != 0) {
			LOG_ERR("Previous pending hasn't arrived");
			goto fail;
		}

		ret = coap_pending_init(&pending, &request, &address, retry_count);
		if (ret < 0) {
			LOG_ERR("Error creating pending");
			goto fail;
		}
		coap_pending_cycle(&pending);

		ret = sendto(fds.fd, request.data, request.offset, 0, &address, sizeof(address));
		if (ret < 0) {
			LOG_ERR("Error sending a CoAP request");
			goto fail;
		} else {
			return 1;
		}
	}
fail:
	return ret;
}

void coap_client_recv(void)
{
	int ret;
	bool blockwise_transfer;
	bool last_block;
	bool separate;
	bool retry = false;
	size_t offset;

	retry = false;
	blockwise_transfer = false;
	last_block = true;
	separate = false;
	offset = 0;
	reset_block_contexts();
	k_sem_take(&coap_client_recv_sem, K_FOREVER);
	while (true) {
		struct coap_packet response;

		atomic_set(&coap_client_recv_active, 1);
		ret = handle_poll();
		if (ret < 0) {
			/* Error in polling, clear pending. */
			coap_pending_clear(&pending);
			report_callback_error(ret);
			goto idle;
		}

		ret = recv_response(&response);
		if (ret < 0) {
			LOG_ERR("Error receiving response");
			report_callback_error(ret);
			goto idle;
		}

		ret = handle_response(&response);
		if (ret < 0) {
			LOG_ERR("Error handling respnse");
			report_callback_error(ret);
			goto idle;
		}

		/* There is more messages coming for the original request */
		if (ret > 0) {
			continue;
		} else {
idle:
			reset_block_contexts();
			atomic_set(&coap_client_recv_active, 0);
			k_sem_take(&coap_client_recv_sem, K_FOREVER);
		}
	}
}

K_THREAD_DEFINE(coap_client_recv_thread, CONFIG_COAP_ASYNC_CLIENT_STACK_SIZE,
		coap_client_recv, NULL, NULL, NULL,
		K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1), 0, 0);
