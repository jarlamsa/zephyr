/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/net/coap.h>

/**
 * @typedef coap_client_response_cb_t
 * @brief Type of the callback being called when there is response to the CoAP request.
 *
 * @param result_code Result code of the response. Negative if there was a failure in send.
 *                    \ref enum coap_response_code for positive.
 * @param offset Offset starting from 0 for the payload.
 * @param payload Buffer containing the payload from the response.
 * @param len Size of the payload.
 * @param user_data User provided context.
 * @param last_block Indicates the last block of the response.
 */
typedef void (*coap_client_response_cb_t)(uint8_t result_code,
                                   size_t offset, size_t len, const uint8_t *payload,
                                   bool last_block, void *user_data);

/**
 * @brief Representation of a CoAP client request.
 */
struct coap_client_request {
        enum coap_method method; /** Method of the request */
        bool confirmable; /** CoAP Confirmable/Non-confirmable message */
        const char *path; /** Path of the requested resource */
        enum coap_content_format fmt; /** Content format to be used */
        uint8_t *payload; /** User allocated buffer for send request */
        size_t len; /** Length of the payload */
        coap_client_response_cb_t cb; /** Callback when response received */
	void *user_data; /** User provided context */
};

/**
 * @brief Send CoAP request
 *
 * Operation is handled asynchronously using system's worker queue
 * or a background thread. Socket must be open and connected to a destination
 * address. Once the callback is called with result code 0, socket can be closed or
 * used for another query.
 *
 * @param sock Open socket file descriptor.
 * @param addr the destination address of the request.
 * @param req CoAP request structure
 * @param retries How many times to retry or -1 to use default.
 * @return zero when operation started successfully or negative error code otherwise.
 */

int coap_client_req(int sock, const struct sockaddr *addr, struct coap_client_request *req,
		    int retries);
