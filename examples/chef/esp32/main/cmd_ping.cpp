/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <lib/shell/Engine.h>

#include <crypto/RandUtils.h>
#include <lib/core/CHIPCore.h>
#include <lib/support/Base64.h>
#include <lib/support/CHIPArgParser.hpp>
#include <lib/support/CodeUtils.h>

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argtable3/argtable3.h"
#include "esp_console.h"
#include "esp_event.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"
#include "ping/ping_sock.h"
#include "protocol_examples_common.h"
#include "sdkconfig.h"

#include <cmd_ping.h>

using namespace chip;
using namespace chip::Shell;
using namespace chip::Logging;

static void cmd_ping_on_ping_success(esp_ping_handle_t hdl, void * args)
{
    uint8_t ttl;
    uint16_t seqno;
    uint32_t elapsed_time, recv_len;
    ip_addr_t target_addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TTL, &ttl, sizeof(ttl));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_SIZE, &recv_len, sizeof(recv_len));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_time, sizeof(elapsed_time));
    printf("%" PRIu32 " bytes from %s icmp_seq=%" PRIu16 " ttl=%" PRIu16 " time=%" PRIu32 " ms\n", recv_len,
           ipaddr_ntoa((ip_addr_t *) &target_addr), seqno, ttl, elapsed_time);
}

static void cmd_ping_on_ping_timeout(esp_ping_handle_t hdl, void * args)
{
    uint16_t seqno;
    ip_addr_t target_addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    printf("From %s icmp_seq=%d timeout\n", ipaddr_ntoa((ip_addr_t *) &target_addr), seqno);
}

static void cmd_ping_on_ping_end(esp_ping_handle_t hdl, void * args)
{
    ip_addr_t target_addr;
    uint32_t transmitted;
    uint32_t received;
    uint32_t total_time_ms;
    uint32_t loss;

    esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST, &transmitted, sizeof(transmitted));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &received, sizeof(received));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_DURATION, &total_time_ms, sizeof(total_time_ms));

    if (transmitted > 0)
    {
        loss = (uint32_t)((1 - ((float) received) / transmitted) * 100);
    }
    else
    {
        loss = 0;
    }
    if (IP_IS_V4(&target_addr))
    {
        printf("\n--- %s ping statistics ---\n", inet_ntoa(*ip_2_ip4(&target_addr)));
    }
    else
    {
        printf("\n--- %s ping statistics ---\n", inet6_ntoa(*ip_2_ip6(&target_addr)));
    }
    printf("%" PRIu32 " packets transmitted, %" PRIu32 " received, %" PRIu32 "%% packet loss, time %" PRIu32 "ms\n", transmitted,
           received, loss, total_time_ms);
    // delete the ping sessions, so that we clean up all resources and can create a new ping session
    // we don't have to call delete function in the callback, instead we can call delete function from other tasks
    esp_ping_delete_session(hdl);
}

static struct
{
    struct arg_dbl * timeout;
    struct arg_dbl * interval;
    struct arg_int * data_size;
    struct arg_int * count;
    struct arg_int * tos;
    struct arg_int * ttl;
    struct arg_str * host;
    struct arg_end * end;
} ping_args;

CHIP_ERROR cmd_ping(int argc, char ** argv) // equivalent to do_ping_cmd() /examples/protocols/icmp_echo/main/echo_example_main.c
{
    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();

    int nerrors = arg_parse(argc, argv, (void **) &ping_args);
    if (nerrors != 0)
    {
        arg_print_errors(stderr, ping_args.end, argv[0]);
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    if (ping_args.timeout->count > 0)
    {
        config.timeout_ms = (uint32_t)(ping_args.timeout->dval[0] * 1000);
    }

    if (ping_args.interval->count > 0)
    {
        config.interval_ms = (uint32_t)(ping_args.interval->dval[0] * 1000);
    }

    if (ping_args.data_size->count > 0)
    {
        config.data_size = (uint32_t)(ping_args.data_size->ival[0]);
    }

    if (ping_args.count->count > 0)
    {
        config.count = (uint32_t)(ping_args.count->ival[0]);
    }

    if (ping_args.tos->count > 0)
    {
        config.tos = (uint32_t)(ping_args.tos->ival[0]);
    }

    if (ping_args.ttl->count > 0)
    {
        config.ttl = (uint32_t)(ping_args.ttl->ival[0]);
    }

    // parse IP address
    struct sockaddr_in6 sock_addr6;
    ip_addr_t target_addr;
    memset(&target_addr, 0, sizeof(target_addr));

    if (inet_pton(AF_INET6, ping_args.host->sval[0], &sock_addr6.sin6_addr) == 1)
    {
        /* convert ip6 string to ip6 address */
        ipaddr_aton(ping_args.host->sval[0], &target_addr);
    }
    else
    {
        struct addrinfo hint;
        struct addrinfo * res = NULL;
        memset(&hint, 0, sizeof(hint));
        /* convert ip4 string or hostname to ip4 or ip6 address */
        if (getaddrinfo(ping_args.host->sval[0], NULL, &hint, &res) != 0)
        {
            printf("ping: unknown host %s\n", ping_args.host->sval[0]);
            return CHIP_ERROR_INVALID_ARGUMENT;
        }
        if (res->ai_family == AF_INET)
        {
            struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
            inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
        }
        else
        {
            struct in6_addr addr6 = ((struct sockaddr_in6 *) (res->ai_addr))->sin6_addr;
            inet6_addr_to_ip6addr(ip_2_ip6(&target_addr), &addr6);
        }
        freeaddrinfo(res);
    }
    config.target_addr = target_addr;

    /* set callback functions */
    esp_ping_callbacks_t cbs = { .cb_args         = NULL,
                                 .on_ping_success = cmd_ping_on_ping_success,
                                 .on_ping_timeout = cmd_ping_on_ping_timeout,
                                 .on_ping_end     = cmd_ping_on_ping_end };
    esp_ping_handle_t ping;
    esp_ping_new_session(&config, &cbs, &ping);
    esp_ping_start(ping);

    return CHIP_NO_ERROR;
}

static shell_command_t cmds_ping[] = {
    { &cmd_ping, "ping", "ping command" },
};

void cmd_ping_init()
{
    ping_args.timeout   = arg_dbl0("W", "timeout", "<t>", "Time to wait for a response, in seconds");
    ping_args.interval  = arg_dbl0("i", "interval", "<t>", "Wait interval seconds between sending each packet");
    ping_args.data_size = arg_int0("s", "size", "<n>", "Specify the number of data bytes to be sent");
    ping_args.count     = arg_int0("c", "count", "<n>", "Stop after sending count packets");
    ping_args.tos       = arg_int0("Q", "tos", "<n>", "Set Type of Service related bits in IP datagrams");
    ping_args.ttl       = arg_int0("T", "ttl", "<n>", "Set Time to Live related bits in IP datagrams");
    ping_args.host      = arg_str1(NULL, NULL, "<host>", "Host address");
    ping_args.end       = arg_end(1);

    Engine::Root().RegisterCommands(cmds_ping, ArraySize(cmds_ping));
}
