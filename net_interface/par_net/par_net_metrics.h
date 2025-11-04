#ifndef PAR_NET_METRICS_H
#define PAR_NET_METRICS_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_metrics_req;

struct par_net_metrics_rep;

size_t par_net_metrics_req_calc_size(void);

size_t par_net_metrics_rep_calc_size(void);

struct par_net_metrics_req *par_net_metrics_req_create(uint8_t flags, char *buffer, size_t *buffer_len);

struct par_net_metrics_rep *par_net_metrics_rep_create(uint32_t,uint32_t,uint32_t,uint32_t,char *buffer, size_t buffer_len);

uint8_t par_net_metrics_req_get_flags(struct par_net_metrics_req *request);

bool par_net_metrics_rep_handle_reply(struct par_net_metrics_rep *reply);


#endif
