#include "par_net_metrics.h"
#include "par_net.h"

struct par_net_metrics_req {
  uint8_t flags;
} __attribute__((packed));

struct par_net_metrics_kv_data{
  uint32_t avg_key_size;
  uint32_t avg_val_size;

  uint32_t max_key_size;
  uint32_t max_val_size;
  
  uint32_t min_key_size;
  uint32_t min_val_size;
}__attribute__((packed));

struct par_net_metrics_rep {
  uint32_t get_count;
  uint32_t put_count;
  uint32_t ops_count;

  struct par_net_metrics_kv_data get;
  struct par_net_metrics_kv_data put;
} __attribute__((packed));

size_t par_net_metrics_req_calc_size(void){
  return sizeof(struct par_net_metrics_req);
} 

size_t par_net_metrics_rep_calc_size(void){
  return sizeof(struct par_net_metrics_rep);
}

struct par_net_metrics_req *par_net_metrics_req_create(uint8_t flags, char *buffer, size_t *buffer_len){
  
  if(par_net_metrics_req_calc_size() > *buffer_len)
    return NULL;

  struct par_net_metrics_req *request = (struct par_net_metrics_req *)(buffer); 
  request->flags = flags; 

  return request;
}

struct par_net_metrics_rep *par_net_metrics_rep_create(uint32_t get_count, uint32_t put_count, 
                                                       uint32_t get_avg_key_size, uint32_t get_avg_val_size , 
                                                       uint32_t put_avg_key_size,uint32_t put_avg_val_size  , 
                                                       uint32_t get_max_key_size, uint32_t get_max_val_size ,  
                                                       uint32_t get_min_key_size, uint32_t get_min_val_size ,
                                                       uint32_t put_max_key_size, uint32_t put_max_val_size , 
                                                       uint32_t put_min_key_size, uint32_t put_min_val_size ,
                                                       uint32_t ops_count ,char *buffer, size_t buffer_len){
	if (buffer_len < par_net_metrics_rep_calc_size()) {
		return NULL;
	}
	struct par_net_metrics_rep *reply = (struct par_net_metrics_rep *)buffer;

	reply->get_count = get_count;
	reply->put_count = put_count;
  
  reply->get.avg_key_size = get_avg_key_size;
  reply->get.avg_val_size = get_avg_val_size;
  reply->get.max_key_size = get_max_key_size;
  reply->get.max_val_size = get_max_val_size;
  reply->get.min_key_size = get_min_key_size;
  reply->get.min_val_size = get_min_val_size;

  reply->put.avg_key_size = put_avg_key_size;  
  reply->put.avg_val_size = put_avg_val_size;
  reply->put.max_key_size = put_max_key_size;
  reply->put.max_val_size = put_max_val_size;
  reply->put.min_key_size = put_min_key_size;
  reply->put.min_val_size = put_min_val_size;
  
  reply->ops_count  = ops_count;
  return reply;

}

bool par_net_metrics_rep_handle_reply(struct par_net_metrics_rep *reply){
 
  FILE *fp = fopen("par_metrics.log", "a");
  if(!fp) return false;

  fprintf(fp,"============ Parallax Metrics ============\n");
  fprintf(fp,
        "\n"
        " Total ops:           %d\n"
        " Get ops:             %d\n"
        " Put ops:             %d\n"
        "========== (GET) ==========\n"
        " Avg Key Size:  %d\n"
        " Avg Val Size:  %d\n"
        " Max Key Size:  %d\n"
        " Max Val Size:  %d\n"
        " Min Key Size:  %d\n"
        " Min Val Size:  %d\n"
        "========== (PUT) =========\n"
        " Avg Key Size:  %d\n"
        " Avg Val Size:  %d\n"
        " Max Key Size:  %d\n"
        " Max Val Size:  %d\n"
        " Min Key Size:  %d\n"
        " Min Val Size:  %d\n"
        "\n",
        
        reply->ops_count,
        reply->get_count,
        reply->put_count,
        reply->get.avg_key_size,
        reply->get.avg_val_size,
        reply->get.max_key_size,
        reply->get.max_val_size,
        reply->get.min_key_size,
        reply->get.min_val_size,
        
        reply->put.avg_key_size,
        reply->put.avg_val_size,
        reply->put.max_key_size,
        reply->put.max_val_size,
        reply->put.min_key_size,
        reply->put.min_val_size

      );

  fprintf(fp,"==========================================\n\n");

  fclose(fp);

  return true;
}

uint8_t par_net_metrics_req_get_flags(struct par_net_metrics_req *request){
  return request->flags;
}
