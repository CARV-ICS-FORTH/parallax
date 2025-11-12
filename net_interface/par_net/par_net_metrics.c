#include "par_net_metrics.h"
#include "par_net.h"

struct par_net_metrics_req {
  uint8_t flags;
} __attribute__((packed));

struct par_net_metrics_rep {
  uint32_t get_count;
  uint32_t put_count;
  uint32_t GET_avg_key_size;
  uint32_t GET_avg_val_size;
  uint32_t PUT_avg_key_size;
  uint32_t PUT_avg_val_size;
  uint32_t ops_count;
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

struct par_net_metrics_rep *par_net_metrics_rep_create(uint32_t get_count, uint32_t put_count, uint32_t get_avg_key_size, uint32_t get_avg_val_size , uint32_t put_avg_key_size, uint32_t put_avg_val_size, uint32_t ops_count ,char *buffer, size_t buffer_len){
	if (buffer_len < par_net_metrics_rep_calc_size()) {
		return NULL;
	}
	struct par_net_metrics_rep *reply = (struct par_net_metrics_rep *)buffer;

	reply->get_count = get_count;
	reply->put_count = put_count;
  
  reply->GET_avg_key_size = get_avg_key_size;
  reply->GET_avg_val_size = get_avg_val_size;
  
  reply->PUT_avg_key_size = put_avg_key_size;  
  reply->PUT_avg_val_size = put_avg_val_size;
  
  reply->ops_count  = ops_count;
  return reply;

}

bool par_net_metrics_rep_handle_reply(struct par_net_metrics_rep *reply){
 
  FILE *fp = fopen("par_metrics.log", "a");
  if(!fp) return false;

  fprintf(fp,"============ Parallax Metrics ============\n");
  fprintf(fp, "\n Get ops: %d\n Put ops: %d\n Avg Key size (GET): %d\n Avg Value Size (GET): %d\n Avg Key Size (PUT): %d\n Avg Value Size (PUT): %d\n Total ops: %d\n\n", 
              reply->get_count, reply->put_count, reply->GET_avg_key_size, reply->GET_avg_val_size, reply->PUT_avg_key_size, reply->PUT_avg_val_size,reply->ops_count);
  fprintf(fp,"==========================================\n\n");

  fclose(fp);

  return true;
}

uint8_t par_net_metrics_req_get_flags(struct par_net_metrics_req *request){
  return request->flags;
}
