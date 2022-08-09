#include "doca_flow.h"

int
doca_flow_init(const struct doca_flow_cfg *cfg,
	       struct doca_flow_error *error){}

void
doca_flow_destroy(void){}

struct doca_flow_port *
doca_flow_port_start(const struct doca_flow_port_cfg *cfg,
		     struct doca_flow_error *error){}

int
doca_flow_port_stop(struct doca_flow_port *port){}

int
doca_flow_port_pair(struct doca_flow_port *port, struct doca_flow_port *pair_port){}

uint8_t*
doca_flow_port_priv_data(struct doca_flow_port *port){}
int
doca_flow_shared_resource_cfg(enum doca_flow_shared_resource_type type, uint32_t id,
			      struct doca_flow_shared_resource_cfg *cfg,
			      struct doca_flow_error *error){}

int
doca_flow_shared_resources_bind(enum doca_flow_shared_resource_type type, uint32_t *res_array,
				uint32_t res_array_len, void *bindable_obj,
				struct doca_flow_error *error){}

struct doca_flow_pipe *
doca_flow_create_pipe(const struct doca_flow_pipe_cfg *cfg,
		const struct doca_flow_fwd *fwd,
		const struct doca_flow_fwd *fwd_miss,
		struct doca_flow_error *error){}

struct doca_flow_pipe_entry*
doca_flow_pipe_add_entry(uint16_t pipe_queue,
			struct doca_flow_pipe *pipe,
			const struct doca_flow_match *match,
			const struct doca_flow_actions *actions,
			const struct doca_flow_monitor *monitor,
			const struct doca_flow_fwd *fwd,
			uint32_t flags,
			void *usr_ctx,
			struct doca_flow_error *error){}

struct doca_flow_pipe_entry*
doca_flow_control_pipe_add_entry(uint16_t pipe_queue,
			uint8_t priority,
			struct doca_flow_pipe *pipe,
			const struct doca_flow_match *match,
			const struct doca_flow_match *match_mask,
			const struct doca_flow_fwd *fwd,
			struct doca_flow_error *error){}

int
doca_flow_pipe_rm_entry(uint16_t pipe_queue, void *usr_ctx,
			struct doca_flow_pipe_entry *entry){}

void
doca_flow_destroy_pipe(uint16_t port_id,
		       struct doca_flow_pipe *pipe){}


void
doca_flow_port_pipes_flush(uint16_t port_id){}

void
doca_flow_destroy_port(uint16_t port_id){}

void
doca_flow_port_pipes_dump(uint16_t port_id, FILE *f){}

int
doca_flow_query(struct doca_flow_pipe_entry *entry,
		struct doca_flow_query *query_stats){}

int
doca_flow_handle_aging(struct doca_flow_port *port, uint16_t queue,
			uint64_t quota, struct doca_flow_aged_query *entries, int len){}

int
doca_flow_entries_process(struct doca_flow_port *port,
		uint16_t pipe_queue, uint64_t timeout,
		uint32_t max_processed_entries){}

enum doca_flow_entry_status
doca_flow_entry_get_status(struct doca_flow_pipe_entry *entry){}

