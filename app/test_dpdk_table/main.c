#include <rte_table_hash.h>
#include <rte_lru.h>

uint64_t pipeline_test_hash(void *key,
		__rte_unused void *key_mask,
		__rte_unused uint32_t key_size,
		__rte_unused uint64_t seed)
{
	uint32_t *k32 = key;
	uint32_t ip_dst = rte_be_to_cpu_32(k32[0]);
	uint64_t signature = ip_dst;

	return signature;
}

void main(){

    struct rte_table_hash_params p={
        .name="test",
        .key_size=48,
        .key_offset=APP_METADATA_OFFSET(32),
        .key_mask = NULL,
		.n_keys = 1 << 16,
		.n_buckets = 1 << 16,
		.f_hash = pipeline_test_hash,
		.seed = 0,
    };

    struct rte_table_ops *ops=&rte_table_hash_lru_ops;

    void *table=ops->f_create(&p, 0, 1);

    uint8_t key[32];
	uint32_t *k32 = (uint32_t *) &key;

	memset(key, 0, 32);
	k32[0] = rte_be_to_cpu_32(0xadadadad);

    char entry = 'A';

    void *entry_ptr;
	int key_found;
    int status;

    status = ops->f_add(table, &key, &entry, &key_found, &entry_ptr);
	if (status != 0)
		printf("add status: %d\n", status);



    status = ops->f_free(table);
    if(status < 0)
        printf("free status: %d\n", status);
}