sources = files(
    'simple_fwd_vnf.c',
    'simple_fwd.c',
	'simple_fwd_control.c',
	'simple_fwd_ft.c',
	'simple_fwd_pkt.c',
	'simple_fwd_port.c',
	'simple_fwd_vnf_core.c',
    '../common/dpdk_utils.c',
    '../common/offload_rules.c',
    '../common/utils.c'
    )

deps += [
    'doca_flow',
	'doca_argp',
	'doca_common'
]

includes+=include_directories('../../lib/doca_flow')
includes+=include_directories('../../lib/doca_argp')