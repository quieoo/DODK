sources = files(
    'switch_core.c',
    'switch.c',
    '../common/flow_parser.c',
    '../common/dpdk_utils.c',
    '../common/offload_rules.c',
    '../common/flow_pipes_manager.c'
)

deps += [
    'doca_flow',
	'doca_argp',
	'doca_common'
]

includes+=include_directories('../../lib/doca_flow')
includes+=include_directories('../../lib/doca_argp')