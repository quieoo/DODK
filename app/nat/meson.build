sources = files(
    'nat_core.c',
    'nat.c',
    '../common/flow_parser.c',
    '../common/dpdk_utils.c'
)

deps += [
    'doca_flow',
	'doca_argp',
	'doca_common'
]

includes+=include_directories('../../lib/doca_flow')
includes+=include_directories('../../lib/doca_argp')