sources = files(
    'firewall_core.c',
    'firewall.c',
    '../common/utils.c',
    '../common/flow_parser.c')

deps += [
    'doca_flow',
	'doca_argp',
	'doca_common'
]

includes+=include_directories('../../lib/doca_flow')
includes+=include_directories('../../lib/doca_argp')