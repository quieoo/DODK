project('DODK', 'c')

incdir = include_directories('lib')

app_src=[
    'lib/doca_argp.c',
    'lib/dpdk_utils.c',
    'lib/doca_log.c',
    'lib/doca_flow.c',
    'lib/utils.c',
    'app/simple_fwd_vnf/simple_fwd_vnf.c',
    'app/simple_fwd_vnf/simple_fwd.c',
    'app/simple_fwd_vnf/simple_fwd_port.c',
    'app/simple_fwd_vnf/simple_fwd_vnf_core.c',
    'app/simple_fwd_vnf/simple_fwd_pkt.c',
    'app/simple_fwd_vnf/simple_fwd_ft.c',
    'app/simple_fwd_vnf/simple_fwd_control.c'
]
machine_args = []
cflags = machine_args
deps=[]
deps+=dependency('libdpdk')


executable('t', app_src, 
    cpp_args: ['-include', 'rte_config.h', cflags],
    include_directories : incdir,
    dependencies:deps
)
