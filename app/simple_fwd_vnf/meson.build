app_src = [
    APP_NAME+'.c',
    'simple_fwd.c',
	'simple_fwd_control.c',
	'simple_fwd_ft.c',
	'simple_fwd_pkt.c',
	'simple_fwd_port.c',
	'simple_fwd_vnf_core.c',
]
library_path='../../lib'

incdir = include_directories(library_path)
lib_src=[
    library_path+'/doca_argp.c',
    library_path+'/dpdk_utils.c',
    library_path+'/doca_log.c',
    library_path+'/doca_flow.c',
    library_path+'/utils.c',
]

machine_args = []
cflags = machine_args
deps=[]
deps+=dependency('libdpdk')

app_src += lib_src

executable(APP_NAME,app_src,
    cpp_args: ['-include', 'rte_config.h', cflags],
    include_directories : incdir,
    dependencies:deps
)
