server_sources=files(
    'simple_fwd.c',
	'simple_fwd_control.c',
	'simple_fwd_ft.c',
	'simple_fwd_pkt.c',
	'simple_fwd_port.c',
	'simple_fwd_vnf_core.c',
	'simple_fwd_vnf.cc'
)
grpc_sources=files(
	'SimpleFlow.grpc.pb.cc',
	'SimpleFlow.pb.cc'
)

client_sources=files(
	'client.cc'
)

all_deps=[]
in_deps=[
    'doca_flow',
	'doca_log',
	'doca_argp',
	'doca_common'
]

foreach d:in_deps
        var_name = 'shared_' + d
        if not is_variable(var_name)
                build = false
                message('Missing dependency "@0@" for example "@1@"'.format(var_name, t))
                break
            endif
        all_deps += [get_variable(var_name)]
endforeach
all_deps+=dependency('libdpdk')
all_deps+=dependency('protobuf')
all_deps+=dependency('grpc++')

includes+=include_directories('../../lib/doca_log')
includes+=include_directories('../../lib/doca_flow')
includes+=include_directories('../../lib/doca_argp')
includes+=include_directories('./')


base_cpp_args = [
	'-std=c++11'
]

executable(
	t+'_server',
	server_sources+grpc_sources,
	c_args:base_cpp_args,
	dependencies:all_deps,
	link_with:[],
	include_directories:includes,
	install:false
)

executable(
	t+'_client',
	client_sources+grpc_sources,
	c_args:base_cpp_args,
	dependencies:all_deps,
	link_with:[],
	include_directories:includes,
	install:false
)