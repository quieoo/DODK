sources=files(
    'doca_flow.c',
    'doca_flow_grpc_client.cc',
    'flow_grpc.grpc.pb.cc',
    'flow_grpc.pb.cc',
    'grpc_orchestrator.grpc.pb.cc',
    'grpc_orchestrator.pb.cc'
)
headers=files(
    'doca_flow.h',
    'doca_flow_net.h',
    'doca_flow_grpc_client.h'
)
includes+=include_directories('../doca_common')
includes+=include_directories('../doca_log')

deps+=[
    'doca_log',
    'doca_common'
]


# grpc_flow_server
server_sources=files(
    'flow_grpc.grpc.pb.cc',
    'flow_grpc.pb.cc',
    'doca_flow_grpc_server.cc',
    'doca_flow.c'
)
base_cpp_args = [
	'-std=c++11'
]

grpc_deps=[]
foreach d:deps
        var_name = 'shared_' + d
        if not is_variable(var_name)
                build = false
                message('Missing dependency "@0@" for example "@1@"'.format(var_name, t))
                break
            endif
        grpc_deps += [get_variable(var_name)]
endforeach
grpc_deps+=dependency('libdpdk')
grpc_deps+=dependency('protobuf')
grpc_deps+=dependency('grpc++')
executable(
    'flow_grpc_server',
    server_sources,
    c_args:base_cpp_args,
    dependencies:grpc_deps,
    link_with:[],
    include_directories:includes,
    install:false
)

#flow_grpc_client
ext_deps+=dependency('protobuf')
ext_deps+=dependency('grpc++')