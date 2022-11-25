tests=[
    'nat',
    'switch',
    'firewall',
    'simple_fwd_vnf'
]
foreach t:tests
    sources=[]
    ext_deps = []
    ext_deps+=dependency('json-c')
    ext_deps+=dependency('libbsd')
    includes = [include_directories(t)]
    includes += include_directories('common')
    deps=[]
    link_whole_libs=[]
    ldflags=[]
    subdir(t)
    build=true
    dep_objs=ext_deps
    foreach d:deps
        var_name = 'shared_' + d
        if not is_variable(var_name)
                build = false
                message('Missing dependency "@0@" for example "@1@"'.format(var_name, t))
                break
            endif
        dep_objs += [get_variable(var_name)]
    endforeach

    if not build
        message('Skipping example "' + t + '"')
        continue
    endif
    if sources.length() == 0
        continue
    endif
    executable('app_'+t, sources,
            include_directories: includes,
            link_whole: link_whole_libs,
            link_args: ldflags,
            c_args: cflags,
            dependencies: dep_objs)

endforeach