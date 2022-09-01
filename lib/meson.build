libraries=[
    'doca_common',
    'doca_log',
    'doca_argp',
    'doca_flow'
]

default_cflags = []
foreach l : libraries
    sources = []
    headers = []
    includes = []
    cflags = default_cflags
    ext_deps = []
    ext_deps+=dependency('libdpdk')
    ext_deps+=dependency('threads')
    deps = []
    objs=[]
    lk_args=[]
    lk_deps=[]
    subdir(l)
    install_headers(headers)
    includes += include_directories(l)
    static_deps = ext_deps
    shared_deps = ext_deps
    foreach d:deps
        shared_deps += [get_variable('shared_' + d)]
        static_deps += [get_variable('static_' + d)]
    endforeach

    libname=l
    


    static_lib = static_library(libname,
            sources,
            c_args: cflags,
            dependencies: static_deps,
            include_directories: includes,
            install: true)
    static_dep = declare_dependency(
            include_directories: includes,
            dependencies: static_deps)
    

    shared_lib = shared_library(libname,
            sources,
            objects: objs,
            c_args: cflags,
            dependencies: shared_deps,
            include_directories: includes,
            link_args: lk_args,
            link_depends: lk_deps,
            install: true)
    shared_dep = declare_dependency(link_with: shared_lib,
            include_directories: includes,
            dependencies: shared_deps)

    set_variable('shared_' + l, shared_dep)
    set_variable('static_' + l, static_dep)
    

endforeach