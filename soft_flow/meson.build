app='soft_flow'
sources=files('main.c')

includes = []
deps = []
deps += dependency('libdpdk')
link_whole_libs=[]
ldflags=[]
build=true
executable(app, sources,
        include_directories: includes,
        link_whole: link_whole_libs,
        link_args: ldflags,
        c_args: cflags,
        dependencies: deps)
