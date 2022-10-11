# Clone all with submodule
```
git clone --recurse-submodules https://github.com/quieoo/DODK.git

```

# Prerequisite
## Install DPDK

Prerequistes for DPDK
```
sudo apt install build-essential python3-pyelftools libnuma-dev
```

install the latest meson.build with pip (tested version is 0.61.2, the lower may bring some problem)

```
sudo apt install python3-pip
sudo pip3 install meson
sudo pip3 install ninja
```

Build dpdk

```
cd dpdk
meson build
cd build
ninja
sudo ninja install
sudo ldconfig
```

## Install gRPC-python
Install pip3 if necessary
```
sudo apt install python3-pip
```
or, upgrade the version of pip:
```
python3 -m pip install --upgrade pip
```

Install gRPC:
```
sudo python3 -m pip install grpcio
sudo python3 -m pip install grpcio-tools
```


# Build DODK and install
```
sudo apt install pkg-config
git clone https://github.com/quieoo/DODK.git
cd DODK
meson build
cd build
ninja
ninja install 
lsconfig
```

Run sample application, for example:
```
./app/simple_fwd_vnf/simple_fwd_vnf -l 0-3 -n 4
```

note: run dpdk application need some extra configrations, such as hugepage, root authority, and dpdk-supported nic


## gRPC Orchestrator
On server side (DPU)
```
cd orchestrator
python3 grpc_server.py
```

On Client side (HOST), create remote program
```
python3 grpc_client.py -a 101.76.213.102 -c app_simple_fwd_vnf -s '-l 0-3 -n 4 -ll 2'
```
