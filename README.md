# Prerequisite
## Install DPDK

### Prerequistes for DPDK
```
sudo apt install build-essential
sudo apt install python3-pyelftools
sudo apt install libnuma-dev
sudo apt install meson
```

```
git clone https://github.com/DPDK/dpdk.git
cd dpdk
meson build
cd build
ninja
sudo ninja install
sudo ldconfig
```


# Build Sample Applications
```
sudo apt install pkg-config
git clone https://github.com/quieoo/DODK.git
cd DODK
meson build
cd build
ninja
```

Run application, for example:
```
./app/simple_fwd_vnf/simple_fwd_vnf -l 0-7 -n 8
```

note: run dpdk application need some extra configrations, such as hugepage, root authority, and dpdk-supported nic
