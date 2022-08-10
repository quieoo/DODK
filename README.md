# Prerequisite
## Install DPDK
For example: 

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