# nat
1. introduction 

    A network address translation (NAT) application leverages the DPU's hardware capability to switch packets with local IP addresses to global ones and vise versa. (https://docs.nvidia.com/doca/sdk/nat/index.html)


2. usage

    on DPU:
    ```
    cd dodk/build
    ./app/app_nat -m static -r ../app/nat/nat_static_rules.json -wan 0000:01:00.0 -lan 0000:01:00.1 -F
    ```