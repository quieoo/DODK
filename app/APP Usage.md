# nat
1. introduction 

    A network address translation (NAT) application leverages the DPU's hardware capability to switch packets with local IP addresses to global ones and vise versa. (https://docs.nvidia.com/doca/sdk/nat/index.html)


2. usage

    on DPU:
    ```
    cd dodk/build
    ./app/app_nat -m static -r ../app/nat/nat_static_rules.json -wan 0000:01:00.0 -lan 0000:01:00.1 -F
    ```
# switch
1. instroduction

    DOCA Switch is a network application that leverages the DPU's hardware capability for internal switching between representor ports on the DPU.

    DOCA Switch is based on the DOCA Flow library. As such, it exposes a command line interface which receives DOCA Flow like commands to allow adding rules in real time.
    (https://docs.nvidia.com/doca/sdk/switch/index.html)

2, usage

    on DPU: 
    ```
    ./app_switch
    ```

# firewall 
1. instroduction

    A firewall application is a network security application that leverages the DPU's hardware capability to monitor incoming and outgoing network traffic and allow or block packets based on a set of preconfigured rules.

    The firewall application is based on DOCA Flow gRPC, used for remote programming of the DPU's hardware.

    The firewall can operate in two modes:
        Static mode – the firewall application gets 5-tuple traffic from the user with a JSON file for packets to be dropped. The packets that do not match any of the 5-tuple are forwarded by a hairpin pipe.
    Interactive mode – the user can add rules from the command line in real time to execute different firewall rules
    (https://docs.nvidia.com/doca/sdk/firewall/index.html)

2. usage

    on dpu:
    ```
    cd orchestrator
    python3 grpc_server.py
    ```

    on host:
    ```
    ./app/app_firewall_new -g localhost -m static -r ../app/firewall_new/firewall_rules.json
    ```