This tutorial is about how to rewrite the original application into a grpc-based application


### What is grpc
```
gRPC is a modern open source high performance Remote Procedure Call (RPC) framework that can run in any environment. It can efficiently connect services in and across data centers with pluggable support for load balancing, tracing, health checking and authentication. It is also applicable in last mile of distributed computing to connect devices, mobile applications and browsers to backend services.
```

Simply speaking, it to abstract a 'server' and a 'client' from original application. The server is running on the remote device and the client is running on local device. Through the agreed interface, the client can directly call the method on the server.


### How to do
* Prerequisite: get grpc on c++/python installed  

* Copy the original app under 'app' directory, and update array of iterated subdirs in app/meson.build  

* Create the proto file which define the interface between server and client  
* Build the interface definition and grpc orchestrator according to different language client of server use.  
    Python:
    ```
    python3 -m grpc_tools.protoc --python_out=. --grpc_python_out=. simple.proto -I.
    ```

    C++:
    ```
    protoc --plugin=protoc-gen-grpc=/usr/local/bin/grpc_cpp_plugin --grpc_out=. simple.proto
    protoc --cpp_out=. simple.proto

    ```
    This should produce 2 headers(simple.pb.h, simple.grpc.pb.h) and source files(simple.pb.cc, simple.grpc.pb.cc), include them in meson.build file.
* Rewrite server(run the original application, and implements the grpc service):
  * Implement grpc defined class and function
    * note: 'package simple' in simple.proto will create a namespace 'simple', using it when implement
  * Create grpc service
  * change the c file where the main function is located to cpp  
    * In order to call the functions defined in original file in c, add the following statement to the header
        ```
        #ifdef __cplusplus
        extern "C" {
        #endif
        ----------definitions--------
        #ifdef __cplusplus
        }
        #endif
        ```
  * Free up a processor for grpc's listening service. For example, with 4 cores assigned to the application with DPDK EAL option '-l 0-3', and launch grpc service on core-3 with "rte_eal_remote_launch"
  * Shutdown grpc service with lock. Since the service exists in a unique_ptr, so it cannot be called outside of the startup function.
    * Add a lock and tear down function to notify the lock
        ```
        static std::condition_variable server_lock;
        static void server_teardown()
        {
            server_lock.notify_one();
        }
        ```
    * lock the service function after start, and shut it down after lock released
        ```
        std::mutex mutex;
        std::unique_lock<std::mutex> lock(mutex);
        server_lock.wait(lock);
        server->Shutdown();
        ```
    * call the teardown function when signal received
* Write the client to call remote function
  * Create channel with specified address and call the function
* Write meson.build
    * Add the generated pb source files to build list
    * Add grpc dependency for meson.build
        ```
        all_deps+=dependency('protobuf')
        all_deps+=dependency('grpc++')
        ```
    * Build server and client each