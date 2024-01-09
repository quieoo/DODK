#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_socket, new_socket;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE] = {0};

    // 创建 socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 绑定服务器地址
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    // 监听
    if (listen(server_socket, 5) == -1) {
        perror("Listening failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        socklen_t client_addr_len = sizeof(client_addr);

        // 接受客户端连接
        if ((new_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len)) == -1) {
            perror("Acceptance failed");
            exit(EXIT_FAILURE);
        }

        // 从客户端接收数据
        ssize_t bytes_received = recv(new_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received == -1) {
            perror("Receiving data failed");
            exit(EXIT_FAILURE);
        }

        // 打印接收到的数据
        printf("Received from client: %s", buffer);

        // 在这里不关闭连接，等待下一个请求到来

        // 清空缓冲区
        memset(buffer, 0, sizeof(buffer));
    }

    // 注意：这里不关闭服务器 socket，因为服务器一直在运行

    return 0;
}
