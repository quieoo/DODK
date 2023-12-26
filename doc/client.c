#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 80
#define SERVER_IP "10.70.113.32"
#define BUFFER_SIZE 1024

int main() {
    int client_socket;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE];

    // 创建套接字
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_address.sin_port = htons(PORT);

    // 连接到服务器
    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server on port %d\n", PORT);

    // 发送HTTP请求
    char request[] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    send(client_socket, request, strlen(request), 0);

    // 接收HTTP响应
    memset(buffer, 0, sizeof(buffer));
    if (recv(client_socket, buffer, sizeof(buffer), 0) == -1) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }

    printf("Received HTTP response from server:\n%s\n", buffer);

    // 关闭套接字
    close(client_socket);

    return 0;
}
