#define _WINSOCK_DEPRECATED_NO_WARNINGS
#undef UNICODE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <iostream>
#include <sys/types.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

int sendData(SOCKET socketK, const char* dataTest, int size)
{
    int total = 0;    	
    int bytesleft = size; 
    int n;
    while (total < size) {
        n = send(socketK, dataTest + total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    size = total; 
    return bytesleft;
}
int main()
{
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
       
    }
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
   
    OpenSSL_add_all_algorithms();

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        
        
    }

    BIO* bio = BIO_new_dgram(sock, BIO_NOCLOSE);

    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_use_certificate_file(ctx, "C:\\Users\\mrojo\\source\\repos\\UDP_TSL_SERVER\\my.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "C:\\Users\\mrojo\\source\\repos\\UDP_TSL_SERVER\\my-pass.pem", SSL_FILETYPE_PEM);

    // Create an SSL structure for the connection
    SSL* ssl = SSL_new(ctx);

    // Set the BIO for the SSL structure
    SSL_set_bio(ssl, bio, bio);

    // Connect to the server
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(1711);
    ret = SSL_connect(ssl);
    if (ret <= 0) {
        // Handle error
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_SSL) {
           

        }


      
    }

    FILE* file;
    fopen_s(&file, "C:\\Users\\mrojo\\source\\repos\\UDP_TSL_SERVER\\plik.txt", "rb");
    if (file == NULL) {
        // Error opening file
        return -1;
    }
    char buffer[1024];
    int len;
    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        len = SSL_write(ssl, buffer, strlen(buffer));
        if (len <= 0) {
            cout << "Sending error" << endl;
            break;
        }
        cout << "Send: " << len << " bytes data" << endl;
    }

    // Close the file and DTLS BIO, and clean up the OpenSSL library
    fclose(file);
    BIO_free(bio);
    CRYPTO_cleanup_all_ex_data();

    return 0;

}