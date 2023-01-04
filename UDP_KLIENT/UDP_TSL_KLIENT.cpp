#undef UNICODE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define ROZMIAR 20
#define _XOPEN_SOURCE_EXTENDED 1
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <filesystem>
#include <stdio.h>
#include <fcntl.h>
#include <string>
#include <io.h>
#include <map>
#include <vector>
#include <iterator>
using namespace std;
#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

const int BUFFER_SIZE = 1024;
const int TIMEOUT_MS = 500;


void ShowCerts(SSL* ssl);

int main(int argc, char* argv[]) {
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    if (ctx == NULL) {
        std::cerr << "Error creating DTLS context." << std::endl;
        return 1;
    }
   
    WSADATA wsaData;
    // inicjalizacja ÄąÄ˝Ă„â€¦danej wersja biblioteki WinSock
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        //  printf("WSAStartup failed: %d\n", ret);
        return 1;
    }
    unsigned short port = 1711;
    struct sockaddr_in sockfd;
    sockfd.sin_port = ntohs(port);
    sockfd.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &(sockfd.sin_addr)) <= 0)  // Inicjalizacja struktury
    {
        //printf("Nieprawidlowy adres \n");
        return -1;
    }

    int sock = socket(sockfd.sin_family, SOCK_DGRAM, 0);



    if (connect(sock, (struct sockaddr*)&sockfd, sizeof(sockfd)) != 0)
    {
        printf("Polaczenie nieudane \n");
        SSL_CTX_free(ctx);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    SSL* ssl = SSL_new(ctx);
    //ShowCerts(ssl);
    if ((SSL_set_fd(ssl, sock)) == 0)// dołączenie dyskryptora do gniazda 
    {
        printf("Blad deskryptora");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        closesocket(sock);
        WSACleanup();
    }
    int res = SSL_connect(ssl);
    if (res < 0)   // sprawdzenie połączenia  
    {
        printf("Connection failed");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        closesocket(sock);
        WSACleanup();
    }
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        // get any certs 

        std::fstream file;
        file.open("C:\\Users\\mrojo\\source\\repos\\UDP_TSL_KLIENT\\UDP_TSL_KLIENT\\plik.txt", std::ios::binary || std::ios::out);
        if (!file.is_open()) {
            std::cerr << "BĹ‚Ä…d przy otwieraniu pliku" << std::endl;
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            closesocket(sock);
            WSACleanup();
            return 1;
        }

        // PÄ™tla wysyĹ‚ajÄ…ca fragmenty pliku
        char buffer[BUFFER_SIZE];
        while (!file.eof()) {
            file.read((char*)&buffer, sizeof(buffer));
            // WysyĹ‚amy fragment pliku za pomocÄ… SSL_write
            int ret = SSL_write(ssl, buffer, sizeof(buffer));
            // printf("%s", ERR_error_string(ERR_get_error(), NULL));
            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);
                std::cout << error;
                if (error == SSL_ERROR_WANT_WRITE) {
                    std::cout << "SSL_ERROR_WANT_WRITE";
                }
                else if (error == SSL_ERROR_WANT_READ) {
                    std::cout << "SSL_ERROR_WANT_READ";
                }
                else if (error == SSL_ERROR_SYSCALL) {
                    std::cout << "SSL_ERROR_SYSCALL";
                }
                else if (error == SSL_ERROR_SSL) {
                    std::cout << "SSL_ERROR_SSL";
                }
                cerr << "Sending File Error:  " << SSL_get_error(ssl, ret) << std::endl;
                file.close();
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                closesocket(sock);
                WSACleanup();
                return 1;
            }
            //cout << "Send: " << ret << " bytes" << endl;
            Sleep(1);
        }

        // Zamykamy plik i gniazdo oraz zwalniamy zasoby
        file.close();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        WSACleanup();

        return 0;
    }
}

void ShowCerts(SSL* ssl)
{
    X509* cert;
    char* line;

    cert = SSL_get_peer_certificate(ssl); //pobieranie certyfikatu serwera
    if (cert != NULL)
    {
        printf("Certyfikat serwera:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);//nazwa podmiotu certyfikatu
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("Brak certyfikatu.\n");
}