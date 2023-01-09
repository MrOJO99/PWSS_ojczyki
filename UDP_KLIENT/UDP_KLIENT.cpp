#define _WINSOCK_DEPRECATED_NO_WARNINGS
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
#include <stdlib.h>
#include <fcntl.h>
#include <string>
#include <io.h>
#include <map>
#include <vector>
#include <iterator>

#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")

using namespace std;
#include <openssl/ssl.h>

#define SERVER "127.0.0.1"
#define PORT 12345
#define MAX_MESSAGE_LENGTH 4096

int main(int argc, char* argv[]) {
	WSADATA wsa_data;
	SOCKET client_socket;
	struct sockaddr_in server_address;
	SSL_CTX* ssl_context;
	SSL* ssl;
	char message[MAX_MESSAGE_LENGTH];
	int message_length;

	// Inicjalizacja biblioteki WinSock
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}

	// Inicjalizacja kontekstu szyfrowania SSL
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	ssl_context = SSL_CTX_new(DTLS_client_method());
	if (ssl_context == NULL){
		WSACleanup(); 
		fprintf(stderr, "SSL_CTX_new failed\n");
		return 1;
	}

	// Tworzenie gniazda klienta
	client_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (client_socket == INVALID_SOCKET) {
		SSL_CTX_free(ssl_context);
		WSACleanup(); 
		fprintf(stderr, "socket failed\n");
		return 1;
	}
	// Konfiguracja adresu serwera
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(SERVER);
	server_address.sin_port = htons(PORT);

	// Tworzenie kontekstu szyfrowania SSL
	ssl = SSL_new(ssl_context);
	if (ssl == NULL) {
		SSL_CTX_free(ssl_context);
		closesocket(client_socket);

		WSACleanup(); 
		fprintf(stderr, "SSL_new failed\n");
		return 1;
	}
	// Powiązanie kontekstu szyfrowania SSL z gniazdem połączenia
	if (SSL_set_fd(ssl, client_socket) == NULL) {
		SSL_CTX_free(ssl_context);
		SSL_free(ssl);
		closesocket(client_socket);

		WSACleanup();
		fprintf(stderr, "SSL_set_fd failed\n");
		return 1;
	};


	int seq_num = 0;
	// Pętla komunikacji z serwerem
	while (1) {
		seq_num = 0;
		// Oczekiwanie na wprowadzenie wiadomości od użytkownika
		printf("> ");
		fgets(message, MAX_MESSAGE_LENGTH, stdin);

		char temp[MAX_MESSAGE_LENGTH];
		strncpy(temp, message, strlen(message));
		temp[strlen(message)] = '\0';
		sprintf(message, "%d %s", seq_num, temp);

		// Usunięcie znaku nowej linii z końca wiadomości
		if (message[strlen(message) - 1] == '\n') {
			message[strlen(message) - 1] = '\0';
		}
		seq_num++;
		if (strncmp(temp, "save", 4) == 0)
		{
			FILE* file = fopen("plik.txt", "rb");
			if (file == NULL) {
				perror("Nie udało się otworzyć pliku");
				break;
			}

			// Wysyłanie komendy do serwera
			if (sendto(client_socket, message, strlen(message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) != strlen(message)) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
			int n;

			while ((n = fread(message, 1, MAX_MESSAGE_LENGTH, file)) > 0) {
				message[n] = '\0';
				strncpy(temp, message, strlen(message));
				temp[strlen(message)] = '\0';
				sprintf(message, "%d %s", seq_num, temp);
				seq_num++;
				if (sendto(client_socket, message, strlen(message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) != strlen(message)) {
					fprintf(stderr, "sendto failed\n");
					break;
				}
			}

			sprintf(message, "%d %s", seq_num, "_END_");
			if (sendto(client_socket, message, strlen(message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) != strlen(message)) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
		}
		else if (strncmp(temp, "download", 8) == 0)
		{
			// Wysyłanie komendy do serwera
			if (sendto(client_socket, message, strlen(message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) != strlen(message)) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
			seq_num = 0;
			while (1) {
				int server_address_length = sizeof(server_address);
				message_length = recvfrom(client_socket, message, MAX_MESSAGE_LENGTH, 0, (struct sockaddr*)&server_address, &server_address_length);
				if (message_length < 0) {
					fprintf(stderr, "recvfrom failed\n");
					break;
				}
				int received_seq_num;
				sscanf(message, "%d", &received_seq_num);


				if (received_seq_num == seq_num) {
					seq_num++;
				}
				else {
					printf("Received message out of order. Expected sequence number: %d, received: %d\n", seq_num, received_seq_num);
					return -1;
				}
				message[message_length] = '\0';
				char* space_ptr = strchr(message, ' ');
				if (space_ptr) { // if a space was found
					memmove(message, space_ptr + 1, strlen(space_ptr));
				}
				// Sprawdzanie, czy otrzymano znak konca wysylania danych
				if (strncmp(message, "_END_", 5) == 0)
				{
					break;
				}
				printf("%s", message);
			}
			printf("\n");

		}
		else // Wysłanie wiadomości do serwera
			if (sendto(client_socket, message, strlen(message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) != strlen(message)) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
		// Sprawdzenie, czy użytkownik nie zakończył komunikacji
		if (strncmp(temp, "bye", 3) == 0) {
			break;
		}
	}
	// Zamykanie połączenia z serwerem
	SSL_shutdown(ssl);
	closesocket(client_socket);

	// Zwolnienie zasobów
	SSL_free(ssl);
	SSL_CTX_free(ssl_context);
	WSACleanup();

	return 0;
}
