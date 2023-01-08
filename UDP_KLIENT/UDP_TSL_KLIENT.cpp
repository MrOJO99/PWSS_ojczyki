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
#include <openssl/ssl.h>

#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")

using namespace std;


#define SERVER "127.0.0.1"
#define PORT 12345
#define MAX_MESSAGE_LENGTH 1024

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
	if (ssl_context == NULL) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return 1;
	}

	// Tworzenie gniazda klienta
	client_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (client_socket == INVALID_SOCKET) {
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
		fprintf(stderr, "SSL_new failed\n");
		return 1;
	}
	// Powiązanie kontekstu szyfrowania SSL z gniazdem połączenia
	SSL_set_fd(ssl, client_socket);

	// Pętla komunikacji z serwerem
	while (1) {
		// Oczekiwanie na wprowadzenie wiadomości od użytkownika
		printf("> ");
		fgets(message, MAX_MESSAGE_LENGTH, stdin);
		message_length = strlen(message);
		// Usunięcie znaku nowej linii z końca wiadomości
		if (message[message_length - 1] == '\n') {
			message[message_length - 1] = '\0';
			message_length--;
		}


		if (strncmp(message, "save", 4) == 0)
		{
			FILE* file = fopen("plik.txt", "rb");
			if (file == NULL) {
				perror("Nie udało się otworzyć pliku");
				exit(1);
			}

			// Wysyłanie komendy do serwera
			if (sendto(client_socket, "save", 4, 0, (struct sockaddr*)&server_address, sizeof(server_address)) != message_length) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
			int n;

			while ((n = fread(message, 1, MAX_MESSAGE_LENGTH, file)) > 0) {
				if (sendto(client_socket, message, n, 0, (struct sockaddr*)&server_address, sizeof(server_address)) != n) {
					fprintf(stderr, "sendto failed\n");
					break;
				}
			}
			if (sendto(client_socket, "_END_", 5, 0, (struct sockaddr*)&server_address, sizeof(server_address)) != 5) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
		}
		else if (strncmp(message, "download", 8) == 0)
		{
			// Wysyłanie komendy do serwera
			if (sendto(client_socket, "download", 8, 0, (struct sockaddr*)&server_address, sizeof(server_address)) != message_length) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
			while (1) {
				int server_address_length = sizeof(server_address);
				message_length = recvfrom(client_socket, message, MAX_MESSAGE_LENGTH, 0, (struct sockaddr*)&server_address, &server_address_length);
				if (message_length < 0) {
					fprintf(stderr, "recvfrom failed\n");
					break;
				}
				message[message_length] = '\0';
				printf("%s\n", message);

				// Sprawdzanie, czy otrzymano znak konca wysylania danych
				if (strncmp(message, "_END_", 5) == 0)
				{
					break;
				}
				message[message_length] = '\0';
				printf("%s", message);
			}
			printf("\n");

		}
		else // Wysłanie wiadomości do serwera
			if (sendto(client_socket, message, message_length, 0, (struct sockaddr*)&server_address, sizeof(server_address)) != message_length) {
				fprintf(stderr, "sendto failed\n");
				break;
			}
		// Sprawdzenie, czy użytkownik nie zakończył komunikacji
		if (strcmp(message, "bye") == 0) {
			break;
		}
	}
	// Zamykanie połączenia z serwerem
	SSL_shutdown(ssl);
	closesocket(client_socket);

	// Zwolnienie zasobów
	SSL_CTX_free(ssl_context);
	WSACleanup();

	return 0;
}
