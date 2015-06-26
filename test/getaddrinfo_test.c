#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char **argv)
{
	struct addrinfo hints, *result, *ai;
	int ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	//hints.ai_flags = AI_V4MAPPED;

	ret = getaddrinfo(argv[1], NULL, &hints, &result);
	if (ret) {
		printf("getaddrinfo(%s) failed: %i: %s\n",
			argv[1], ret, gai_strerror(ret));
		return 1;
	}

	for (ai = result; ai != NULL; ai = ai->ai_next)
	{
		if (ai->ai_family == AF_INET)
			printf("this is an IPv4 result\n");
		else if(ai->ai_family == AF_INET6)
			printf("this is an IPv6 result\n");
		else
			printf("eww what's this?\n");
	}

	freeaddrinfo(result);
}
