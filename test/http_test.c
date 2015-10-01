// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include "../services/http.h"

#ifdef HTTP_MAIN
int main()
{
	//check_service(HTTP_SERV_STATUS_FILE);
	http_listen(80);
	return 0;
}
#endif

void nothing(){}
