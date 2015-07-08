#include "../logger.h"

#if defined(MAIN)
extern void ipc_dbus_listen();

int main()
{
	debug_log("getdns_IPC_DAEMON starting");
   	ipc_dbus_listen();
   	return 0;
}
#endif
