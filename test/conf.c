#include <resolv.h>
#include <stdlib.h>
#include <stdio.h>



#define ENV_SPOOF "RESOLV_SPOOF_CHECK"
extern struct __res_state _res;
extern struct hconf _res_hconf;

int main()
{
//__res_maybe_init(&_res, 0);
res_init();
printf("ENV_SPOOF: %s!\n", getenv(ENV_SPOOF));
printf("resolv.conf: <options: EDNS0? %s ; insecure1? %s>\n", _res.options&RES_USE_EDNS0 ? "ON":"OFF", _res.options&RES_INSECURE1?"ON":"OFF");
/*printf("host.conf: <spoof: %s>!\n", _res_hconf.flags&HCONF_FLAG_SPOOFALERT ? "on&warn" :  
	(_res_hconf.flags&HCONF_FLAG_SPOOF ? "on&nowarn" : "off"));*/
return 0;
}
