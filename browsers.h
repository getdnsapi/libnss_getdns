#ifndef _BROWSERS_HINTS_H_
#define _BROWSERS_HINTS_H_
struct query_hints
{
	int pid, ppid, af;
	char *name;
	float score;
};

#define DESKTOP_APP_ENTRIES_DIR "/usr/share/applications"
#define KNOWN_BROWSERS "wget, curl, firefox, chrome, chromium-browser, opera, epiphany, epiphany-browser, links2"
#define THRESHOLD 0.70

int is_known_browser(struct query_hints *params);
void display_error_page(char *ref_arg, int err_code);
int browser_check(int af);
#endif
