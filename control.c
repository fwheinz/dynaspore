#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>

#include "xfc.h"


void reply (FILE *sock, int code, char *msg) {
	fprintf(sock, "HTTP/1.0 %d 1337\r\nContent-type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n", code);
	if (msg)
		fprintf(sock, "%s\r\n", msg);
	fflush(sock);
}

void resetstats (void) {
	memset(ss.corestats, '\0', ss.nrcores*sizeof(struct corestats));
	steps = 0;
	ss.lastreset = getmstimestamp();
}

void handle_lua (FILE *sock, char *cmd, char *param, char *post) {
	if (!strcasecmp(cmd, "exec")) {
		lua_handle_webexec(sock, param, post);
	} else if (!strcasecmp(cmd, "reset")) {
		if (xl_init(sock))
			reply(sock, 200, "Lua engine resetted");
	} else if (!strcasecmp(cmd, "reload")) {
		if (xl_reload(sock))
			reply(sock, 200, "Lua master script reloaded");
	} else if (!strcasecmp(cmd, "sleep")) {
		lua_lock();
		sleep(5);
		lua_unlock();
	} else {
		reply(sock, 404, "Command not found");
	}
}

void handle_request (FILE *sock, char *req, char *post) {
	char *subsys, *cmd, *param;

	DEBUG(3, "Control-Request: %s\n", req);

	subsys = req;

	req = strchr(req, '/');
	if (!req) {
		reply(sock, 404, "No Command");
		return;
	}
	*req = '\0';
	req++;
	cmd = req;

	req = strchr(req, '/');
	if (!req) {
		reply(sock, 404, "No Parameters");
		return;
	}
	*req = '\0';
	req++;
	param = req;

	// Dispatch subsystems here
	if (!strcasecmp(subsys, "lua"))
		handle_lua(sock, cmd, param, post);
	else
		lua_handle_webrequest(sock, subsys, cmd, param, post);
}

__thread char sid[256];

static void _handle_connection (FILE *sock) {
	char buf[4096], *req, line[4096];

	DEBUG(3, "New connection, reading...\n");
	req = fgets(buf, sizeof(buf), sock);
	if (!req) {
		DEBUG(3, "Premature EOF, returning...\n");
		return;
	}
	char *ptr = strchr(req, ' ');
	if (!ptr)
		return;
	while (*ptr && *ptr++ == ' ')
		;
	req = ptr;
	ptr = strchr(ptr, ' ');
	if (!ptr)
		return;
	*ptr = '\0';
	int cl = -1;
        char *_sid = NULL;
	while ((ptr = fgets(line, sizeof(line), sock))) {
		if (!strncasecmp(line, "content-length: ", 16)) {
			cl = atoi(line + 16);
		} else if (!strncasecmp(line, "x-session: ", 11)) {
			_sid = line + 11;
                        _sid[strcspn(_sid, "\r\n")] = 0; // remove trailing nl
                        strncpy(sid, _sid, sizeof(sid));
                        sid[sizeof(sid)-1] = '\0';
		}
		if (*line == '\r' || *line == '\n')
			break;
	}
	DEBUG(3, "Handling request %s\n", req);
	if (cl > 0 && cl < 10000000) {
		char *post = alloca(cl+1);
		int st = fread(post, cl, 1, sock);
		post[cl] = '\0';
		if (st != 1)
			return;
		handle_request(sock, req, post);
	} else {
		handle_request(sock, req, NULL);
	}
}

static void *handle_connection (void *arg) {
	int fd = (unsigned long)arg;
	FILE *sock = fdopen(fd, "r+");
	_handle_connection(sock);
	fclose(sock);

	return NULL;
}


static void handle_clients (int fd) {
	struct sockaddr_in peer;
	socklen_t peerlen;

	do {
		peerlen = sizeof(peer);
		int cl = accept(fd, (struct sockaddr *) &peer, &peerlen);
		if (cl < 0)
			continue;
		pthread_t t;
		pthread_create(&t, NULL, handle_connection, (void*)((unsigned long)cl));
		pthread_detach(t);
	} while (1);

}

void *start_control (void *arg) {
	struct sockaddr_in s;
	int one = 1;

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	s.sin_family = AF_INET;
	s.sin_port = htons(8080);
	s.sin_addr.s_addr = INADDR_ANY;
	bind(fd, (struct sockaddr *) &s, sizeof(struct sockaddr_in));
	listen(fd, 128);
	handle_clients(fd);

	return NULL;
}

