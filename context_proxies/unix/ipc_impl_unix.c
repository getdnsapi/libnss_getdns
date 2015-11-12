// Copyright Verisign, Inc and NLNetLabs.  See LICENSE file for details

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "../../nss_getdns.h"
#include "../../logger.h"
#include "../../context_interface.h"
#include "../../query.h"
#include "../../logger.h"
#include "../../services/http.h"
#include "ipc_impl_unix.h"


/* Eventloop based on select */
#define MAX_TIMEOUTS FD_SETSIZE

typedef struct my_eventloop {
	getdns_eventloop        base;
	getdns_eventloop_event *fd_events[FD_SETSIZE];
	uint64_t                fd_timeout_times[FD_SETSIZE];
	getdns_eventloop_event *timeout_events[MAX_TIMEOUTS];
	uint64_t                timeout_times[MAX_TIMEOUTS];
} my_eventloop;

static uint64_t get_now_plus(uint64_t amount)
{
	struct timeval tv;
	uint64_t       now;
	
	if (gettimeofday(&tv, NULL)) {
		perror("gettimeofday() failed");
		exit(EXIT_FAILURE);
	}
	now = tv.tv_sec * 1000000 + tv.tv_usec;

	return (now + amount * 1000) >= now ? now + amount * 1000 : -1;
}

static getdns_return_t
my_eventloop_schedule(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *event)
{
	my_eventloop *my_loop  = (my_eventloop *)loop;
	size_t        i;

	assert(loop);
	assert(event);
	assert(fd < FD_SETSIZE);

	log_debug( "%s(loop: %p, fd: %d, timeout: %"PRIu64", event: %p)\n"
	        , __FUNCTION__, loop, fd, timeout, event);
	if (fd >= 0 && (event->read_cb || event->write_cb)) {
		assert(my_loop->fd_events[fd] == NULL);

		my_loop->fd_events[fd] = event;
		my_loop->fd_timeout_times[fd] = get_now_plus(timeout);
		event->ev = (void *) (intptr_t) fd + 1;

		log_debug( "scheduled read/write at %d\n", fd);
		return GETDNS_RETURN_GOOD;
	}

	assert(event->timeout_cb && !event->read_cb && !event->write_cb);

	for (i = 0; i < MAX_TIMEOUTS; i++) {
		if (my_loop->timeout_events[i] == NULL) {
			my_loop->timeout_events[i] = event;
			my_loop->timeout_times[i] = get_now_plus(timeout);
			event->ev = (void *) (intptr_t) i + 1;

			log_debug( "scheduled timeout at %d\n", (int)i);
			return GETDNS_RETURN_GOOD;
		}
	}
	return GETDNS_RETURN_GENERIC_ERROR;
}

static getdns_return_t
my_eventloop_clear(getdns_eventloop *loop, getdns_eventloop_event *event)
{
	my_eventloop *my_loop = (my_eventloop *)loop;
	size_t i;

	assert(loop);
	assert(event);

	log_debug( "%s(loop: %p, event: %p)\n", __FUNCTION__, loop, event);

	i = (intptr_t)event->ev - 1;
	assert(i >= 0 && i < FD_SETSIZE);

	if (event->timeout_cb && !event->read_cb && !event->write_cb) {
		assert(my_loop->timeout_events[i] == event);
		my_loop->timeout_events[i] = NULL;
	} else {
		assert(my_loop->fd_events[i] == event);
		my_loop->fd_events[i] = NULL;
	}
	event->ev = NULL;
	return GETDNS_RETURN_GOOD;
}

static void my_eventloop_cleanup(getdns_eventloop *loop)
{
}

static void my_read_cb(int fd, getdns_eventloop_event *event)
{
	log_debug( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->read_cb(event->userarg);
}

static void my_write_cb(int fd, getdns_eventloop_event *event)
{
	log_debug( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->write_cb(event->userarg);
}

static void my_timeout_cb(int fd, getdns_eventloop_event *event)
{
	log_debug( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->timeout_cb(event->userarg);
}

static void my_eventloop_run_once(getdns_eventloop *loop, int blocking)
{
	my_eventloop *my_loop = (my_eventloop *)loop;

	fd_set   readfds, writefds;
	int      fd, max_fd = -1;
	uint64_t now, timeout = (uint64_t)-1;
	size_t   i;
	struct timeval tv;

	assert(loop);

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	now = get_now_plus(0);

	for (i = 0; i < MAX_TIMEOUTS; i++) {
		if (!my_loop->timeout_events[i])
			continue;
		if (now > my_loop->timeout_times[i])
			my_timeout_cb(-1, my_loop->timeout_events[i]);
		else if (my_loop->timeout_times[i] < timeout)
			timeout = my_loop->timeout_times[i];
	}
	for (fd = 0; fd < FD_SETSIZE; fd++) {
		if (!my_loop->fd_events[fd])
			continue;
		if (my_loop->fd_events[fd]->read_cb)
			FD_SET(fd, &readfds);
		if (my_loop->fd_events[fd]->write_cb)
			FD_SET(fd, &writefds);
		if (fd > max_fd)
			max_fd = fd;
		if (my_loop->fd_timeout_times[fd] < timeout)
			timeout = my_loop->fd_timeout_times[fd];
	}
	if (max_fd == -1 && timeout == (uint64_t)-1)
		return;

	if (! blocking || now > timeout) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	} else {
		tv.tv_sec  = (timeout - now) / 1000000;
		tv.tv_usec = (timeout - now) % 1000000;
	}
	if (select(max_fd + 1, &readfds, &writefds, NULL, &tv) < 0) {
		perror("select() failed");
		exit(EXIT_FAILURE);
	}
	now = get_now_plus(0);
	for (fd = 0; fd < FD_SETSIZE; fd++) {
		if (my_loop->fd_events[fd] &&
		    my_loop->fd_events[fd]->read_cb &&
		    FD_ISSET(fd, &readfds))
			my_read_cb(fd, my_loop->fd_events[fd]);

		if (my_loop->fd_events[fd] &&
		    my_loop->fd_events[fd]->write_cb &&
		    FD_ISSET(fd, &writefds))
			my_write_cb(fd, my_loop->fd_events[fd]);

		if (my_loop->fd_events[fd] &&
		    my_loop->fd_events[fd]->timeout_cb &&
		    now > my_loop->fd_timeout_times[fd])
			my_timeout_cb(fd, my_loop->fd_events[fd]);

		i = fd;
		if (my_loop->timeout_events[i] &&
		    my_loop->timeout_events[i]->timeout_cb &&
		    now > my_loop->timeout_times[i])
			my_timeout_cb(-1, my_loop->timeout_events[i]);
	}
}

static void my_eventloop_run(getdns_eventloop *loop)
{
	my_eventloop *my_loop = (my_eventloop *)loop;
	size_t        i;

	assert(loop);

	i = 0;
	while (i < MAX_TIMEOUTS) {
		if (my_loop->fd_events[i] || my_loop->timeout_events[i]) {
			my_eventloop_run_once(loop, 1);
			i = 0;
		} else {
			i++;
		}
	}
}

static getdns_eventloop *my_eventloop_init(my_eventloop *loop)
{
	static getdns_eventloop_vmt my_eventloop_vmt = {
		my_eventloop_cleanup,
		my_eventloop_schedule,
		my_eventloop_clear,
		my_eventloop_run,
		my_eventloop_run_once
	};

	(void) memset(loop, 0, sizeof(my_eventloop));
	loop->base.vmt = &my_eventloop_vmt;
	return &loop->base;
}

#define MAXBUFSIZ sizeof(response_bundle)
#define ADDRESS "/var/tmp/getdns_module_unix.sock"
#define BACKLOG_SIZE 64

typedef struct server_state {
	getdns_eventloop_event ev;
	int                    fd;
	getdns_context        *context;
	getdns_dict           *extensions;
	time_t                 last_changed;
	my_eventloop           loop;
} server_state;

typedef struct client_connection {
	getdns_eventloop_event ev;
	int                    cfd;
	server_state          *s;
	req_params             req;
	char                   overflow_spc;
	response_bundle       *reply;
} client_connection;

static void write_reply_cb(void *userarg)
{
	client_connection   *conn = userarg;

	ssize_t              wsz;

	assert(conn);

	my_eventloop_clear(&conn->s->loop.base, &conn->ev);
	conn->ev.write_cb = NULL;

	if ((wsz = write(conn->cfd, conn->reply, sizeof(response_bundle))) < 0)
		log_warning("ipc_unix_listen< write: %s >", strerror(errno));

	else if (wsz < sizeof(response_bundle))
		log_warning("ipc_unix_listen< write: underflow error >");

	if (conn->reply && conn->reply != &RESP_BUNDLE_EMPTY)
		free(conn->reply);

	close(conn->cfd);
	free(conn);
}

static void lookup_response_cb(getdns_context *context,
    getdns_callback_type_t callback_type, getdns_dict *response,
    void *userarg, getdns_transaction_t t)
{
	client_connection *conn = userarg;
	getdns_return_t    r;

	log_debug("ipc_unix_listen< response for transaction %"PRIu64" >", t);

	if (!conn) {
		log_warning("ipc_unix_listen< no userarg: %"PRIu64" >", t);
		return;
	}
	if (callback_type != GETDNS_CALLBACK_COMPLETE)
		log_warning("ipc_unix_listen< callback type %d: %"PRIu64" >"
		           , callback_type, t);

	else if (!response)
		log_warning("ipc_unix_listen< NULL response>");

	else if ((r = parse_addr_bundle(response, &conn->reply, &conn->req)))
		log_warning("ipc_unix_listen< parse error: %d >", r);

	if (!conn->reply) {
		log_warning("ipc_unix_listen< RESPONSE_BUNDLE is null >");
		conn->reply = &RESP_BUNDLE_EMPTY;
	}
	if (conn->req.reverse) {
		log_debug("ipc_unix_listen< reversed reply: %s >", conn->reply->cname);
	}
	conn->ev.write_cb = write_reply_cb;

	log_debug("ipc_unix_listen< schedule write for fd: %d >", conn->cfd);
	(void) my_eventloop_schedule(&conn->s->loop.base, conn->cfd, -1, &conn->ev);

	if (response)
		getdns_dict_destroy(response);
}

static void read_request_cb(void *userarg)
{
	client_connection   *conn = userarg;

	ssize_t              rsz;
	getdns_return_t      r;
	getdns_transaction_t transaction_id;

	assert(conn);

	my_eventloop_clear(&conn->s->loop.base, &conn->ev);
	conn->ev.read_cb = NULL;

	if ((rsz = read(conn->cfd, (void *)&conn->req, sizeof(req_params) + 1)) < 0)
		log_warning("ipc_unix_listen< read: %s >", strerror(errno));

	else if (rsz < sizeof(req_params))
		log_warning("ipc_unix_listen< read: underflow error >");

	else if (rsz > sizeof(req_params))
		log_warning("ipc_unix_listen< read: overflow error >");

	else if (!conn->req.reverse) {
		/* Query for addresses */
		if ((r = getdns_address(
		    conn->s->context, conn->req.query, conn->s->extensions,
		    conn, &transaction_id, lookup_response_cb)))

			log_warning("ipc_unix_listen< getdns_address: %d>", r);
		else {
			log_debug("ipc_unix_listen< read: request for "
			          "%s scheduled: %"PRIu64">"
			         , conn->req.query, transaction_id);
			return; /* Success */
		}
	} else {
		static const getdns_bindata TYPE_IPv4 = { 4, (void *)"IPv4" };
		static const getdns_bindata TYPE_IPv6 = { 4, (void *)"IPv6" };

		char           dd[16];
		getdns_dict   *address = NULL;
		getdns_bindata address_data;
		
		address_data.size = conn->req.af == AF_INET6 ? 16 : 4;
		address_data.data = (void *)dd;

		if (inet_pton(conn->req.af, conn->req.query, dd) <= 0)
			log_warning("ipc_unix_listen< inet_pton for %s>", conn->req.query);

		else if (!(address = getdns_dict_create()))
			log_warning("ipc_unix_listen< could not create address bindata >");

		else if ((r = getdns_dict_set_bindata(address, "address_type",
		    conn->req.af == AF_INET6 ? &TYPE_IPv6 : &TYPE_IPv4 )))
			log_warning("ipc_unix_listen< could not set address_type >");

		else if ((r = getdns_dict_set_bindata(address, "address_data", &address_data)))
			log_warning("ipc_unix_listen< could not set address_data >");
			
		else if ((r = getdns_hostname(
		    conn->s->context, address, conn->s->extensions,
		    conn, &transaction_id, lookup_response_cb)))

			log_warning("ipc_unix_listen< getdns_hostname: %d>", r);
		else {
			log_debug("ipc_unix_listen< read: reversed request for "
			          "%s scheduled: %"PRIu64">"
			         , conn->req.query, transaction_id);

			getdns_dict_destroy(address);
			return; /* Success */
		}
		getdns_dict_destroy(address);
	}
	close(conn->cfd);
	free(conn);
}

static void accept_client_cb(void *userarg)
{
	server_state      *s = userarg;

	struct sockaddr_un peer_addr;
	socklen_t          peer_addr_size;
	int                cfd;
	client_connection *conn = NULL;

	assert(s);

	if ((cfd = accept(s->fd, (struct sockaddr *)(&peer_addr), &peer_addr_size)) < 0)
		log_warning("ipc_unix_listen< accept: %s >", strerror(errno));

	else if (!(conn = calloc(1, sizeof(client_connection))))
		log_warning("ipc_unix_listen< accept: memory error >");
	else {
		conn->ev.userarg = conn;
		conn->ev.read_cb = read_request_cb;
		conn->cfd = cfd;
		conn->s   = s;

		log_debug("ipc_unix_listen< schedule read for fd: %d >", cfd);
		(void) my_eventloop_schedule(&s->loop.base, cfd, -1, &conn->ev);
		return; /* Success */
	}
	if (conn)
		free(conn);
	if (cfd >= 0)
		close(cfd);
}

#ifdef HAVE_HTTP_SERVICE
typedef struct http_server_state {
	getdns_eventloop_event ev;
	int                    fd;
	getdns_context         *context;
	getdns_dict            *extensions;
	time_t                 last_changed;
	my_eventloop           *loop;
} http_server_state;

typedef struct http_client_state {
	getdns_eventloop_event ev;
	int                    fd;
	http_server_state      *s;
	char                   *content;
	char                   *header;
	char                   *host;
	char                    statusmsg[2048];
} http_client_state;

static void write_http_reply_cb(void *userarg)
{
	http_client_state *c = userarg;
	size_t             wsz;

	assert(c);

	my_eventloop_clear(&c->s->loop->base, &c->ev);
	c->ev.write_cb = NULL;

	if ((wsz = write(c->fd, c->header, strlen(c->header)) !=
	    strlen(c->header)))
		log_warning("http_listen< header not completely written >");

	else if ((wsz = write(c->fd, c->content, strlen(c->content)) !=
	    strlen(c->content)))
		log_warning("http_listen< content not completely written >");

	else if ((wsz = write(c->fd, "\r\n", strlen("\r\n")) !=
	    strlen("\r\n")))
		log_warning("http_listen< end not completely written >");

	close(c->fd);
	if (c->host)
		free(c->host);
	if (c->header)
		free(c->header);
	if (c->content)
		free(c->content);
	free(c);
}

static void http_response_cb(getdns_context *context,
	getdns_callback_type_t callback_type, getdns_dict *response,
	void *userarg, getdns_transaction_t t)
{
	http_client_state   *c = userarg;
	getdns_return_t      r;
	uint32_t             status;
	enum service_type    srvc = ERROR_PAGE;

	log_debug("http_listen< response for transaction %"PRIu64" >", t);

	if (!c) {
		log_critical("http_response_cb< no userarg: %"PRIu64" >", t);
		return;
	}
	if (callback_type != GETDNS_CALLBACK_COMPLETE) {
		log_warning("http_listen< callback type %d: %"PRIu64" >"
		           , callback_type, t);
		(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
		               , "callback type %d: %"PRIu64
			       , callback_type, t);

	} else if (!response) {
		log_warning("http_listen< NULL response>");
		(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
		               , "NULL response");

	} else if ((r = getdns_dict_get_int(response, "status", &status))) {
		log_warning("http_listen< could not get status>");
		(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
		               , "could not get status");

	} else if (status == GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS) {
                (void) snprintf( c->statusmsg, sizeof(c->statusmsg)
                               , "<h2>Could not securely resolve %s</h2><hr/>"
			         "<p>REASON: ALL_BOGUS_ANSWERS"
				 "<fieldset><legend>DNSSEC status</legend>"
				 "BOGUS</fieldset></p>", c->host);

	} else if (status == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS) {
                (void) snprintf( c->statusmsg, sizeof(c->statusmsg)
                               , "<h2>Could not securely resolve %s</h2><hr/>"
			         "<p>REASON: NO_SECURE_ANSWERS"
				 "<fieldset><legend>DNSSEC status</legend>"
				 "INSECURE</fieldset></p>", c->host);

	} else if ((r = getdns_dict_get_int(response, "/replies_tree/0/dnssec_status", &status))) {
		log_warning("http_listen< could not get dnssec_status>");
		(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
		               , "could not get status");

	} else if (status == GETDNS_DNSSEC_BOGUS) {
                (void) snprintf( c->statusmsg, sizeof(c->statusmsg)
                               , "<h2>Could not securely resolve %s</h2><hr/>"
			         "<p>REASON: Bogus answer"
				 "<fieldset><legend>DNSSEC status</legend>"
				 "BOGUS</fieldset></p>", c->host);
	} else {
		srvc = HOME_PAGE;
                (void) snprintf( c->statusmsg, sizeof(c->statusmsg)
                               , "<hr/><hr/><p>%s resolved to <h3>%s</h3></p>"
			       , c->host, "an address");
	}
	log_debug("http_listen< input from %d processed >", c->fd);
	load_page(srvc, &c->header, &c->content, c->statusmsg);
	if (c->content == NULL || c->header == NULL)
		log_warning("http_listen< Error reading from client connection... >");
	c->ev.write_cb = write_http_reply_cb;
	log_debug("http_listen< schedule write for fd: %d >", c->fd);
	(void) my_eventloop_schedule(&c->s->loop->base, c->fd, -1, &c->ev);

	if (response)
		getdns_dict_destroy(response);
}


static void read_http_request_cb(void *userarg)
{
	http_client_state   *c = userarg;
	enum service_type    srvc = HOME_PAGE;
	char                *line = NULL, line_buf[2048];
	FILE                *in = NULL;
	getdns_return_t      r;
	getdns_transaction_t transaction_id;

	assert(c);

	my_eventloop_clear(&c->s->loop->base, &c->ev);
	c->ev.read_cb = NULL;

	log_debug("http_listen< processing input from %d >", c->fd);
	/*
	 * Following logic loosly based on process_input() from services/http.c
	 */
	if (!(in = fdopen(dup(c->fd), "r"))) {
		log_warning("http_listen< could not open stream for fd: %d >", c->fd);
		(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
		               , "could not open stream for fd: %d", c->fd );

		srvc = ERROR_PAGE;

	} else while ((line = fgets(line_buf, sizeof(line_buf), in))) {
		if (strstr(line, "favicon"))
			srvc = FAVICON;
		else if (strncmp(line, "POST / HTTP/", 12) == 0)
			srvc = FORM_DATA;
		else if (strncmp(line, "Host: ", 6) != 0)
			continue;
		line[strcspn(line + 6, ":\n\r") + 6] = 0;
		if (!(c->host = strdup(line + 6))) {
			log_warning("http_listen< could not strdup: %s >", line + 6);
			(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
				       , "could not strdup: %s", line + 6);
			srvc = ERROR_PAGE;
			break;

		}
		if ((r = getdns_address(
		    c->s->context, c->host, c->s->extensions, c,
		    &transaction_id, http_response_cb))) {

			log_warning("http_listen< getdns_address: %d >", r);
			(void) snprintf( c->statusmsg, sizeof(c->statusmsg)
				       , "getdns_address: %d", r );
			srvc = ERROR_PAGE;
			break;
		}
		log_debug("http_listen< read: request for "
			  "%s scheduled: %"PRIu64">"
			 , c->host, transaction_id);

		fclose(in);
		/* Read remaining data */
		while (read(c->fd, line_buf, sizeof(line_buf)) == sizeof(line_buf))
			;
		return;
	}
	if (in)
		fclose(in);
	if (line) {
		/* Read remaining data */
		while (read(c->fd, line_buf, sizeof(line_buf)) == sizeof(line_buf))
			;
	}
	log_debug("http_listen< input from %d processed >", c->fd);
	load_page(srvc, &c->header, &c->content, c->statusmsg);
	if (c->content == NULL || c->header == NULL)
		log_warning("http_listen< Error reading from client connection... >");
	c->ev.write_cb = write_http_reply_cb;
	log_debug("http_listen< schedule write for fd: %d >", c->fd);
	(void) my_eventloop_schedule(&c->s->loop->base, c->fd, -1, &c->ev);
}

static void accept_http_client_cb(void *userarg)
{
	http_server_state *s = userarg;

	struct sockaddr_in peer_addr;
	socklen_t          peer_addr_size;
	int                cfd;
	http_client_state *c = NULL;
	int                flags;

	assert(s);

	if ((cfd = accept(s->fd, (struct sockaddr *)(&peer_addr), &peer_addr_size)) < 0)
		log_warning("http_listen< accept: %s >", strerror(errno));

	else if ((flags = fcntl(cfd, F_GETFL)) < 0)
		log_warning("http_listen< get flags %s >", strerror(errno));

	else if (fcntl(cfd, F_SETFL, flags | O_NONBLOCK) < 0)
		log_warning("http_listen< set flags %s >", strerror(errno));

	else if (!(c = calloc(1, sizeof(http_client_state))))
		log_warning("http_listen< accept: memory error >");
	else {
		c->ev.userarg = c;
		c->ev.read_cb = read_http_request_cb;
		c->fd         = cfd;
		c->s          = s;

		log_debug("http_listen< schedule read for fd: %d >", cfd);
		(void) my_eventloop_schedule(&s->loop->base, cfd, -1, &c->ev);
		return; /* Success */
	}
	if (c)
		free(c);
	if (cfd >= 0)
		close(cfd);
}

#endif

void ipc_unix_listen()
{
	static int          singleton = 0;
	static server_state s;
	getdns_return_t     r;
	struct sockaddr_un  server_addr;

	if (singleton++) {
		log_critical("ipc_unix_listen< only one listening daemon allowed >");
		exit(EXIT_FAILURE);
	}
	(void) memset(&s, 0, sizeof(s));

	if ((s.fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		log_critical("ipc_unix_listen< socket: %s >", strerror(errno));
		exit(EXIT_FAILURE);
	}
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, ADDRESS);

	if (connect(s.fd, (struct sockaddr *)(&server_addr),
	    sizeof(server_addr.sun_family) + sizeof(ADDRESS)) >= 0) {
		log_info("ipc_unix_listen< another listener already running >");
		/* Another server listening already */
		close(s.fd);
		return;
	}
	unlink(ADDRESS);
    
	if (bind(s.fd, (struct sockaddr *)(&server_addr),
	    sizeof(server_addr.sun_family) + sizeof(ADDRESS)) < 0)
		log_critical("ipc_unix_listen< bind: %s >", strerror(errno));
	
	else if (listen(s.fd, BACKLOG_SIZE) < 0)
		log_critical("ipc_unix_listen< listen: %s >", strerror(errno));

	else if (load_context(&s.context, &s.extensions, &s.last_changed), !s.context)
		log_critical("ipc_unix_listen< NULL CONTEXT >");

	else if ((r = getdns_context_set_eventloop(s.context, (my_eventloop_init(&s.loop)))))
		log_critical("ipc_unix_listen< setting eventloop to context: %d>", r);

	else {
#ifdef HAVE_HTTP_SERVICE
		static http_server_state h;
		int                      one = 1;
		struct sockaddr_in       http_addr;

		(void) memset(&h, 0, sizeof(h));
		h.context    =  s.context;
		h.extensions =  s.extensions;
		h.loop       = &s.loop;

		http_addr.sin_family = AF_INET;
		http_addr.sin_addr.s_addr = INADDR_ANY;
		http_addr.sin_port = htons(HTTP_UNRPRIV_PORT);
		
		if ((h.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			log_critical("http_listen< socket: %s >", strerror(errno));

		else if (setsockopt(h.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0)
			log_critical("http_listen< setsockopt: %s >", strerror(errno));

		else if (bind(h.fd, (struct sockaddr *) &http_addr, sizeof(http_addr)) < 0) {
			log_critical("http_listen< bind: %s >", strerror(errno));
			close(h.fd);

		} else if (listen(h.fd, BACKLOG_SIZE) < 0) {
			log_critical("http_listen< listen: %s >", strerror(errno));
			close(h.fd);

		} else {
			h.ev.userarg = &h;
			h.ev.read_cb = accept_http_client_cb;

			(void) my_eventloop_schedule(&h.loop->base, h.fd, -1, &h.ev);
		}
#endif
		s.ev.userarg = &s;
		s.ev.read_cb = accept_client_cb;

		(void) my_eventloop_schedule(&s.loop.base, s.fd, -1, &s.ev);
		my_eventloop_run(&s.loop.base);

		return; /* Success */
	}
	if (s.extensions)
		getdns_dict_destroy(s.extensions);
	if (s.context)
		getdns_context_destroy(s.context);
	if (s.fd >= 0)
		close(s.fd);

	exit(EXIT_FAILURE);
}

int ipc_unix_proxy_resolve(char* query, int type, int af, response_bundle **result)
{
	int sockfd, socklen;
    struct sockaddr_un server_addr;
    if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        log_critical("ipc_unix_proxy_resolve < socket(%s): %s >", ADDRESS, strerror(errno));
        return -1;
    }
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, ADDRESS);
    socklen = sizeof(server_addr.sun_family) + strlen(server_addr.sun_path);
    if(connect(sockfd, (struct sockaddr *)(&server_addr), socklen) < 0)
    {
    	int errnum = errno;
        log_info("ipc_unix_proxy_resolve< connect(%s): %s >", ADDRESS, strerror(errnum));
#ifdef DAEMON_ONLY_MODE
	return -1;
#else
        if(errnum == ECONNREFUSED || errnum == ENOENT)
        {
        	ipc_unix_start_daemon();
		usleep(1000);
        	log_info("ipc_unix_proxy_resolve< Retrying to connect to %s >", ADDRESS);
        	if(connect(sockfd, (struct sockaddr *)(&server_addr), socklen) < 0)
        	{
        		log_critical("ipc_unix_proxy_resolve< Retry failed: %s >", strerror(errno));
        		return -1;
        	}
        }else{
        	log_critical("ipc_unix_proxy_resolve< Exiting with error: %s : %d >", strerror(errno), errnum);
        	return -1;
        }
#endif
    }
    req_params request = {.reverse=type, .af=af};
    memset(request.query, 0, sizeof(request.query));
    memcpy(request.query, query, strlen(query));
    if(send(sockfd, &request, sizeof(req_params), 0) <= 0)
    {
    	log_warning("ipc_unix_proxy_resolve< send: %s >", strerror(errno));
        return -1;
    }
    char buf[MAXBUFSIZ];
    size_t len;
    if( (len = recv(sockfd, buf, MAXBUFSIZ, 0) ) <= 0)
    {
    	log_warning("ipc_unix_proxy_resolve< recv: %s >", strerror(errno));
        return -1;
    }
    *result = malloc(sizeof(response_bundle));
	if(*result == NULL)
	{
		log_critical("ipc_unix_proxy_resolve< MALLOC failed >");
		return -1;
	}
	memset(*result, 0, sizeof(response_bundle));
    memcpy(*result, buf, len);
    close(sockfd);
    return 0;
}

#ifdef HAVE_CONTEXT_PROXY
getdns_context_proxy ctx_proxy = &ipc_unix_proxy_resolve;
#endif

void ipc_unix_start_daemon()
{
	/*
	*New process will create a daemon process and exit.
	*/
	pid_t sessid /*Session ID (We will fork from then exit parent.)*/;
	pid_t ipc_pid = fork();
	/*Make sure fork succeeded*/
	if(ipc_pid < 0)
	{
		log_critical("ipc_unix_listen< Error forking. >");
		exit(EXIT_FAILURE);
	}
	/*Exit parent process*/
	if(ipc_pid > 0)
	{
		log_info("ipc_unix_listen< Entering daemon mode. >");
		exit(EXIT_SUCCESS);
	}
	/*
	*Now we are in the child process, daemon mode
	*Create new session ID and reset file mode mask, 
	*change to a safe working dir, and close out standard file descriptors.
	*/
	umask(0);
	sessid = setsid();
	if(sessid < 0)
	{
		log_critical("ipc_unix_listen< setsid() failed >");
		exit(EXIT_FAILURE);
	}
	if( (chdir("/")) < 0)
	{
		log_critical("ipc_unix_listen< chdir() failed >");
		exit(EXIT_FAILURE);
	}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/*IPC daemon starts....*/
	log_info("ipc_unix_start_daemon< starting IPC context proxy daemon >");
	ipc_unix_listen();
}
