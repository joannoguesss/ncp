/*
 * ncp - network copy: download a URL to a file.
 *
 * Supports http and https, redirects, chunked transfers,
 * resuming partial downloads (-c) and a quiet mode (-q).
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define VERSION "1.0"
#ifndef CA_BUNDLE
#define CA_BUNDLE "/etc/pki/tls/certs/ca-bundle.crt" /* created by make-ca */
#endif
#define MAX_REDIRECTS 10
#define BUF_SIZE 16384
#define BAR_WIDTH 30

struct url {
	int tls;
	char host[256];
	char port[8];
	char path[4096];
};

struct conn {
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
	char buf[BUF_SIZE];
	size_t pos, len;
};

struct response {
	int status;
	long long length; /* -1 if unknown */
	int chunked;
	char location[4096];
};

struct progress {
	const char *name;
	long long done, total, offset;
	double started, last;
};

static int quiet;

static void die(const char *fmt, ...)
{
	va_list ap;

	fputs("ncp: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

/* Split "https://host:port/path?query" into its parts. */
static void parse_url(const char *s, struct url *u)
{
	const char *p;
	size_t n;

	if (strncmp(s, "https://", 8) == 0) {
		u->tls = 1;
		p = s + 8;
		strcpy(u->port, "443");
	} else if (strncmp(s, "http://", 7) == 0) {
		u->tls = 0;
		p = s + 7;
		strcpy(u->port, "80");
	} else {
		die("unsupported URL: %s", s);
	}

	n = strcspn(p, ":/?#");
	if (n == 0 || n >= sizeof u->host)
		die("bad host in URL: %s", s);
	memcpy(u->host, p, n);
	u->host[n] = '\0';
	p += n;

	if (*p == ':') {
		p++;
		n = strcspn(p, "/?#");
		if (n == 0 || n >= sizeof u->port)
			die("bad port in URL: %s", s);
		memcpy(u->port, p, n);
		u->port[n] = '\0';
		p += n;
	}

	n = strcspn(p, "#");
	if (n + 2 > sizeof u->path)
		die("URL too long");
	if (*p != '/')
		snprintf(u->path, sizeof u->path, "/%.*s", (int)n, p);
	else
		snprintf(u->path, sizeof u->path, "%.*s", (int)n, p);
}

/* Turn a Location header into a full URL, relative to the current one. */
static void resolve(const struct url *base, const char *loc, char *out, size_t n)
{
	const char *scheme = base->tls ? "https" : "http";
	char dir[4096];
	char *q;

	if (strstr(loc, "://")) {
		snprintf(out, n, "%s", loc);
	} else if (loc[0] == '/' && loc[1] == '/') {
		snprintf(out, n, "%s:%s", scheme, loc);
	} else if (loc[0] == '/') {
		snprintf(out, n, "%s://%s:%s%s", scheme, base->host, base->port, loc);
	} else {
		snprintf(dir, sizeof dir, "%s", base->path);
		if ((q = strchr(dir, '?')))
			*q = '\0';
		strrchr(dir, '/')[1] = '\0';
		snprintf(out, n, "%s://%s:%s%s%s", scheme, base->host, base->port, dir, loc);
	}
}

/* Last part of the path, without the query string. */
static void default_name(const char *path, char *out, size_t n)
{
	const char *end = path + strcspn(path, "?");
	const char *start = end;

	while (start > path && start[-1] != '/')
		start--;
	if (start == end)
		snprintf(out, n, "index.html");
	else
		snprintf(out, n, "%.*s", (int)(end - start), start);
}

static void conn_open(struct conn *c, const struct url *u)
{
	static int warned;
	struct addrinfo hints, *res, *ai;
	int err;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(u->host, u->port, &hints, &res)))
		die("%s: %s", u->host, gai_strerror(err));

	c->fd = -1;
	for (ai = res; ai; ai = ai->ai_next) {
		c->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (c->fd < 0)
			continue;
		if (connect(c->fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(c->fd);
		c->fd = -1;
	}
	freeaddrinfo(res);
	if (c->fd < 0)
		die("%s: cannot connect", u->host);

	c->pos = c->len = 0;
	c->ctx = NULL;
	c->ssl = NULL;
	if (!u->tls)
		return;

	if (!(c->ctx = SSL_CTX_new(TLS_client_method())))
		die("cannot create TLS context");
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
	SSL_CTX_set_options(c->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
	if (access(CA_BUNDLE, R_OK) == 0) {
		if (!SSL_CTX_load_verify_locations(c->ctx, CA_BUNDLE, NULL))
			die("cannot load %s", CA_BUNDLE);
		SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	} else {
		if (!warned)
			fprintf(stderr, "ncp: warning: %s not found, not verifying HTTPS\n", CA_BUNDLE);
		warned = 1;
		SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
	}

	if (!(c->ssl = SSL_new(c->ctx)))
		die("cannot create TLS session");
	SSL_set_fd(c->ssl, c->fd);
	SSL_set_tlsext_host_name(c->ssl, u->host); /* SNI */
	SSL_set1_host(c->ssl, u->host);            /* check the certificate name */
	if (SSL_connect(c->ssl) != 1) {
		ERR_print_errors_fp(stderr);
		die("%s: TLS handshake failed", u->host);
	}
}

static void conn_close(struct conn *c)
{
	if (c->ssl)
		SSL_free(c->ssl);
	if (c->ctx)
		SSL_CTX_free(c->ctx);
	close(c->fd);
}

static void conn_write(struct conn *c, const char *s, size_t n)
{
	ssize_t w;

	while (n > 0) {
		w = c->ssl ? SSL_write(c->ssl, s, (int)n) : write(c->fd, s, n);
		if (w <= 0)
			die("write to server failed");
		s += w;
		n -= (size_t)w;
	}
}

/* Refill the read buffer. Returns 0 at end of stream. */
static size_t conn_fill(struct conn *c)
{
	int r, e;
	ssize_t n;

	if (c->ssl) {
		r = SSL_read(c->ssl, c->buf, sizeof c->buf);
		if (r <= 0) {
			e = SSL_get_error(c->ssl, r);
			if (e != SSL_ERROR_ZERO_RETURN)
				die("TLS read failed");
			r = 0;
		}
		n = r;
	} else {
		n = read(c->fd, c->buf, sizeof c->buf);
		if (n < 0)
			die("read failed: %s", strerror(errno));
	}
	c->pos = 0;
	c->len = (size_t)n;
	return c->len;
}

static size_t conn_read(struct conn *c, char *dst, size_t max)
{
	size_t n;

	if (c->pos == c->len && conn_fill(c) == 0)
		return 0;
	n = c->len - c->pos;
	if (n > max)
		n = max;
	memcpy(dst, c->buf + c->pos, n);
	c->pos += n;
	return n;
}

/* Read one line without its CRLF. Returns -1 at end of stream. */
static int conn_getline(struct conn *c, char *line, size_t max)
{
	size_t i = 0;
	char ch;

	for (;;) {
		if (c->pos == c->len && conn_fill(c) == 0)
			return -1;
		ch = c->buf[c->pos++];
		if (ch == '\n')
			break;
		if (i + 1 < max)
			line[i++] = ch;
	}
	if (i > 0 && line[i - 1] == '\r')
		i--;
	line[i] = '\0';
	return (int)i;
}

static void send_request(struct conn *c, const struct url *u, long long offset)
{
	char req[8192];
	int def = strcmp(u->port, u->tls ? "443" : "80") == 0;
	size_t n;

	n = (size_t)snprintf(req, sizeof req,
		"GET %s HTTP/1.1\r\n"
		"Host: %s%s%s\r\n"
		"User-Agent: ncp/" VERSION "\r\n"
		"Accept: */*\r\n"
		"Connection: close\r\n",
		u->path, u->host, def ? "" : ":", def ? "" : u->port);
	if (offset > 0 && n < sizeof req)
		n += (size_t)snprintf(req + n, sizeof req - n, "Range: bytes=%lld-\r\n", offset);
	if (n < sizeof req)
		n += (size_t)snprintf(req + n, sizeof req - n, "\r\n");
	if (n >= sizeof req)
		die("request too long");
	conn_write(c, req, n);
}

static void read_headers(struct conn *c, struct response *r)
{
	char line[8192];
	char *v;

	if (conn_getline(c, line, sizeof line) < 0)
		die("connection closed before response");
	if (sscanf(line, "HTTP/%*d.%*d %d", &r->status) != 1)
		die("bad response: %s", line);

	r->length = -1;
	r->chunked = 0;
	r->location[0] = '\0';
	while (conn_getline(c, line, sizeof line) > 0) {
		if (!(v = strchr(line, ':')))
			continue;
		*v++ = '\0';
		while (*v == ' ' || *v == '\t')
			v++;
		if (strcasecmp(line, "Content-Length") == 0)
			r->length = strtoll(v, NULL, 10);
		else if (strcasecmp(line, "Transfer-Encoding") == 0)
			r->chunked = strcasecmp(v, "chunked") == 0;
		else if (strcasecmp(line, "Location") == 0)
			snprintf(r->location, sizeof r->location, "%s", v);
	}
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void human(double b, char *out, size_t n)
{
	const char *unit[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	int i = 0;

	while (b >= 1024 && i < 4) {
		b /= 1024;
		i++;
	}
	snprintf(out, n, i ? "%.1f %s" : "%.0f %s", b, unit[i]);
}

/* Draw the progress line, at most ten times per second. */
static void show(struct progress *p, int final)
{
	char bar[BAR_WIDTH + 1], got[32], rate[32];
	double t = now(), elapsed;
	int fill;

	if (quiet || !isatty(2))
		return;
	if (!final && t - p->last < 0.1)
		return;
	p->last = t;

	elapsed = t - p->started;
	human((double)p->done, got, sizeof got);
	human(elapsed > 0 ? (double)(p->done - p->offset) / elapsed : 0, rate, sizeof rate);

	if (p->total > 0) {
		fill = (int)(p->done * BAR_WIDTH / p->total);
		memset(bar, '#', (size_t)fill);
		memset(bar + fill, '.', (size_t)(BAR_WIDTH - fill));
		bar[BAR_WIDTH] = '\0';
		fprintf(stderr, "\r%s %3lld%% [%s] %s %s/s\033[K",
			p->name, p->done * 100 / p->total, bar, got, rate);
	} else {
		fprintf(stderr, "\r%s %s %s/s\033[K", p->name, got, rate);
	}
	if (final)
		fputc('\n', stderr);
}

static void write_out(FILE *f, const char *b, size_t n, struct progress *p)
{
	if (fwrite(b, 1, n, f) != n)
		die("%s: %s", p->name, strerror(errno));
	p->done += (long long)n;
	show(p, 0);
}

static void copy_n(struct conn *c, FILE *f, long long n, struct progress *p)
{
	char buf[BUF_SIZE];
	size_t got;

	while (n > 0) {
		got = conn_read(c, buf, n < BUF_SIZE ? (size_t)n : BUF_SIZE);
		if (got == 0)
			die("connection closed early, run again with -c to resume");
		write_out(f, buf, got, p);
		n -= (long long)got;
	}
}

static void copy_body(struct conn *c, const struct response *r, FILE *f, struct progress *p)
{
	char buf[BUF_SIZE], line[64];
	long long size;
	size_t got;

	if (r->chunked) {
		/* each chunk: size in hex, CRLF, data, CRLF; size 0 ends it */
		for (;;) {
			if (conn_getline(c, line, sizeof line) < 0)
				die("connection closed early, run again with -c to resume");
			if ((size = strtoll(line, NULL, 16)) == 0)
				break;
			copy_n(c, f, size, p);
			conn_getline(c, line, sizeof line);
		}
	} else if (r->length >= 0) {
		copy_n(c, f, r->length, p);
	} else {
		while ((got = conn_read(c, buf, sizeof buf)) > 0)
			write_out(f, buf, got, p);
	}
}

static void usage(void)
{
	fputs("usage: ncp [-cq] [-o file] url\n", stderr);
	exit(1);
}

int main(int argc, char **argv)
{
	char url[8192], next[8192], name[1024];
	const char *out = NULL;
	long long offset = 0;
	int resume = 0, opt, hops;
	struct response r;
	struct progress p;
	struct conn c;
	struct stat st;
	struct url u;
	FILE *f;

	while ((opt = getopt(argc, argv, "cqo:")) != -1) {
		switch (opt) {
		case 'c': resume = 1; break;
		case 'q': quiet = 1; break;
		case 'o': out = optarg; break;
		default: usage();
		}
	}
	if (optind != argc - 1)
		usage();

	signal(SIGPIPE, SIG_IGN);
	snprintf(url, sizeof url, "%s", argv[optind]);
	parse_url(url, &u);

	if (out)
		snprintf(name, sizeof name, "%s", out);
	else
		default_name(u.path, name, sizeof name);
	if (resume && stat(name, &st) == 0)
		offset = st.st_size;

	for (hops = 0;; hops++) {
		if (hops > MAX_REDIRECTS)
			die("too many redirects");

		conn_open(&c, &u);
		send_request(&c, &u, offset);
		read_headers(&c, &r);

		if (r.status >= 300 && r.status < 400 && r.location[0]) {
			conn_close(&c);
			resolve(&u, r.location, next, sizeof next);
			snprintf(url, sizeof url, "%s", next);
			parse_url(url, &u);
			continue;
		}
		break;
	}

	if (r.status == 416 && offset > 0) {
		if (!quiet)
			fprintf(stderr, "%s: already complete\n", name);
		conn_close(&c);
		return 0;
	}
	if (r.status != 200 && r.status != 206)
		die("%s: server replied %d", url, r.status);
	if (r.status == 200)
		offset = 0; /* server ignored the range, start over */

	if (!(f = fopen(name, offset ? "ab" : "wb")))
		die("%s: %s", name, strerror(errno));

	p.name = name;
	p.done = p.offset = offset;
	p.total = r.length >= 0 ? offset + r.length : -1;
	p.started = now();
	p.last = 0;

	copy_body(&c, &r, f, &p);
	show(&p, 1);

	if (fclose(f) != 0)
		die("%s: %s", name, strerror(errno));
	conn_close(&c);
	return 0;
}
