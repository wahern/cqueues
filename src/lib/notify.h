

#define NOTIFY_CREATE 0x01
#define NOTIFY_DELETE 0x02
#define NOTIFY_ATTRIB 0x04
#define NOTIFY_MODIFY 0x08
#define NOTIFY_REVOKE 0x10


struct notify_options {
	_Bool foo;
}; /* struct notify_options */

#define notify_opts(...) (&(struct notify_options){ 0, __VA_ARGS__ })


struct notify *notify_open(const char *, const struct notify_options *, int *);

void notify_close(struct notify *);

int notify_pollfd(struct notify *);

int notify_add(struct notify *, const char *);

