


struct notify *notify_open(const char *, int *);

void notify_close(struct notify *);

int notify_pollfd(struct notify *);

int notify_add(struct notify *, const char *);