#ifndef WINLOAD_H
#define WINLOAD_H

void mod_init();
struct mod *mod_load(const char *filename, int is_dll);
void mod_free(struct mod *mod);
unsigned mod_find(struct mod *mod, const char *name);
unsigned modfun_call(unsigned fun, int argc, ...);
unsigned mod_get_entry(struct mod *mod);

#endif
