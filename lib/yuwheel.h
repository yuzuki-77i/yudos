#pragma once
#include <stddef.h>

int systemf( const char *fmt, ... );
void super_fucking_srand(void);
const char *locate(int depth);
const char *timestamp();
const char *base_name(const char *path);
char *trim(char *s);