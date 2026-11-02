#pragma once

#define GREEN "\033[32m"
#define RED "\033[31m"
#define BLUE "\033[34m"
#define YELLOW "\033[33m"
#define PURPLE "\033[38;2;128;0;255m"
#define RESET "\033[0m"

__attribute__( (format(printf,2,3)) )
void log_print(const char *type, const char *fmt, ...);
int random_art(const char *size, const char *col);
void boom(const char *program_name, const char *version, const char *banner_color, const char *art_size, const char *art_color, const char *tipslib[], int n_tips);
