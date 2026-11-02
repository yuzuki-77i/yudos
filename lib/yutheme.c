#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include "yutheme.h"
#include "yuwheel.h"

void log_print(const char *type, const char *fmt, ...){
    va_list ap;

    if(strcmp(type, "suc") == 0){printf(GREEN"[+]"RESET " "); }
    else if(strcmp(type, "err") == 0){printf(RED"[-]"RESET " "); }
    else if(strcmp(type, "warn") == 0){printf(YELLOW"[!]"RESET " "); }
    else if(strcmp(type, "info") == 0){printf(BLUE"[*]"RESET " "); }
    else if(strcmp(type, "spec") == 0){printf(PURPLE"[x]"RESET " "); }
    
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

int random_art(const char *size, const char *col){
    int n = strlen(size);
    if(n <= 0 || n > 16){ return -1; }
    char *size_result[16];
    for(int x = 0; x < n; x++){
        if(size[x] == 's'){size_result[x] = "small";}
        else if(size[x] == 'm'){size_result[x] = "medium";}
        else if(size[x] == 'b'){size_result[x] = "big";}
        else{printf("unknown size '%c'\n", size[x]); return -1; }
    }

    int count_art = 0;
    char size_path[1024];
    char path[2048];
    snprintf(size_path, sizeof(size_path), "%s/assets/ascii_arts/%s", locate(2), size_result[rand()%n]);
    DIR *d = opendir(size_path);
    if(!d){printf("%s[!]%s Cannot load ascii arts\n", YELLOW, RESET); return -1;}
    struct dirent *e;
    int idx = 0;
    while((e = readdir(d)) != NULL){
        if(e->d_name[0] == '.'){continue;}
        count_art ++;
    }
    rewinddir(d);
    if(count_art == 0){printf("%s[!]%s Cannot load ascii arts\n", YELLOW, RESET); closedir(d); return -1;}
    int pick = rand() % count_art;
    while((e = readdir(d)) != NULL){
        if(e->d_name[0] == '.'){continue;}
        if(idx == pick){
            snprintf(path, sizeof(path), "%s/%s", size_path, e->d_name);
            break;
            }
        idx++;
    }

    FILE *f = fopen(path, "r");
    if(!f){printf("%s[!]%s Cannot read random ascii art file\n", YELLOW, RESET); closedir(d); return -1;}
    int c;
    printf("%s", col);
    while((c = fgetc(f)) != EOF){putchar(c);}
    printf("%s", RESET);
    printf("\n");
    fclose(f);

    return 0;

}

void boom(const char *program_name, const char *version, const char *banner_color, const char *art_size, const char *art_color, const char *tipslib[], int n_tips){

    /* banner */
    FILE *f = NULL;
    char boom_path[1024];
    char line[4096];
    const char *project_root;

    if(!banner_color){ banner_color = ""; }

    project_root = locate(2);
    if(!project_root){ log_print("warn", "Cannot locate project root, banner skipped"); goto banner_done; }

    snprintf(boom_path, sizeof(boom_path), "%s/assets/boom.txt", project_root);

    f = fopen(boom_path, "r");
    if(!f){ log_print("warn", "Cannot open %s, banner skipped", boom_path); goto banner_done; }

    while(fgets(line, sizeof(line), f)){
        size_t len = strlen(line);
        while( len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r') ){ line[--len] = '\0'; }
        printf("%s%s%s\n", banner_color, line, RESET);
    }

    banner_done : if(f){ fclose(f); }

    /* art */
    random_art(art_size, art_color);

    /* tips */
    if(!n_tips){ return; }

    int valid[n_tips];
    int n_valid = 0;
    for(int i = 0; i < n_tips; i++){
        int len = (int)strlen(tipslib[i]);
        if(len <= 0 || len > 62){ continue; }
        valid[n_valid++]= i;
    }
    if(!n_valid){ return; }

    int t1 = rand() % n_valid;
    int t2 = rand() % n_valid;
    if(t1 == t2){t2 = (t2 + 1) % n_valid;}

    char tip_head[128];
    snprintf(tip_head, sizeof(tip_head), "%s %s", program_name, version);
    const char *tip_tail = "   --by yuzuki";
    int rest_width = 62 - (int)strlen(tip_head);
    if(rest_width < (int)strlen(tip_tail)){ rest_width = (int)strlen(tip_tail); }

    printf("\n");
    printf("         =[ %s%s%s%-*s ]\n", YELLOW, tip_head, RESET, rest_width, tip_tail);
    printf("  + -- --=[ %-62s ]\n", tipslib[valid[t1]]);
    printf("  + -- --=[ %-62s ]\n", tipslib[valid[t2]]);
    printf("\n");
}