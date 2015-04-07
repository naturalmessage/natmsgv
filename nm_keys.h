// nm_keys.h
//
//#include "gcrypt.h"
//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
//  //#include <assert.h>
//  //#include <time.h>
//#include <ctype.h>


//#define MAX_ENTRY_LEN 500
//#define MAX_KEY_BUFF 10000
//#define MAX_CMDLINE_BUFF 500

//char save_name[MAX_ENTRY_LEN];
//char output_fname[MAX_ENTRY_LEN];


char *get_line (char *s, size_t n, FILE *f);
int read_sexp_file(FILE *fp, gcry_sexp_t *sexp_r, char *txt, 
  int ascii_only, int debug_lvl);
