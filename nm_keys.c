// nm_keys.c
// Purpose:
//   1) Define a few things that will be used in 
//      the Natural Message key creation, signing,
//      and verification programs.
//
// READ THIS FILE ABOUT S-EXPRESSIONS (DONT' CUT CORNERS): 
//        http://people.csail.mit.edu/rivest/Sexp.txt
//
/*
														LIBGCRYPT AND S-EXPRESSIONS

	The blocks of S-expressoin contain ASCII data or c- escapes and
	contain many ()() -- like LISP.

	* Note that the libgcrypt gcry_sexp_build() function
	  handles the encoding of binary data, so if you follow
    the directions for that function, it will import data for 
    you (e.g., you do not have to generate base64 or type || 
    to enclose base64).
	* Print an S-expression using gcry_sexp_sprint().
	* Use gcry_sexp_find_token() to extract a subset of an S-exp.

	Notes from: http://people.csail.mit.edu/rivest/sexp.html

	* Inside the S-expressions, base64 is delimited with pipes:
	    (e |NFGq/E3wh9f4rJIQVXhS|)
	* ASCII Hex can be delimited with ##.
	* A list object is delmited with ()?
	* Dates can be entered like this:
	    (not-before "1997-01-01_09:00:00").
	* Regular text and numbers can be entere like this:
	    (account "12345678") (* numeric range "1" "1000")
	* The 'transport' example on the mit link looks like base64 inside {}
	  See base64PrintWholeObject() in input.c on the MIT site for base64 object.
    and contains embedded EOL, which are ignored per 
    http://people.csail.mit.edu/rivest/Sexp.txt.

*/
//
//
// I had to create a link in Fedora 20 so that the program could find
// this existing libgcrypt library:
//   # cd /usr/lib64
//   # ln -s /usr/local/lib/libgcrypt.so.20 ./libgcrypt.so.20
//
// Compile this using the 'make' command execute from this directory.
//
// local file nm_keys.h

#include <stddef.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
//
#include "nm_keys.h"

char *get_line (char *str_ptr, size_t n, FILE *f)
{
	// I am using this to get input from the user and
	// avoid keeping EOL or other trailing whitespace.
	//
	// str_ptr is the location where the processed string will go.
	// n is the max number of chars to allow for the initial input,
	//   and that value would include any EOL.
  char *p = fgets (str_ptr, n, f);

  if (p != NULL) {
		// Remove all trailing whitespace.
    size_t last = strlen (str_ptr) - 1;
		while(isspace(str_ptr[last]))
			str_ptr[last--] = '\0';
  }
  return p;
}

int read_sexp_file(FILE *fp, gcry_sexp_t *sexp_r, char *txt, 
  int ascii_only, int debug_lvl){
	// Read an ASCII text file that looks like an s-expression
	// and convert it to an internal-format s-expression 
	// with an additional copy of the original text buffer.
	//
	//fp:
	//  The input file handle (the caller must close this).
	//
	//r_sexp:
	//  The resulting internal-format s-expression.
	//
	//txt:
	//  The resulting text representation of the s-expression.
	//
	gcry_error_t err;
	int idx;
	int ch;
	//int txt_len;

	idx = 0;
	if(ascii_only){
		while ((ch=fgetc(fp)) != EOF){  /* read/print characters including newline */
			if(isascii(ch)){
				*(txt + idx++) = ch;
			}else{
				if (debug_lvl > 0)
					fprintf(stderr, "Ignoring non-ASCII character: %c", ch);
			}
		}
	}else{
		while ((ch=fgetc(fp)) != EOF){  /* read characters including newline */
			*(txt + idx++) = ch;
 		}
	}
	
	//if !(feof(fp)) 
	if (ferror(fp))
	{
		fprintf(stderr, "Error. Could not read the input file.");
		fprintf(stderr,"fgetc() failed in file %s at line # %d\n", __FILE__,__LINE__);
		//perror("fgetc() failed in file %s at line # %d\n", __FILE__,__LINE__);
		exit(EXIT_FAILURE);
	}
	//fclose(fp);
	if(debug_lvl > 3){
		fprintf(stderr, "In read_sexp_file I read %d chars.\n", idx);
		fprintf(stderr, "In read_sexp_file I read this: %s\n", txt);
	}

	//          CONVERT STRING TO INTERNAL S-EXP
	err = gcry_sexp_new(sexp_r, txt, 0, 1);
	if (err){
		fprintf (stderr, "Error. In read_sexp_file, could not create the new s-exp : %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 999;
	}else{
		if(debug_lvl > 5){
			fprintf(stderr, "In read_sexp_file, the input s-expression was converted to internal s-expression format.\n");
		}
	}

	if (debug_lvl > 5){
		fprintf(stderr, "In read_sexp_file, the internal s-exp looks like this:\n");
		gcry_sexp_dump(*(sexp_r));
	}	

	return 0;
}
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
