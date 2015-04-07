// nm_sign.c
/*
    Copyright 2014 Robert E. Hoot. Pahrump, NV, USA.

    This program is distributed under the terms of the GNU General Public License.

    This file is part of the Natural Message Server.

    The Natural Message Server Suite is free software: you can 
    redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Natural Message Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with the Natural Message Server.  If not, see <http://www.gnu.org/licenses/>.
*/
// Purpose:
//   1) Read a a data file (via --in) and sign it with
//      an NaturalMessage-format private key, thereby
//      prodicing a detached signature file (--signature),
//      which, if not specified, will be the name of hte input file
//      with a suffix of ".sig".
//
// Notes:
//     READ THIS FILE ABOUT S-EXPRESSIONS (DONT' CUT CORNERS): 
//        http://people.csail.mit.edu/rivest/Sexp.txt
//

//
#include <stddef.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Local header (for read_sexp_file)
// I leave this file in the local directory.
#include "nm_keys.h"

#include <time.h>
#include <getopt.h>

// If you change these values, you might need to
// adjust the secure memory allocation: SECMEM
#define MAX_ENTRY_LEN 500
#define MAX_KEY_BUFF 3000

#define debug_lvl 0
int verbose_flag;


//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int usage(){
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "nm_sign --in <infile> --signature <output_file> --key <private_key>\n");
	return 99;
}
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int main (int argc, char **argv) {
	// Define some stuff for verification of sig:
	gcry_error_t err;
	size_t err_offset;

	gcry_sexp_t sexp_nm_key;
	gcry_sexp_t sexp_prv_key;
	gcry_sexp_t sexp_input_data;
	gcry_sexp_t sexp_signature;
	int rslt;

	FILE *fp;
	int idx;
	char ch;

	
	/*
	----------------------------------------------------------------------
															LIBGCRYPT INITIALIZATION
	----------------------------------------------------------------------
	*/
	/* 
		 Version check should be the very first call because it
		 makes sure that important subsystems are initialized.
	*/
	char *v_ptr;
	v_ptr = gcry_check_version (GCRYPT_VERSION);
	// printf("  version is %s\n", v_ptr);

	if (strncmp(v_ptr, "1.6", 3))
	{
		fprintf(stderr, "libgcrypt version mismatch\n");
		exit (2);
	}

	/*
		We don’t want to see any warnings, e.g. because we have not yet
		parsed program options which might be used to suppress such
		warnings. 
	*/
	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	/*
	 .. If required, other initialization goes here. Note that the
	 process might still be running with increased privileges and that
	 the secure memory has not been initialized. 
	*/

	/*
		Allocate a pool of 25k secure memory. This make the secure memory
		available and also drops privileges where needed. 
	*/

  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL); //put random nbrs in secmem
  gcry_control (GCRYCTL_SET_VERBOSITY, 0);
	// I get an error saying that secmem was already initialized.
	// The default secmem size in Dec 2014 was 32768
	gcry_control (GCRYCTL_INIT_SECMEM, 25600, 0);
	/* 
		It is now okay to let Libgcrypt complain when there was/is
		a problem with the secure memory. 
	*/
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
	/* 
	 ... If required, other initialization goes here.
	*/

	/* Tell Libgcrypt that initialization has completed. */
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	/*
	----------------------------------------------------------------------
													END LIBGCRYPT INITIALIZATION
	----------------------------------------------------------------------
	*/

	// Double check that the initialization is done.
	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
	{
		fprintf(stderr, "libgcrypt has not been initialized\n");
		abort ();
	}


	// allocate things that use libgcrypt secure memeory

	char *nm_key_txt     = gcry_malloc_secure(MAX_KEY_BUFF);
	char *input_data_txt = gcry_malloc_secure(MAX_KEY_BUFF);
	char *input_fname    = gcry_malloc_secure(MAX_ENTRY_LEN);
	char *sig_txt        = gcry_malloc_secure(MAX_KEY_BUFF);
	char *input_prv_key_fname = gcry_malloc_secure(MAX_KEY_BUFF);
	char *output_fname   = gcry_malloc_secure(MAX_ENTRY_LEN);
	output_fname[0] = 0x00; // double safe initialization
	/*
		"To use a cipher algorithm, you must first allocate an
		according handle. This is to be done using the open 
		function:" (libgcrypt manual 1.6, p. 29).
		gcry_error_t gcry_cipher_open
	*/

	/*
	*/
	//------------------------------------------------------------
	/*----------------------------------------------------------------------
												 Process Command-Line Arguments
	----------------------------------------------------------------------
	*/

	int opt_code; //encoded value from command-line args

	while (1){
		// The format of the struct is defined by getopt_long:
		// 'const char *name'
		// 'int has_arg' can be one of three things: 
		//               'no_argument', 'required_argument' or 'optional_argument'.
		// 'int *flag'
		// 'int val'    if flag is 0, the value of the option,
		//              else val is the value to put in the flag variable.

		static struct option long_options[] = {
					/* These options set a flag. */
					{"verbose", no_argument,       &verbose_flag, 1},
					{"brief",   no_argument,       &verbose_flag, 0},
							 {"in",    required_argument,       0, 'i'},
							 {"signature",  required_argument,       0, 's'},
							 {"key",        required_argument, 0, 'k'},
							 {"help",        no_argument, 0, '?'},
							 {0, 0, 0, 0}
		};
		/* 'getopt_long' stores the option index here. */
		int option_index = 0;
		opt_code = getopt_long (argc, argv, "i:k:s:",
										 long_options, &option_index);

		/* Detect the end of the options. */
		if (opt_code == -1)
			break;

		switch (opt_code){
			case 0:
				/* If this option set a flag, do nothing else now. */
				if (long_options[option_index].flag != 0)
					break;
				//printf("set verbosity here??\n");
				//printf ("(case is 0) option %s", long_options[option_index].name);
				//if (optarg)
				//	printf (" with arg %s", optarg);
				//printf ("\n");
				break;

			case 'h':
				// help
				usage();
				break;

			case 'i':
				// input file
				strncpy(input_fname, optarg, MAX_ENTRY_LEN - 1);
				break;

			case 'k':
				// private key filename
				strncpy(input_prv_key_fname, optarg, MAX_ENTRY_LEN - 1);
				break;

			case 's':
				// output signature file name
				strncpy(output_fname, optarg, MAX_ENTRY_LEN - 1);
				break;

			case '?':
				/* 'getopt_long' already printed an error message. */
				usage();
				return 738;
				break;

			default:
				abort ();
		}
	} //end while-loop

	if (verbose_flag)
		fprintf(stderr, "verbose flag is set");

	/* Print any remaining command line arguments (not options). */
	if (optind < argc){
		fprintf (stderr, "Error.  Unexpected option: ");
		while (optind < argc)
			fprintf (stderr, "%s ", argv[optind++]);
		putchar ('\n');
		return 290;
	}


	if (input_fname[0] == 0x00){
		fprintf (stderr, "Error. Input filename is missing.\n");
		usage();
		return 321;
	}

	if (input_prv_key_fname[0] == 0x00){
		fprintf (stderr, "Error. Input private key filename is missing.\n");
		usage();
		return 322;
	}

	if (output_fname[0] == 0x00){
		strcpy(output_fname, input_fname);
		strcat(output_fname, ".sig");
	}

	//------------------------------------------------------------
	//------------------------------------------------------------
	//   IMPORT THE FILE TO SIGN AND MAKE IT AN S-EXP
	//fp = stdin;
	fp = fopen(input_fname, "rb");
	if(!fp){
		fprintf(stderr, "Error. Failed open the input data file.");
		return(438);
	}
	////read_sexp_file(fp, &sexp_input_data, input_data_txt, 1);
	idx = 0;
	while (((ch=fgetc(fp)) != EOF) && (idx < MAX_KEY_BUFF)){  /* read/print characters including newline */
		*(input_data_txt + idx++) = ch;
	}
	fclose(fp);
	if (debug_lvl > 2){
		fprintf(stderr, "the input data is: %s\n", input_data_txt);
	}
	//   CONSTRUCT AN S-EXPRESSION FOR THE DATA
	err = gcry_sexp_build(&sexp_input_data, &err_offset, "(data (flags raw) (hash sha384 %s))", input_data_txt);
	if(err){
		fprintf (stderr, "Error. formatting the input data/nonce: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 902;
	}
	if (debug_lvl >2){
		fprintf(stderr, "Here is the dump of the data/nonce only:\n");
		gcry_sexp_dump(sexp_input_data);
	}
	
	//err = gcry_sexp_build("(data (value |%s|))",
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//  Read the NaturalMessage private key
	//fp = fopen("inputfile.key", "r");
	fp = fopen(input_prv_key_fname, "r");
	if(!fp){
		fprintf(stderr, "Error. Failed open the input private key file.");
		return(443);
	}
	rslt = read_sexp_file(fp, &sexp_nm_key, nm_key_txt, 0, debug_lvl );
	if(rslt){
		fprintf(stderr, "Error. Failed to import a valid private key from the input private key file.");
		return(444);
	}
	if (debug_lvl >2 ){
		fprintf(stderr, "Here is a dump of the s-exp for the imported full prv key:\n");
		gcry_sexp_dump(sexp_nm_key);
	}
	//  Extract the libgcrypt private key from the NaturalMessage key.
	sexp_prv_key = gcry_sexp_find_token(sexp_nm_key, "private-key", 0);
	if(!sexp_prv_key){
		fprintf (stderr, "Error. Could not get the private-key from the input s-expression.\n");
		return 901;
	}

	if (debug_lvl >2){
		fprintf(stderr, "Here is the dump of the private key only:\n");
		gcry_sexp_dump(sexp_prv_key);
	}

	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------

	//------------------------------------------------------------
	//------------------------------------------------------------
	//     SIGN THE FILE
	//
	
	err = gcry_pk_sign(&sexp_signature, sexp_input_data, sexp_prv_key);
	if(err){
		// If you get this error, it means you don't have the right
		// version: "/Invalid public key algorithm"
		fprintf (stderr, "Error. Could not sign the data. %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		fprintf(stderr, "Tip: You need to use a PRIVATE SIGN-KEY (not an Enc encryption key).\n");
		return 903;
	}
	
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//   Export the text of the signature
	gcry_sexp_sprint(sexp_signature, GCRYSEXP_FMT_ADVANCED, sig_txt, MAX_KEY_BUFF);
	if (debug_lvl > 3){
		fprintf(stderr, "- - - - - - - - -- - - -  -   ---\n");
		fprintf(stderr, "The Signature:\n");
		fprintf(stderr, "%s\n", sig_txt);
		fprintf(stderr, "- - - - - - - - -- - - -  -   ---\n");
	}

	fp = fopen(output_fname, "w");
	if(!fp){
		fprintf(stderr, "Error. Failed open the output file.");
		return(439);
	}
	fprintf(fp, "%s", sig_txt);
	fclose(fp);
	//------------------------------------------------------------
	//------------------------------------------------------------
	//free(savename);
	gcry_free(output_fname);
	gcry_free(nm_key_txt);
	gcry_free(input_data_txt);
	gcry_free(input_fname);
	gcry_free(input_prv_key_fname);
	gcry_free(sig_txt);

	gcry_sexp_release(sexp_nm_key);
	gcry_sexp_release(sexp_prv_key);
	gcry_sexp_release(sexp_input_data);
	gcry_sexp_release(sexp_signature);
	return 0;
}
