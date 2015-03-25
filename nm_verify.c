// nm_verify.c
// Purpose:
//   1) Read a detached signature in NaturalMessage-format 
//      and a regular data file and use a public key
//      in NM format to verify the signature.
//
//     READ THIS FILE ABOUT S-EXPRESSIONS (DONT' CUT CORNERS): 
//        http://people.csail.mit.edu/rivest/Sexp.txt
//
//
//
//#include <gcrypt.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
//#include <assert.h>
//#include <time.h>
//#include <ctype.h>
//
// Local header:
#include "nm_keys.h"
#include <getopt.h>
#define MAX_ENTRY_LEN 500
#define MAX_KEY_BUFF 3000
#define MAX_CMDLINE_BUFF 500
#define debug_lvl 0

//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int verbose_flag;
int usage(){
	printf("Usage: nm_verify --in <orig_data> --signature <sigfile.sig> --key <public.key>\n");
	return 0;
}
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int main (int argc, char *argv[]) {
	// Define some stuff for verication of sig:
	gcry_error_t err;
	size_t err_offset;

	char *input_fname        = gcry_malloc_secure(MAX_CMDLINE_BUFF);
	char *input_sig_fname    = gcry_malloc_secure(MAX_CMDLINE_BUFF);
	char *input_pub_key_fname= gcry_malloc_secure(MAX_CMDLINE_BUFF);
	//char *input_data_txt     = gcry_malloc_secure(MAX_KEY_BUFF);
	char *input_sig_txt      = gcry_malloc_secure(MAX_KEY_BUFF);
	char *nm_key_txt         = gcry_malloc_secure(MAX_KEY_BUFF);
	gcry_sexp_t sexp_nm_key; //, sexp_nm_offline_key, sexp_offline_pub_key;
	gcry_sexp_t sexp_pub_key;
	gcry_sexp_t sexp_input_data;
	gcry_sexp_t sexp_signature;

	int err_int;

	FILE *fp;

	/*
	----------------------------------------------------------------------
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
				printf("set verbosity here??\n");
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
				strncpy(input_pub_key_fname, optarg, MAX_ENTRY_LEN - 1);
				break;

			case 's':
				// output signature file name
				strncpy(input_sig_fname, optarg, MAX_ENTRY_LEN - 1);
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
		puts ("verbose flag is set");

	/* Print any remaining command line arguments (not options). */
	if (optind < argc){
		printf ("Error.  Unexpected option: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		putchar ('\n');
		return 290;
	}


	if (input_fname[0] == 0x00){
		fprintf (stderr, "Error. Input filename is missing.\n");
		usage();
		return 321;
	}

	if (input_pub_key_fname[0] == 0x00){
		fprintf (stderr, "Error. Input public key filename is missing.\n");
		usage();
		return 322;
	}

	if (input_sig_fname[0] == 0x00){
		fprintf (stderr, "Error. Input signature filename is missing.\n");
		usage();
		return 327;
	}

	/*
	----------------------------------------------------------------------
													LIBGCRYPT INITIALIZATION
                (mostly from libgcrypt 1.6.2 manual p. 5-6)
	----------------------------------------------------------------------
	*/
	/* 
		 Version check should be the very first call because it
		 makes sure that important subsystems are initialized.
	*/
	if (!gcry_check_version (GCRYPT_VERSION))
	{
		fputs ("libgcrypt version mismatch\n", stderr);
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

	//put random nbrs in secmem
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL); //run immediately after check_ver
	/*
		Allocate a pool of 16k secure memory. This make the secure memory
		available and also drops privileges where needed. 
	*/
  gcry_control (GCRYCTL_SET_VERBOSITY, 0);
	printf("running secmem now...\n");
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	printf("finished running secmem ...\n");
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
		fputs ("libgcrypt has not been initialized\n", stderr);
		abort ();
	}


	/*
		"To use a cipher algorithm, you must first allocate an
		according handle. This is to be done using the open 
		function:" (libgcrypt manual 1.6, p. 29).
		gcry_error_t gcry_cipher_open
	*/

	/*
	*/
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//  Read the NaturalMessage public key
	fp = fopen(input_pub_key_fname, "r");
	if(!fp){
		perror("Error. Failed open the input public key file.");
		return(438);
	}
	err_int = read_sexp_file(fp, &sexp_nm_key, nm_key_txt, 0, debug_lvl);
	if(err_int){
		printf("Could not get the public key into an sexp.\n");
		exit(0);
	}
	
	fclose(fp);
	if (debug_lvl >2 ){
		printf("Here is a dump of the s-exp for the imported full PUBLIC key:\n");
		gcry_sexp_dump(sexp_nm_key);
	}
	//  Extract the libgcrypt public key from the NaturalMessage key.
	sexp_pub_key = gcry_sexp_find_token(sexp_nm_key, "public-key", 0);
	if(!sexp_pub_key){
		fprintf (stderr, "Error. Could not get the public-key from the input s-expression.\n");
		return 901;
	}

	if (debug_lvl >2){
		printf("Here is the dump of the public key only:\n");
		gcry_sexp_dump(sexp_pub_key);
	}

	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------

	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//   IMPORT THE FILE that needs to be verified
	//   (this goes to a regular buffer, not an SEXP)
	//
	fp = fopen(input_fname, "r");

	if(!fp){
		perror("Error. Failed open the input data file.");
		return(439);
	}
	//err_int = read_sexp_file(fp, &sexp_input_data, input_data_txt, 
	//		1, debug_lvl);
	
	fseek(fp, 0, SEEK_END);
	long pos = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *input_data_txt = gcry_malloc_secure(pos+1);
	if(!input_data_txt){
		perror("Error.  Malloc for the input data file failed.\n");
		exit(843);
	}
	// Read the data
	size_t blocks_read;
	blocks_read = fread(input_data_txt, pos, 1, fp);
	if (blocks_read != 1){
		perror("Error while reading the input file.\n");
		exit(932);
	}

	fclose(fp);
	if (debug_lvl > 2){
		printf("the input data is: %s\n", input_data_txt);
	}
	//   CONSTRUCT AN S-EXPRESSION FOR THE DATA
	//err = gcry_sexp_build(&sexp_input_data, &err_offset, "(data (flags raw) (hash sha384 %s))", input_data_txt);
	err = gcry_sexp_build(&sexp_input_data, &err_offset, "(data (flags raw) (hash sha384 %s))", input_data_txt);
	if(err){
		fprintf (stderr, "Error. formatting the input data/nonce: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 902;
	}
	if (debug_lvl >2){
		printf("Here is the dump of the data/nonce only:\n");
		gcry_sexp_dump(sexp_input_data);
	}
	
	//err = gcry_sexp_build("(data (value |%s|))",
	//------------------------------------------------------------
	//    IMPORT THE SIGNATURE AND CONVERT IT TO AN OFFICIAL S-EXP
	fp = fopen(input_sig_fname, "r");
	if(!fp){
		perror("Error. Failed open the input data file.");
		return(440);
	}
	err_int = read_sexp_file(fp, &sexp_signature, input_sig_txt, 1, debug_lvl);
	if(err_int){
		printf("The signature was not read.\n");
		exit(0);
	}
	fclose(fp);
	if (debug_lvl > 2){
		printf("the input signature is: %s\n", input_data_txt);
	}
	//   CONSTRUCT AN S-EXPRESSION FOR THE DATA
	err = gcry_sexp_new(&sexp_signature,  input_sig_txt, 0 , 1);
	if(err){
		fprintf (stderr, "Error. formatting the input signature: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 902;
	}
	if (debug_lvl >2){
		printf("Here is the dump of the sig:\n");
		gcry_sexp_dump(sexp_input_data);
	}
	
	//------------------------------------------------------------
	//     VERIFY THE FILE
	//
	err = gcry_pk_verify(sexp_signature, sexp_input_data, sexp_pub_key);
	if(err){
		fprintf (stderr, "Error. Verification failed: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 903;
	}else{
		printf("Signature is confirmed\n");
	}
	
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	gcry_sexp_release(sexp_nm_key); //, sexp_nm_offline_key, sexp_offline_pub_key;
	gcry_sexp_release(sexp_pub_key);
	gcry_sexp_release(sexp_input_data);
	gcry_sexp_release(sexp_signature);
	gcry_free(input_fname        );
	gcry_free(input_sig_fname    );
	gcry_free(input_pub_key_fname);
	gcry_free(input_data_txt     );
	gcry_free(input_sig_txt      );
	gcry_free(nm_key_txt         );
	return 0;
}
