// NMVerifyServer.c
//
// This is not updated to use secure memory,but it should work.
// use nm_sign and nm_verify to tweak this (or copy the sections
// into this program and recompile).
//
//
//
//
// Purpose:
//   1) Read a nonce, a detached signature in 
//      NaturalMessage-format, and a public key
//      in NM format to verify the signature.
//      Then check a second detached signature to verify
//      that the first key was signed by the Offline Master 
//      Key that has the known sha384 supplied by the user.
//
//     READ THIS FILE ABOUT S-EXPRESSIONS (DONT' CUT CORNERS): 
//        http://people.csail.mit.edu/rivest/Sexp.txt
//
/*
														LIBGCRYPT AND S-EXPRESSIONS

	The blocks of S-expressoin contain ASCII data or c- escapes and
	contain many ()() -- like LISP.

	READ THIS FILE (DONT' CUT CORNERS): http://people.csail.mit.edu/rivest/Sexp.txt

	* Scan this: http://people.csail.mit.edu/rivest/sexp.html
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


	Some filenames look like this: sexp.h

  READ the instructions for gcry_sexp_build() because the format
	strings are not the standard C format strings.

	Print an S-expression using gcry_sexp_sprint().

	Use gcry_sexp_find_token() to extract a subset of an S-exp.
*/
//
//
// I had to create a link in fedora so that the program could find
// this library:
// [root@99lenovohd libg]# cd /usr/lib64
// [root@99lenovohd lib64]# ln -s /usr/local/lib/libgcrypt.so.20 ./libgcrypt.so.20
//
// Compile to an executable:
//   gcc -Wall -g -D_FILE_OFFSET_BITS=64 `libgcrypt-config --cflags -o NMVerifyServer --libs` NMVerifyServer.c
//
// Compile to an object file:
//    gcc -o libgVerifyNM01.o libgVerifyNM01.c `libgcrypt-config --cflags --libs`
// OR maybe:
//    gcc -c libgVerifyNM01.c `libgcrypt-config --cflags`
//
#include <gcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>

#define MAX_ENTRY_LEN 500
#define MAX_KEY_BUFF 10000
#define MAX_CMDLINE_BUFF 500
#define debug_lvl 4

char save_name[MAX_ENTRY_LEN];
char output_fname[MAX_ENTRY_LEN];


int file_length(FILE *f)
{
	//from http://bytes.com/topic/c/answers/221370-how-get-file-size
	int pos;
	int end;
	pos = ftell (f);
	fseek (f, 0, SEEK_END);
	end = ftell (f);
	fseek (f, pos, SEEK_SET);
	return end;
}

char *get_line (char *s, size_t n, FILE *f)
{
	// From http://home.datacomm.ch/t_wolf/tw/c/getting_input.html
  char *p = fgets (s, n, f);

  if (p != NULL) {
    size_t last = strlen (s) - 1;

    if (s[last] == '\n') s[last] = '\0';
  }
  return p;
}

int read_sexp_file(FILE *fp, gcry_sexp_t *sexp_r, char *txt, int ascii_only){
	// Read an ASCII text file that looks like an s-expression
	// and convert it to an internal-format s-expression 
	// with an additional copy of the original text buffer.
	//
	//fp:
	//  The input file handle.
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
			if(ch < 0){
				if (debug_lvl > 0)
					printf("Ignoring non-ASCII character: %c", ch);
			}else{
				*(txt + idx++) = ch;
			}
		}
	}else{
		while ((ch=fgetc(fp)) != EOF){  /* read/print characters including newline */
			*(txt + idx++) = ch;
 		}
	}
	
	//if !(feof(fp)) 
	if (ferror(fp))
	{
		perror("Error. Could not read the input file.");
		fprintf(stderr,"fgetc() failed in file %s at line # %d\n", __FILE__,__LINE__);
		exit(EXIT_FAILURE);
	}
	//fclose(fp);
	if(debug_lvl > 3){
		printf("In read_sexp_file I read %d chars.\n", idx);
		printf("In read_sexp_file I read this: %s\n", txt);
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
			printf("In read_sexp_file, the input s-expression was converted to internal s-expression format.\n");
		}
	}

	if (debug_lvl > 5){
		printf("In read_sexp_file, the internal s-exp looks like this:\n");
		gcry_sexp_dump(*(sexp_r));
	}	

	return 0;
}
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int main (int argc, char **argv) {
	// Define some stuff for verication of sig:
	gcry_error_t err;
	size_t err_offset;

	char input_fname[MAX_CMDLINE_BUFF];
	char input_sig_fname[MAX_CMDLINE_BUFF];
	char input_pub_key_fname[MAX_CMDLINE_BUFF];
	char input_keysig_fname[MAX_CMDLINE_BUFF];
	char input_offline_pub_key_fname[MAX_CMDLINE_BUFF];
	char input_server_fingerprint[MAX_CMDLINE_BUFF];

	char input_data_txt[MAX_KEY_BUFF];
	char input_sig_txt[MAX_KEY_BUFF];
	char input_keysig_txt[MAX_KEY_BUFF];
	char nm_key_txt[MAX_KEY_BUFF];
	char nm_offline_pub_key_txt[MAX_KEY_BUFF];
	gcry_sexp_t sexp_nm_key, sexp_nm_offline_key, sexp_offline_pub_key;
	gcry_sexp_t sexp_pub_key;
	gcry_sexp_t sexp_online_key_data;
	gcry_sexp_t sexp_input_data, sexp_keysig;
	gcry_sexp_t sexp_signature ;
	int idx;
	char ch;


	FILE *fp;

	if (argc == 7){
		strncpy(input_fname, (char *) argv[1], MAX_CMDLINE_BUFF);
		strncpy(input_sig_fname, (char *) argv[2], MAX_CMDLINE_BUFF);
		strncpy(input_pub_key_fname, (char *) argv[3], MAX_CMDLINE_BUFF);
		strncpy(input_keysig_fname, (char *) argv[4], MAX_CMDLINE_BUFF);
		strncpy(input_offline_pub_key_fname, (char *) argv[5], MAX_CMDLINE_BUFF);
		strncpy(input_server_fingerprint, (char *) argv[6], MAX_CMDLINE_BUFF);
		if(debug_lvl > 0)
			printf("Reading input file: %s\n", input_fname);
	}else{
		printf("Usage: %s InputDataFname SIG PUBLIC.KEY KeySig OfflinePubKey Fingerprint\n", argv[0]);
		return 876;
	}

	/*
	----------------------------------------------------------------------
															LIBGCRYPT INITIALIZATION
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
	//gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	/*
	 .. If required, other initialization goes here. Note that the
	 process might still be running with increased privileges and that
	 the secure memory has not been initialized. 
	*/

	/*
		Allocate a pool of 16k secure memory. This make the secure memory
		available and also drops privileges where needed. 
	*/

	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
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
	//------------------------------------------------------------
	//   IMPORT THE FILE TO verify AND MAKE IT AN S-EXP
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part I\n");

	//fp = stdin;
	fp = fopen(input_fname, "r");
	////read_sexp_file(fp, &sexp_input_data, input_data_txt, 1);
	idx = 0;
	while (((ch=fgetc(fp)) != EOF) & (idx < MAX_KEY_BUFF)){  /* read/print characters including newline */
		*(input_data_txt + idx++) = ch;
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
	if (debug_lvl > 5){
		printf("Here is the dump of the data/nonce only:\n");
		gcry_sexp_dump(sexp_input_data);
	}
	
	//err = gcry_sexp_build("(data (value |%s|))",
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//    IMPORT THE SIGNATURE AND CONVERT IT TO AN OFFICIAL S-EXP
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part II\n");

	fp = fopen(input_sig_fname, "r");
	printf("TEMP the sig fname is %s\n", input_sig_fname);
	err=read_sexp_file(fp, &sexp_signature, input_sig_txt, 1);
	fclose(fp);
	if(err){
		printf("Error importing the signature for the nonce.");
		return 543;
	}
	if (debug_lvl > 2){
		printf("the input signature on the nonce is: %s\n", input_sig_txt);
	}
	//////   CONSTRUCT AN S-EXPRESSION FOR THE DATA
	////err = gcry_sexp_new(&sexp_signature,  input_sig_txt, 0 , 1);
	////if(err){
	////	fprintf (stderr, "Error. formatting the input signature: %s/%s\n",
	////		gcry_strsource (err),
	////		gcry_strerror (err));
	////	return 902;
	////}
	if (debug_lvl > 5){
		printf("Here is the dump of the sig:\n");
		gcry_sexp_dump(sexp_input_data);
	}
	
	//------------------------------------------------------------
	//------------------------------------------------------------
	//  Read the NaturalMessage public key
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part III\n");

	printf("TEMP - reading online pub key from file: %s\n", input_pub_key_fname);
	fp = fopen(input_pub_key_fname, "r");
	read_sexp_file(fp, &sexp_nm_key, nm_key_txt, 0);
	fclose(fp);
	if (debug_lvl > 5 ){
		printf("Here is a dump of the s-exp for the imported full PUBLIC key:\n");
		gcry_sexp_dump(sexp_nm_key);
	}
	//  Extract the libgcrypt public key from the NaturalMessage key.
	printf("TEMP, i will now extract the online public key from the NM thing\n");
	sexp_pub_key = gcry_sexp_find_token(sexp_nm_key, "public-key", 0);
	if(!sexp_pub_key){
		fprintf (stderr, "Error. Could not get the public-key from the input s-expression.\n");
		return 901;
	}

	if (debug_lvl > 5){
		printf("Here is the dump of the public key only:\n");
		gcry_sexp_dump(sexp_pub_key);
	}

	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//     VERIFY THE FILE
	//
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part IV\n");

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
	//   Read the signature for the online key
	//   (This is the second file that needs verification)
	//
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part V\n");

	printf("TEMP NOTE, STARTING KEYSIG READ.\n");
	fp = fopen(input_keysig_fname, "r");
	read_sexp_file(fp, &sexp_keysig, input_keysig_txt, 0);
	fclose(fp);
	//
	if (debug_lvl > 2){
		printf("Here is the dump of the signature for the online key (keysig):\n");
		gcry_sexp_dump(sexp_keysig);
	}
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//   Read the Offline public key
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part VI\n");

	fp = fopen(input_offline_pub_key_fname, "r");
	read_sexp_file(fp, &sexp_nm_offline_key, nm_offline_pub_key_txt, 0);
	if (debug_lvl > 5 ){
		printf("Here is a dump of the s-exp for the imported OFFLINE PUBLIC key:\n");
		gcry_sexp_dump(sexp_nm_offline_key);
	}
	fclose(fp);
	//  Extract the libgcrypt public key from the NaturalMessage key.
	sexp_offline_pub_key = gcry_sexp_find_token(sexp_nm_offline_key, "public-key", 0);
	if(!sexp_offline_pub_key){
		fprintf (stderr, "Error. Could not get the offline public-key from the input s-expression.\n");
		return 901;
	}

	if (debug_lvl > 2){
		printf("Here is the dump of the offline public key only:\n");
		gcry_sexp_dump(sexp_offline_pub_key);
	}

	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//    CONVERT THE ONLINE PUB KEY TO A DATA S-EXP
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part VI-B\n");

	// The length of a server key will probably not be on 
	// a boundary for the input block size of the hash algo,
	// so use PKCS1 to pad the block size.
	///err = gcry_sexp_build(&sexp_online_key_data, &err_offset, "(data (flags pkcs1) (hash sha384 %s))", nm_key_txt);
	err = gcry_sexp_build(&sexp_online_key_data, &err_offset, "(data (flags raw) (hash sha384 %s))", nm_key_txt);
	if(err){
		fprintf (stderr, "Error. formatting the online public key as a data object to check its sig: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 902;
	}
	if (debug_lvl > 2){
		printf("Here is the dump of the online key as a data s-exp:\n");
		gcry_sexp_dump(sexp_online_key_data);
	}
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//     VERIFY THE SIGNATURE ON THE ONLINE KEY
	//
	if (debug_lvl > 0)
		printf("\n--------------------------------- Part VII\n");

	err = gcry_pk_verify( sexp_keysig, sexp_online_key_data, sexp_offline_pub_key);
	if(err){
		fprintf (stderr, "Error. Verification failed: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 903;
	}else{
		printf("Signature on the Online Key by the Offline Key is confirmed\n");
	}
	
	//------------------------------------------------------------
	//------------------------------------------------------------
	printf("**** I STILL NEED TO VERIFY THE SHA384 OF THE OFFLINE PUBLIC KEY");
	//------------------------------------------------------------
	//------------------------------------------------------------
	return 0;
}
