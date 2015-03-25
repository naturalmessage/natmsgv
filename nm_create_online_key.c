// nm_create_online_key.c
/*
    Copyright 2014 Robert E. Hoot. Pahrump, NV, USA.

    This program is distributed under the terms of the GNU General Public License.

    This file is part of the Natural Message Server software suite.

    The Natural Message Server software suite is free software: you
    can redistribute it and/or modify it under the terms of the GNU
    General Public License as published by the Free Software Foundation,
    either version 3 of the License, or (at your option) any later
    version.
    
    Natural Message Server is distributed in the hope that it will be
    useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with the Natural Message Server.  If not, see
    <http://www.gnu.org/licenses/>.
*/
//
// Purpose:
//  1) Generate online and offline keys for a Natural Message
//     server.
//  1) The offline master key is for signing only, and it will be
//     an ECC Ed25519 key with No expiration date.
//     The Sha384 of this exported text file with S-expressions
//     becomes the server fingerprint.
//  2) Create an online RSA2048 encryption key that expires at a
//     date set by the user (recommended about 30 days).
//     (I might substitute regular GPG RSA keys for encryption due
//     to the hassle of using RSA to encrypt a nonce that encrypts
//     the big file with AES -- but then this leads back to the
//     compile problem of putting the correct GPGME on verious OSs).
//  3) Create an online ECC Ed25519 signing key that expires at a date
//     set by the user (recommeded about 30 days).
//  4) The user can enter information like the name and a Natural Message
//     user ID and other comment info to identify the owner.
// After compiling, run:
//   valgrind  --leak-check=full  --show-leak-kinds=all ./nm_create_server_keys
//
// READ THIS FILE ABOUT S-EXPRESSIONS (DONT' CUT CORNERS): 
//   http://people.csail.mit.edu/rivest/Sexp.txt
//
// local header file:
#include "nm_keys.h"

#include <time.h>
#include <assert.h>

#define MAX_ENTRY_LEN 500
#define MAX_CMDLINE_BUFF 1000
// Note: If you adjust MAX_KEY_BUFF, double check the
// allocation for secure memory: find "GCRYCTL_INIT_SECMEM"
#define MAX_KEY_BUFF 3000
#define DEBUG_LVL 2

char save_name[MAX_ENTRY_LEN];
char output_fname[MAX_ENTRY_LEN];

struct entry_stuff_t
{
	// yes, I waste space here.
	char name_real[MAX_ENTRY_LEN];
	char name_comment[MAX_ENTRY_LEN];
	char natmsg_id[MAX_ENTRY_LEN];
	char key_function[3];
	char IPV4[MAX_ENTRY_LEN];
	char IPV6[MAX_ENTRY_LEN];
	char backup_IPV4[MAX_ENTRY_LEN];
	char expiration_YYYYMMDD[MAX_ENTRY_LEN];
	char create_time[MAX_ENTRY_LEN];
	char output_fname_prefix[MAX_ENTRY_LEN];
} entry_stuff;


//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int natmsg_gen_key(const char * sexp_txt_in,
	struct entry_stuff_t *entry_data,
  char * rslt_pub_txt_ptr,
	char * rslt_prv_txt_ptr,
  size_t max_rslt_txt_len,
	gcry_sexp_t *sexp_key_rslt,
	int debug_lvl){
	// This function accepts some arguments to create a public/private key pair
	// using libgcrypt.  It returns both an internal/binary format S-expression
	// for the combined public-private key pair, plus separte text
	// representaitons of the S-expressions for public and private keys that
	// also contain some information about the owner of the keys.
	//
	//sexp_txt:
	//  The user should pass sexp_txt_in as regular text that
	//  can contain S-expressions for either RSA, ECC, or maybe other types of keys.
	//  Example of the sexp_txt_in input values that can be passed here:
	//  //static const char buff_online_enc_sexp[] = "(genkey (rsa (nbits 4:2048)))";
	//  //static const char buff_online_sign_sexp[] = "(genkey (ecc (curve \"Ed25519\")))";
	//  Note that quoted text inside S-expressions requires double quotes.
	//
	//entry_stuff:
	//  This is a struct that contains information such as the user name
	//  and expiration date.  Some of the information will go to both the
	//  public and private text representations of the keys, and some
	//  will go only to the public key.
	//
	//  When users enter metadata (name, comment, etc.), it goes into
	//  the entry_stuff struct.  There is currently only minimal 
	//  error checking on the expiration date and no error checking
	//  on the other fields.
	//
	//  When the user enters metadata (e.g., name and comment), 
	//  the user should strive to enter the subset of ASCII that is
	//  allowed for regular text for s-expressions.  
	//  (see http://people.csail.mit.edu/rivest/Sexp.txt)
	//  Non ASCII might be converted
	//  to a format that libgcrypt can process into internal-format 
	//  s-expressions, which means that one character that is not in
	//  the approved list for s-expressions will force the entire string
	//  to be converted to hex or base 64 or some arbitrary format chosen
	//  by libgcrypt that can be imported into an s-expression. This
	//  should not cause any errors, but the user would have to use 
	//  a reader to convert the hex into the original text of the name,
	//  comment, or other such field.
	//
	//rslt_pub_txt_ptr:
	//  This is a a pointer to a char buffer that the caller allocates before
	//  calling this function.  It will contain the text representation of the 
	//  S-expression for the public key, along with some info about the owner
	//  of the key.
	//
	//rslt_prv_txt_ptr:
	//  This is a a pointer to a char buffer that the caller allocates before
	//  calling this function.  It will contain the text representation of the 
	//  S-expression for the private key, along with some info about the owner
	//  of the key.
	//
	//max_rslt_txt_len:
	//  This is the maximum length in bytes of the text that will be returned.
	//
	//sexp_key_rslt:
	//  The results are returned to rslt_pub_txt_ptr, char * rslt_prv_txt_ptr.


	size_t err_offset;
	gcry_error_t err;
	gcry_sexp_t sexp_pub_nm_key; //this will be converted to text and returned.
	gcry_sexp_t sexp_prv_nm_key; //this will be converted to text and returned.
	gcry_sexp_t sexp_key_parms;
	gcry_sexp_t sexp_pub_tmp, sexp_prv_tmp;

	char *tmp_combined_sexp_txt = gcry_malloc_secure(max_rslt_txt_len);
	char *tmp_pub_sexp_txt = gcry_malloc_secure(max_rslt_txt_len);


	err = gcry_sexp_new(&sexp_key_parms, sexp_txt_in, 0, 1);
	if (err){
		fprintf (stderr, "Error. Formatting of the s-exp for keygen Failed: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 999;
	}else{
		if(debug_lvl > 0){
			printf("Creation of the s-expression that goes to the keygen process is good.\n");
		}
	}
	
	// The resulting s-expression is stored at this address
	// sexp_key_rslt.
	err = gcry_pk_genkey(sexp_key_rslt, sexp_key_parms);
	if (err){
		fprintf (stderr, "Error.  keygen Failed: %s/%s\n",
			gcry_strsource (err),
			gcry_strerror (err));
		return 999;
	}else{
		// The keygen looks good. 
		//
		// Format options for printing s-exp are on page 69 of 1.62 libgcrypt PDF: 
		//   GCRYSEXP_FMT_DEFAULT, GCRYSEXP_FMT_CANON, GCRYSEXP_FMT_ADVANCED
		//
		if(debug_lvl > 3){
			// Print full key (contains both pub and private sections).
			printf("The full pub/prv key is:\n");
			gcry_sexp_sprint(*(sexp_key_rslt), GCRYSEXP_FMT_ADVANCED, tmp_combined_sexp_txt, 10000);
			fprintf(stderr, tmp_combined_sexp_txt);
		}
		// ------------------------------------------------------------------
		//
		// ------------HERE IS THE PUBLIC KEY
		// Extract the public key s-exp to its own s-exp.
		sexp_pub_tmp = gcry_sexp_find_token(*(sexp_key_rslt), "public-key", 0);

		// Build an s-expression that holds the gcrypt public
		// key along with the Natural Message meta data
		// about the key owner.
		gcry_sexp_build(&sexp_pub_nm_key, &err_offset,
			"(NaturalMessage-Assymetric-Key\n"
			"  (Owner-Info\n"
			"    (Name %s)\n"
		  "    (Comment %s)\n"
		  "    (Key-Function %s)\n"
		  "    (Natural-Message-ID %s)\n"
		  "    (IPV4 %s)\n"
		  "    (IPV6 %s)\n"
		  "    (Alternative-IPV4 %s)\n"
		  "    (Create-Time %s)\n"
		  "    (Expire-Date-YYYYMMDD %s))\n"
			"  %S)",
			entry_data->name_real,
			entry_data->name_comment, 
			entry_data->key_function,
			entry_data->natmsg_id,
			(char *) entry_data->IPV4,
			entry_data->IPV6,
			entry_data->backup_IPV4,
			entry_data->create_time,
			entry_data->expiration_YYYYMMDD,
			sexp_pub_tmp);
			//tmp_pub_sexp_txt);
		
		// Now convert the whole thing to a regular string
		gcry_sexp_sprint(sexp_pub_nm_key, GCRYSEXP_FMT_ADVANCED,
			rslt_pub_txt_ptr, max_rslt_txt_len);
		
		//------------HERE IS THE PRIVATE KEY
		// Extract the private key s-exp to its own s-exp.
		sexp_prv_tmp = gcry_sexp_find_token(*(sexp_key_rslt), 
			"private-key", 0);

		// Build a single s-expression that has the regular
		// key plus the custom Natural Message info.
		// The libgcrypt _build fnction should be using 
		// secure memory for this.
		gcry_sexp_build(&sexp_prv_nm_key, &err_offset,
			"(NaturalMessage-Assymetric-Key\n"
			"  (Owner-Info\n"
			"    (Name %s)\n"
		  "    (Comment %s)\n"
		  "    (Key-Function %s)\n"
		  "    (Create-Time %s)\n  )\n"
			"  %S)", 
			entry_data->name_real, 
			entry_data->name_comment, 
			entry_data->key_function,
			entry_data->create_time,
			sexp_prv_tmp);

		// Now convert the whole thing to a regular string
		gcry_sexp_sprint(sexp_prv_nm_key, GCRYSEXP_FMT_ADVANCED,
			rslt_prv_txt_ptr, max_rslt_txt_len);
		
		//----------------------------------------
		//----------------------------------------
	}
	// Free mem to reuse the key_parms
	gcry_sexp_release(sexp_pub_nm_key);
	gcry_sexp_release(sexp_prv_nm_key);
	gcry_sexp_release(sexp_key_parms);
	gcry_sexp_release(sexp_pub_tmp);
	gcry_sexp_release(sexp_prv_tmp);

	gcry_free(tmp_combined_sexp_txt);
	gcry_free(tmp_pub_sexp_txt);
	////gcry_free(tmp_prv_sexp_txt);
	return 0;
}
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int usage(){
	printf("You must enter all the arguments or none of them (in which case "
		"you will be prompted interactively.)\n");
	printf("For any argument, you can enter two quotes with nothing between to "
		"be prompted at run time to enter a value.\n");
	printf("Usage: nm_create_online_key Name_of_Server Comment Webmaster_NatMsg_PUB_ID "
		"IPV4 IPV6 ipv4_backup Expiration_YYYYMMDD output_fname_prefix\n");
	return 876;

	return 0;
}
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
int main (int argc, char **argv) {
	// Define some stuff for verication of sig:
	int rslt;

	// Bob stuff
	gcry_sexp_t sexp_online_enc_key, sexp_online_sign_key; 
	gcry_sexp_t sexp_offline_sign_key;
	static const char buff_online_enc_sexp[] = "(genkey (rsa (nbits 4:2048)))";
	static const char buff_online_sign_sexp[] =  "(genkey (ecc (curve \"Ed25519\")))";
	static const char buff_offline_sign_sexp[] = "(genkey (ecc (curve \"Ed25519\")))";
	char *buff_online_enc_pub_sexp_result  = gcry_malloc_secure(MAX_KEY_BUFF);
	char *buff_online_enc_prv_sexp_result  = gcry_malloc_secure(MAX_KEY_BUFF);
	char *buff_online_sign_pub_sexp_result = gcry_malloc_secure(MAX_KEY_BUFF);
	char *buff_online_sign_prv_sexp_result = gcry_malloc_secure(MAX_KEY_BUFF);
	char *buff_offline_sign_pub_sexp_result= gcry_malloc_secure(MAX_KEY_BUFF);
	char *buff_offline_sign_prv_sexp_result= gcry_malloc_secure(MAX_KEY_BUFF);
	int j;

	time_t t;
	struct tm *my_time;
	char *time_str_now;
	FILE *fp;
	char save_YYYYMMDD[10];

	//------------------------------------------------------------------------
	entry_stuff.name_real[0] = '\0';
	entry_stuff.name_comment[0] = '\0';
	entry_stuff.natmsg_id[0] = '\0';
	entry_stuff.key_function[0] = '\0';
	entry_stuff.IPV4[0] = '\0';
	entry_stuff.IPV6[0] = '\0';
	entry_stuff.backup_IPV4[0] = '\0';
	entry_stuff.expiration_YYYYMMDD[0] = '\0';
	entry_stuff.create_time[0] = '\0';
	entry_stuff.output_fname_prefix[0] = '\0';

	//------------------------------------------------------------------------
	if (argc == 9){
		////No verification -- if you want to enter lots of garbage, 
		////that is what you will get.
		//if len > 0:
		//	entry_stuff.IPV4[len - 1] = '\0';
		printf("Processing command line arguments.");
		strncpy(entry_stuff.name_real, (char *) argv[1], MAX_CMDLINE_BUFF);
		strncpy(entry_stuff.name_comment, (char *) argv[2], MAX_CMDLINE_BUFF);
		strncpy(entry_stuff.natmsg_id, (char *) argv[3], MAX_CMDLINE_BUFF);
		strncpy(entry_stuff.IPV4, (char *) argv[4], MAX_CMDLINE_BUFF);
		strncpy(entry_stuff.IPV6, (char *) argv[5], MAX_CMDLINE_BUFF); //how long should this be?
		strncpy(entry_stuff.backup_IPV4, (char *) argv[6], MAX_CMDLINE_BUFF);
		strncpy(entry_stuff.expiration_YYYYMMDD, (char *) argv[7], MAX_CMDLINE_BUFF);
		strncpy(entry_stuff.output_fname_prefix, (char *) argv[8], MAX_CMDLINE_BUFF);

		printf("==== test... name real is %s\n", entry_stuff.name_real);
	}else{
		if (argc > 1){
			usage();
			return 876;
		}
	}
	//------------------------------------------------------------------------
	/*
	----------------------------------------------------------------------
															LIBGCRYPT INITIALIZATION
							(mostly from pages 5-6 of the libgcrypt 1.6.2 manual)
	----------------------------------------------------------------------
	*/
	/* 
		 Version check should be the very first call because it
		 makes sure that important subsystems are initialized.
	   The check-version thing is needed for initialization,
	   so I'm not sure if I should wait to free it until the end
	*/
	const char *version_rslt;
	version_rslt = gcry_check_version (GCRYPT_VERSION);
	if (!version_rslt){
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
		Allocate a pool of 40k secure memory. This make the secure memory
		available and also drops privileges where needed.
		You might need to invoke this using root privileges
	*/

	
	gcry_control (GCRYCTL_USE_SECURE_RNDPOOL); //put random nbrs in secmem
	gcry_control (GCRYCTL_SET_VERBOSITY, 0);

	gcry_control (GCRYCTL_INIT_SECMEM, 40960, 0);
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
	//    THE NEW KEYGEN IS HERE
	//
	
	//----------------------------------------
	printf("\nFor the following input, try to enter ASCII characters.");
	printf("It is not an error to enter UTF-8, but the format of");
	printf("the entered text string might be converted to hex or base64,");
	printf("and you would need to convert the hex or base64 to see");
	printf("the original values.  The input text will be put into\n");
	printf("S-expressions. For S-expression trivia, see:\n");
	printf("   http://people.csail.mit.edu/rivest/Sexp.txt\n");
	printf("Avoid entering trailing whitespace.\n\n");

	if (strlen(entry_stuff.output_fname_prefix) == 0){
		printf("Enter the Output Filename Prefix: ");
		get_line(entry_stuff.output_fname_prefix, 100, stdin);
	}
	
	if (strlen(entry_stuff.name_real) == 0){
		printf("Enter the Real Name for the key: ");
		get_line(entry_stuff.name_real, 100, stdin);
	}
	

	if ( strlen(entry_stuff.name_comment) == 0){
		printf("Enter the Name Comment for the key: ");
		get_line(entry_stuff.name_comment, 400, stdin);
	}
	
	// The following entry stuff applies to the online
	// keys but not the offline key:
	if(strlen(entry_stuff.natmsg_id) == 0){
		printf("Enter the Natural Message ID for the ONLINE key: ");
		get_line(entry_stuff.natmsg_id, 200, stdin);
	}
	
	// Validate entry for YYYYMMDD.  The original input capture
	// will keep only 8 chars, then check if they are digits.
	if(strlen(entry_stuff.expiration_YYYYMMDD) == 0){
		// //entry_stuff.expiration_YYYYMMDD[0] = 0x00;
		while (entry_stuff.expiration_YYYYMMDD[0] == 0x00){
			printf("Enter the Expiration Date (YYYYMMDD) for the ONLINE key: ");
			// Remember to add a byte to the entry to allow for NULL
			// or EOL. The routine will strip trailing whitespace.
			get_line(entry_stuff.expiration_YYYYMMDD, 10, stdin);
		
			if(strlen(entry_stuff.expiration_YYYYMMDD) == 8){
				// Length is good.  The input routine will kill trailing chars.
				for(j=0;j<strlen(entry_stuff.expiration_YYYYMMDD); j++){
					if (!isdigit(entry_stuff.expiration_YYYYMMDD[j])){
						printf("\n"); //start on a new line for the next attempt
						entry_stuff.expiration_YYYYMMDD[0] = 0x00; //force re-entry
						break;
					}
				}
			}else{
				// Bad entry length
				entry_stuff.expiration_YYYYMMDD[0] = 0x00; //force re-entry
				printf("\n"); //start on a new line for the next attempt
			}
		}
		strncpy(save_YYYYMMDD, entry_stuff.expiration_YYYYMMDD, 8);
	}
		
	if(strlen(entry_stuff.IPV4) == 0){
		printf("Enter the IPv4 for the web site: ");
		get_line(entry_stuff.IPV4, 17, stdin);
	}
	

	if(strlen(entry_stuff.IPV6) == 0){
		printf("Enter the IPv6 for the web site: ");
		get_line(entry_stuff.IPV6, 32, stdin);
	}

	if(strlen(entry_stuff.backup_IPV4) == 0){
		printf("Enter the backup/alternative IPv4 for the web site: ");
		get_line(entry_stuff.backup_IPV4, 17, stdin);
	}
	
  time(&t );
	if(! t){
		printf("Error. Failed to get the current time.\n");
		return(888);
	}
  my_time = localtime(&t);
	time_str_now = asctime(my_time);
  // Asctime adds an EOL to the string, 
  // so remove it.
  int i;
  i=strlen(time_str_now) - 1;
  while(isspace(time_str_now[i])) time_str_now[i] = 0x00;
  //
  
	// The cap of 30 is to prevent anything too crazy
	assert(strlen(time_str_now) < 30);
  strncpy(entry_stuff.create_time, time_str_now, 30);

	strncpy(save_name, entry_stuff.name_real, MAX_ENTRY_LEN );
	//-------------------------------------------------------------------
	//-------------------------------------------------------------------
	//            ONLINE KEY GEN
	//
	strcpy(entry_stuff.key_function, "e"); //encryption key
	strncat(entry_stuff.name_real, " ONLINE ENCRYPTION KEY", 
		MAX_ENTRY_LEN - strlen(entry_stuff.name_real));
	// restore the expire date for the online key
	strncpy(entry_stuff.expiration_YYYYMMDD, save_YYYYMMDD,  8);

  rslt = natmsg_gen_key(buff_online_enc_sexp, 
		&entry_stuff,
		buff_online_enc_pub_sexp_result, 
		buff_online_enc_prv_sexp_result,
		MAX_KEY_BUFF,
		&sexp_online_enc_key, DEBUG_LVL);

	if(rslt){
		perror("Generation of online encryption key failed\n");
		exit(721);
	}

	// Write the PUB key to a file:
	if (strlen(buff_online_enc_pub_sexp_result) > 0){
		strcpy(output_fname, entry_stuff.output_fname_prefix);
		strcat(output_fname, "OnlinePUBEncKey.key");
		fp = fopen((char *) output_fname, "w");
		if(!fp){
			perror("Error. Could not open the Public Encryption Key output file.");
			return(345);
		}
		fprintf(fp,"%s", buff_online_enc_pub_sexp_result);
		fclose(fp);

		// Write the prv key to a file:
		strcpy(output_fname, entry_stuff.output_fname_prefix);
		strcat(output_fname, "OnlinePRVEncKey.key");
		fp = fopen((char *) output_fname, "w");
		if(!fp){
			perror("Error. Could not open the Private Encryption Key output file.");
			return(345);
		}
		fprintf(fp,"%s", buff_online_enc_prv_sexp_result);
		fclose(fp);
	}
	//------------------------------------------------------------
	printf("\n -=-=-=-=-=-=- Starting Online ECC keygen\n");

	strcpy(entry_stuff.key_function, "s"); //signing key

	//Restore the name of the server, then append "online signing key"
	strncpy(entry_stuff.name_real, save_name, MAX_ENTRY_LEN );
	char *name_tmp = " ONLINE SIGNING KEY";
	printf("====== test in keygen. name_real is %s\n" , entry_stuff.name_real);

	strncat(entry_stuff.name_real, name_tmp, MAX_ENTRY_LEN - strlen(name_tmp)); 

  rslt = natmsg_gen_key(buff_online_sign_sexp,
		&entry_stuff,
		buff_online_sign_pub_sexp_result, 
		buff_online_sign_prv_sexp_result,
		MAX_KEY_BUFF,
		&sexp_online_sign_key, DEBUG_LVL);

	if(rslt){
		perror("Generation of online encryption key failed\n");
		exit(722);
	}

	//
	// Write the PUB key to a file:
	if (strlen(buff_online_sign_pub_sexp_result) > 0){
		strcpy(output_fname, entry_stuff.output_fname_prefix);
		strcat(output_fname, "OnlinePUBSignKey.key");
		if(DEBUG_LVL > 1)
			printf("out fname 3 is %s\n", output_fname);

		fp = fopen((char *) output_fname, "w");
		if(!fp){
			perror("Error. Could not open the Online Public Encryption Key output file.");
			return(345);
		}
		fprintf(fp,"%s", buff_online_sign_pub_sexp_result);
		fclose(fp);
		if(DEBUG_LVL > 1)
			printf("I closed the online PUB key file\n");
		// Write the prv key to a file:
		strcpy(output_fname, entry_stuff.output_fname_prefix);
		strcat(output_fname, "OnlinePRVSignKey.key");
		if(DEBUG_LVL > 1)
			printf("...i will now open the prv output file\n");
		fp = fopen((char *) output_fname, "w");
		if(!fp){
			perror("Error. Could not open the Online Private Signing Key output file.");
			return(345);
		}
		fprintf(fp,"%s", buff_online_sign_prv_sexp_result);
		fclose(fp);
		if(DEBUG_LVL > 1)
			printf("I closed the online PRV key file\n");
	}else{
		printf("Error, the online PUB key was not generated.\n");
	}
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//------------------------------------------------------------
	//
	
	gcry_sexp_release(sexp_online_enc_key);
	gcry_sexp_release(sexp_offline_sign_key);
	gcry_sexp_release(sexp_online_sign_key);

	int tmpi, tmpii;
	tmpi = strlen(buff_offline_sign_pub_sexp_result);
	tmpii = strlen(buff_offline_sign_prv_sexp_result);
	printf("testing len of buff_offline_sign_pub_sexp_result: %d\n", tmpi);
	printf("testing len of buff_offline_sign_prv_sexp_result: %d\n", tmpii);

	gcry_free(buff_online_enc_pub_sexp_result  );
	gcry_free(buff_online_enc_prv_sexp_result  );
	gcry_free(buff_online_sign_pub_sexp_result );
	gcry_free(buff_online_sign_prv_sexp_result );
	gcry_free(buff_offline_sign_pub_sexp_result);
	gcry_free(buff_offline_sign_prv_sexp_result);
		
	//gcry_free((void *) version_rslt); //did not seem to free anything

	return 0;
}
