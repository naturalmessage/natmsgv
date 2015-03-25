//shatest.c
//
// This is an example of using libgcrypt
// to get the sha384 of a string (entered
// on the command line).
// THIS DOES NOT PAD THE DATA TO BE ON
// AND EVEN BLOCK BOUNDARY, SO IT IS WRONG.
// USE OPENSSL TO GET THE FINGERPRITN BY
// FINDING THE SHA384 OF THE ENTIRE PUBLIC KEY FILE.
//
// There is a quicker libgcrypt function
// for getting the sha384, but I wasn't sure
// if it would respect the context settings
// for secure memory.
//
#include "gcrypt.h"
#define MAX_BUFF 3000
int main(int argc, char *argv[]){

	
	char *buff = malloc(MAX_BUFF);
	int debug=0;

	if (argc == 2){
		strncpy(buff,argv[1], MAX_BUFF);
	}else{
		printf("Usage: shatest 'value'\n");
		return(4);
	}
	/*
 	  --------------------------------------------------
								 Initialization
 	  --------------------------------------------------
	*/ 

  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

	// Alocate 8k secure memory
  gcry_control (GCRYCTL_INIT_SECMEM, 8192, 0);
  /* 
    It is now okay to let Libgcrypt complain when there was/is
    a problem with the secure memory. 
  */
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  //gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	/*
 	  --------------------------------------------------
						Create a context for Message Digests
 	  --------------------------------------------------
	*/ 

	gcry_md_hd_t hd; //handle to a context
	gcry_error_t err;
	unsigned flags;	

	flags = GCRY_MD_FLAG_SECURE  ;
	err = gcry_md_open (&hd , GCRY_MD_SHA384 , flags );
	if (err){
		printf("Error. Could not set the option for secure random number storage.\n");
		return 123;
	}

	err = gcry_md_enable(hd, GCRY_MD_SHA384);
	if (err){
		printf("Error. Could not enable SHA384.\n");
		return 123;
	}


	//------------Load the raw data
	gcry_md_write(hd, buff, strlen(buff)); //strlen(buff)); // do NOT add +1 for the null

	//------------Get the message digest
	unsigned char *dgst_buff;
	dgst_buff = gcry_md_read(hd, GCRY_MD_SHA384);
	if(!dgst_buff){
		printf("read returned nothing\n");
	}
	int j;
	for(j=0; j< strlen(dgst_buff); j++){
		// Show the hex digits of the digest
		printf("%X", dgst_buff[j]);
	}
	printf("\n");
	
	/*
 	  --------------------------------------------------
                         Close
 	  --------------------------------------------------
	*/ 
	// Close the context and free the memory.
	gcry_md_close(hd);

	free(buff);
	return 0;
}
