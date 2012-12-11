// Don Nguyen 860-90-2099
// Project 1

//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries
#include <openssl/rand.h>
#include <iostream>
#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
string HelperChar_To_String( char a[],int amount)
{
  char b[amount];
  for( int i = 0 ; i < amount; i++)
    {
      b[i] = a[i];
    } 
  return b;
}
int main(int argc, char** argv)
{
  //-------------------------------------------------------------------------
  // Initialization
  
  ERR_load_crypto_strings();
  SSL_library_init();
  SSL_load_error_strings();
  
  setbuf(stdout, NULL); // disables buffered output
  
  // Handle commandline arguments
  // Useage: client server:port filename
  if (argc < 3)
    {
      printf("Useage: client -server serveraddress -port portnumber filename\n");
      exit(EXIT_FAILURE);
    }
  char* server = argv[1];
  char* filename = argv[2];
  bool state = true;
  
  printf("------------\n");
  printf("-- CLIENT --\n");
  printf("------------\n");
  
  //-------------------------------------------------------------------------
  // 1. Establish SSL connection to the server
  printf("1.  Establishing SSL connection with the server...");
  
  // Setup client context
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  //	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
    {
      printf("Error setting cipher list. Sad christmas...\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the BIO
  BIO* client = BIO_new_connect(server);
  if (BIO_do_connect(client) != 1)
    {
      printf("FAILURE.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the SSL
  SSL* ssl=SSL_new(ctx);
  if (!ssl)
    {
      printf("Error creating new SSL object from context.\n");
      exit(EXIT_FAILURE);
    }
  SSL_set_bio(ssl, client, client);
  if (SSL_connect(ssl) <= 0)
    {
      printf("Error during SSL_connect(ssl).\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("SUCCESS.\n");
  printf("    (Now connected to %s)\n", server);
  
  //-------------------------------------------------------------------------
  // 2. Send the server a random number
  printf("2.  Sending challenge to the server...");
  
  //string randomNumber="31337";
  //RAND_bytes(unsigned char *buf, int num);
  unsigned char randomBUFF[BUFFER_SIZE];
  int checkrand = RAND_bytes(randomBUFF,BUFFER_SIZE);
  if( checkrand != 1)
    {
      print_errors();
    }
  //SSL_write
  //SSL_write(SSL *ssl, const void *buf, int num);
  char buffer[BUFFER_SIZE];
  // Use the memset to write to buff can't just set the string to the buffer
  memset( buffer, 0 , sizeof(buffer));
  //memcpy( buffer,randomNumber.c_str(), sizeof(buffer));
  memcpy( buffer,randomBUFF, sizeof(buffer));
  
  int buff_len = SSL_write( ssl, buffer, BUFFER_SIZE );
  
  printf("SUCCESS.\n");
  printf("    (Challenge sent: \"%s\")\n",  buff2hex((const unsigned char* ) randomBUFF, BUFFER_SIZE).c_str());
  
  //-------------------------------------------------------------------------
  // 3a. Receive the signed key from the server
  printf("3a. Receiving signed key from server...");
  
  //char* buff="FIXME";
  //int len=5;
  char buff[BUFFER_SIZE];
  char BufftoNewBuff[BUFFER_SIZE];
  memset(buff,0,sizeof(buff));
  int len = 5;
  
  //SSL_read;
  // SSL_read(SSL *ssl, void *buf, int num)
  int lengthOfFile = SSL_read(ssl,buff,BUFFER_SIZE);
  
  printf("RECEIVED.\n");
  printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buff, len).c_str(), len);
  print_errors();
  
  //-------------------------------------------------------------------------
  // 3b. Authenticate the signed key
  printf("3b. Authenticating key...");
  
  //BIO_new(BIO_s_mem())
  // BIO_new(BIO_METHOD *type);
  BIO *bufferSEND = BIO_new(BIO_s_mem());
  
  //BIO_write
  //BIO_write(BIO *b, const void *buf, int len);
  BIO_write(bufferSEND, buff, lengthOfFile); 
  
  //BIO_new_file
  //*BIO_new_file(const char *filename, const char *mode);
  BIO *authenticKey = BIO_new_file("rsapublickey.pem", "r");
  
  //PEM_read_bio_RSA_PUBKEY
  //RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x,pem_password_cb *cb, void *u);
  RSA *rsa = PEM_read_bio_RSA_PUBKEY(authenticKey, NULL, NULL , NULL);
  
  //RSA_public_decrypt
  //RSA_public_decrypt(int flen, unsigned char *from,unsigned char *to, RSA *rsa, int padding);
  RSA_public_decrypt(RSA_size(rsa), (const unsigned char* )buff, (unsigned char* )BufftoNewBuff, rsa, RSA_PKCS1_PADDING);
  
  string ValidKey = buff2hex((const unsigned char* ) buff, 20);
  string decrypted = buff2hex((const unsigned char* ) BufftoNewBuff, 20); 
  
  printf("AUTHENTICATED\n");
  printf("    (Generated key: %s)\n", ValidKey.c_str());
  printf("    (Decrypted key: %s)\n", decrypted.c_str());
  // Free BIO everytime
  //BIO_free
  //BIO_free(BIO *a);
  BIO_free(authenticKey);
  
  //-------------------------------------------------------------------------
  // 4. Send the server a file request
  printf("4.  Sending file request to server...");
  PAUSE(2);
  //BIO_flush
  //BIO_flush(BIO *b);
  BIO_flush(bufferSEND);
  string fileRequest = filename;
  // Will only be valid if there is a NULL character at the end of the string
  fileRequest+='\0';
  //BIO_puts
  //BIO_puts(BIO *b,const char *buf);
  int putsFile = BIO_puts(bufferSEND, fileRequest.c_str());
  //SSL_write
  //SSL_write(SSL *ssl, const void *buf, int num);
  SSL_write(ssl, fileRequest.c_str(), putsFile);
  
  printf("SENT.\n");
  printf("    (File requested: \"%s\")\n", filename);
  
  //-------------------------------------------------------------------------
  // 5. Receives and displays the contents of the file requested
  printf("5.  Receiving response from server...\n");
  printf("===========================\n");
  printf("     CONTENTS IN FILE         \n");
  printf("===========================\n");
  
  //BIO_new_file
  //BIO *BIO_new_file(const char *filename, const char *mode);
  string sent = filename;
  sent = "Recieved"+sent;
  BIO* NewFile = BIO_new_file(sent.c_str(), "w");
  char readFromFile[BUFFER_SIZE]; 
  memset(readFromFile,0,sizeof(readFromFile));
  int readLines;
  string copiedRead;
  
  int SizeRead;
  // Loop will run until it breaks out with the if condition statement inside the loop
  while( (SizeRead = SSL_read(ssl,readFromFile,BUFFER_SIZE)) >= 1)
    {
      //SSL_read
      // int SizeRead = SSL_read(ssl,readFromFile,BUFFER_SIZE);
      BIO_write(NewFile,readFromFile,SizeRead);
      // If the size that you are reading in is less than the BUFFER_SIZE then it breaks out of this infinite loop
      copiedRead = HelperChar_To_String(readFromFile,SizeRead);
      cout << copiedRead;
    }
  
  //BIO_free
  BIO_free(NewFile);
  printf("FILE RECEIVED.\n");  
  //-------------------------------------------------------------------------
  // 6. Close the connection
  printf("6.  Closing the connection...");
  
  //SSL_shutdown
  SSL_shutdown(ssl);
  printf("DONE.\n");
  printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
  print_errors();
  
  //-------------------------------------------------------------------------
  // Freedom!
  SSL_CTX_free(ctx);
  SSL_free(ssl);
  return EXIT_SUCCESS;
  
}
