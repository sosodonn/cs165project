// Don Nguyen 860-90-2099
// Project 1

//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

#include <iostream>
//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
  //-------------------------------------------------------------------------
  // initialize
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
  
  setbuf(stdout, NULL); // disables buffered output
  
  // Handle commandline arguments
  // Useage: client -server serveraddress -port portnumber filename
  if (argc < 2)
    {
      printf("Useage: server portnumber\n");
      exit(EXIT_FAILURE);
    }
  char* port = argv[1];
  
  printf("------------\n");
  printf("-- SERVER --\n");
  printf("------------\n");
  
  //-------------------------------------------------------------------------
  // 1. Allow for a client to establish an SSL connection
  printf("1. Allowing for client SSL connection...");
  
  // Setup DH object and generate Diffie-Helman Parameters
  DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
  int dh_err;
  DH_check(dh, &dh_err);
  if (dh_err != 0)
    {
      printf("Error during Diffie-Helman parameter generation.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup server context
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  //	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
  SSL_CTX_set_tmp_dh(ctx, dh);
  if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
    {
      printf("Error setting cipher list. Sad christmas...\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the BIO
  BIO* server = BIO_new(BIO_s_accept());
  BIO_set_accept_port(server, port);
  BIO_do_accept(server);
  
  // Setup the SSL
  SSL* ssl = SSL_new(ctx);
  if (!ssl)
    {
      printf("Error creating new SSL object from context.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  SSL_set_accept_state(ssl);
  SSL_set_bio(ssl, server, server);
  if (SSL_accept(ssl) <= 0)
    {
      printf("Error doing SSL_accept(ssl).\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("DONE.\n");
  printf("    (Now listening on port: %s)\n", port);
  
  //-------------------------------------------------------------------------
  // 2. Receive a random number (the challenge) from the client
  printf("2. Waiting for client to connect and send challenge...");
  
  //SSL_read
  string challenge="";
  
  char buff[BUFFER_SIZE];
  memset( buff, 0 , sizeof(buff));
  // SSL_read(SSL *ssl, void *buf, int num)
  int buff_len  = SSL_read( ssl, buff, BUFFER_SIZE );
  
  challenge = buff;
  printf("DONE.\n");
  printf("    (Challenge: \"%s\")\n",  buff2hex((const unsigned char* ) buff, sizeof(buff)).c_str());
  
  //-------------------------------------------------------------------------
  // 3. Generate the SHA1 hash of the challenge
  printf("3. Generating SHA1 hash...");
  //BIO_new(BIO_s_mem());
  // BIO_new(BIO_METHOD *type);
  BIO* lookThrough = BIO_new(BIO_s_mem());
  
  //BIO_write
  //BIO_write(BIO *b, const void *buf, int len);
  BIO_write(lookThrough,buff,buff_len);
  
  //BIO_new(BIO_f_md());
  // BIO_new(BIO_METHOD *type);
  BIO *SHA1hash = BIO_new(BIO_f_md());
  
  //BIO_set_md;
  //BIO_set(BIO *a,BIO_METHOD *type);
  BIO_set_md(SHA1hash ,EVP_sha1());
  
  //BIO_push;
  //BIO_push(BIO *b,BIO *append);
  BIO_push(SHA1hash ,lookThrough);
  
  //BIO_gets;
  char buffed[EVP_MAX_MD_SIZE];
  //BIO_gets(BIO *b,char *buf, int size);
  int value = BIO_gets(SHA1hash ,buffed,EVP_MAX_MD_SIZE);
  string hash=  buff2hex((const unsigned char*)buffed, value);
  
  printf("SUCCESS.\n");
  printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash.c_str(), value);
  
  //BIO_free()
  BIO_free_all(SHA1hash);
  
  //-------------------------------------------------------------------------
  // 4. Sign the key using the RSA private key specified in the
  //     file "rsaprivatekey.pem"
  printf("4. Signing the key...");
  
  unsigned char buff_read_encryption[128];
  memset(buff_read_encryption,0,sizeof(buff_read_encryption));
  
  char RSAprivatefile[] = "rsaprivatekey.pem";
  BIO *privatekey = BIO_new_file(RSAprivatefile,"r");
  //PEM_read_bio_RSAPrivateKey
  //RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x,pem_password_cb *cb, void *u);
  RSA *rsa = PEM_read_bio_RSAPrivateKey(privatekey,NULL,NULL,NULL);
  
  //RSA_private_encrypt
  //RSA_private_encrypt(int flen, unsigned char *from,unsigned char *to, RSA *rsa, int padding);
  int siglen = RSA_private_encrypt(RSA_size(rsa)-11,(const unsigned char*)buffed,buff_read_encryption,rsa,RSA_PKCS1_PADDING);
  
  //char* signature="FIXME";
  char* signature=(char*)buff_read_encryption;
  
  printf("DONE.\n");
  printf("    (Signed key length: %d bytes)\n", siglen);
  printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);
  
  //-------------------------------------------------------------------------
  // 5. Send the signature to the client for authentication
  printf("5. Sending signature to client for authentication...");
  
  // Create a new buffer, clear it and copy the signature to it
  char sig_buf[BUFFER_SIZE];
  memset(sig_buf,0, sizeof(sig_buf));
  memcpy(sig_buf, signature, sizeof(sig_buf)); 
  
  //BIO_flush
  BIO_flush(lookThrough); 
  //SSL_write
  SSL_write(ssl, sig_buf, BUFFER_SIZE);
  
  printf("DONE.\n");
  
  //-------------------------------------------------------------------------
  // 6. Receive a filename request from the client
  printf("6. Receiving file request from client...");
  
  
  char filename[BUFFER_SIZE];
  memset(filename,0,sizeof(filename));
  //SSL_read
  SSL_read(ssl,filename,BUFFER_SIZE);
  
  printf("RECEIVED.\n");
  printf("    (File requested: \"%s\"\n", filename);
  
  //-------------------------------------------------------------------------
  // 7. Send the requested file back to the client (if it exists)
  printf("7. Attempting to send requested file to client...");
  
  PAUSE(2);
  
  bool keep = true;
  string message;
  char buffer[BUFFER_SIZE];
  memset(buffer,0, sizeof(buffer));
  //BIO_flush
  BIO_flush(server);
  int bytesRead;
  int bytesSent=0;
  int count = 0;   
  int write;
  //BIO_new_file
  BIO*bfile = BIO_new_file(filename, "r");
  if(bfile == NULL)
    {
      cout << "ERROR! No file exist" << endl;
      return 0;
    } 
  else
    {
      int temp = 0;
      while( (bytesRead =  BIO_read(bfile, buffer, BUFFER_SIZE)) >= 1)
	{
	  write = SSL_write(ssl, buffer, bytesRead);
	  bytesSent += write;
	}
    }
  
  
  printf("SENT.\n");
  printf("    (Bytes sent: %d)\n", bytesSent);
  
  //-------------------------------------------------------------------------
  // 8. Close the connection
  printf("8. Closing connection...");
  
  //SSL_shutdown
  SSL_shutdown(ssl);
  //BIO_reset
  BIO_reset(server);
  printf("DONE.\n");
  
  printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
  
  //-------------------------------------------------------------------------
  // Freedom!
  
  BIO_free_all(server);
  return EXIT_SUCCESS;
}
