cs165project
============

Computer security project

For my github account I was not sure on what to upload so I uploaded my whole folder which included,

ssl_server.cpp, ssl_client.cpp, rsaprivatekey.pem, rsapublickey.pem, simple.cpp, utils.h and README.md

In order for the code to work you will need all these files in the same directory. You will have to put a file
with the "rsaprivatekey.pem" and "rsapublickey.pem" that contains the public and private key that we
calculated from the previous lab. The client and server needs those files in order to send the files accross from the folder.

Whenver the file is sent over it will have "Recieved"+filename of whatever file you sent.

General Overview:
This project dealth with the RSA encryption and decryption using the SSL library. It has many
member functions that were new to me that I was able to search for the implementation prototypes.
Another feature that I worked that was new was networking with client and server. I first began
by establishing a connection between client-server. Then the client generated a random number(challenge)
that was sent to the server. When the server recieved it decrypted it using the RSA private key.
From that step it created teh SHA1 challenge and sign the has to send it back to the client.
Then it will send a file request which the server will send the filename and send the entire file back to the client.
After it completely sent it will create a new file with the contents in it. 

To run the program  you will have to put:

1) make

2) Terminal A: server (port number) ex) server 1025
	* port number must be greater than 1024

3) Terminal B: client server_address:portnumber filename
	ex) client localhost:1025 README.md

4) It should output all the steps already implemented in the file
	and output the file contents to the terminal and inside a
	new file. It should successfully send the file over if you follow the command
	the filename outcome will be "Recieved"+filename which will have the
	same stuff in filename.
