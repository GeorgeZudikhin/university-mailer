#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <ldap.h>


///////////////////////////////////////////////////////////////////////////////

#define BUF 1024
/* the number of files the user has received is stored in a file in their directory named numOfFiles */
#define SEPARATOR '\n'
#define MAX_NAME 8
#define MAX_SUBJ 80

///////////////////////////////////////////////////////////////////////////////

const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
const int ldapVersion = LDAP_VERSION3;
bool successfulLogin = false;
int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;
using namespace std;
namespace fs = std::filesystem;
string sender = "";
string clientIP = "";
pid_t childpid;

///////////////////////////////////////////////////////////////////////////////

void *clientCommunication(void *data, string folder);
string login(string buffer, string folder);
bool receiveFromClient(string buffer, string folder);
string list(string folder);
string read(string buffer, string folder);
bool deleteMessage(string buffer, string folder);

/* HELPERS */
void signalHandler(int sig);
void printUsage();
int getNumOfFiles(string folder);
string getHighestFileNumber(string folder);
string getString(string buffer);
string removeString(string buffer, string s1);
bool verifyStringLength(string string, int maxStringLength);
bool lockFile(int fd);
bool unlockFile(int fd);


///////////////////////////////////////////////////////////////////////////////

/**
 * @brief Server for basic tw-mailer. Responds to commands from the client, can save a message in the receiver's repository,
 * list the number of messages in the user's inbox and their subjects, read the content of a given message and delete messages
 * 
 */
int main(int argc, char* argv[])
{
   /* ARGUMENT HANDLING */
   if(argc != 3) { 
      printUsage();
   }

   // assign the third command-line argument to the folder variable
   string folder = argv[2];

   try {
      // check whether the directory specified by the folder path exists or not
      if (!fs::is_directory(folder)) { 
         cout << folder << " does not exist. Creating now..." << endl;
         fs::create_directory(folder);
      } 
   } catch(fs::filesystem_error& error) {
      cerr << error.what() << endl;
      exit(EXIT_FAILURE);
   }

   /* END OF ARGUMENT HANDLING */

   // the length of socket address
   socklen_t addrlen;

   struct sockaddr_in address, cliaddress;

   // used to set a socket option to allow reusing the socket address
   int reuseValue = 1;
   

   /* SIGNAL HANDLER SIGINT (Interrupt: ctrl+c) */
   if (signal(SIGINT, signalHandler) == SIG_ERR) {
      perror("signal can not be registered");
      return EXIT_FAILURE;
   }

   /* CREATE A SOCKET IPv4, TCP (connection oriented), IP (same as client) */
   if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      perror("Socket error"); // errno set by socket()
      return EXIT_FAILURE;
   }

   /* SET SOCKET OPTIONS socket, level, optname, optvalue, optlen */
   if (setsockopt(create_socket, // specify our socket
                  SOL_SOCKET,    // specify that we are configuring options at the socket level
                  SO_REUSEADDR,  // allow the reuse of a local address even if it's already bound by another socket
                  &reuseValue,   // pointer to the value we want to set for the SO_REUSEADDR option
                  sizeof(reuseValue)) == -1) {
      perror("set socket options - reuseAddr");
      return EXIT_FAILURE;
   }

   if (setsockopt(create_socket,
                  SOL_SOCKET,
                  SO_REUSEPORT,  // allow multiple sockets to bind to the same local address and port number
                  &reuseValue,
                  sizeof(reuseValue)) == -1) {
      perror("set socket options - reusePort");
      return EXIT_FAILURE;
   }

   /* INIT ADDRESS Attention: network byte order => big endian */
   memset(&address, 0, sizeof(address));
   address.sin_family = AF_INET;            // address is for an IPv4 socket
   address.sin_addr.s_addr = INADDR_ANY;    // allows the socket to listen on all network interfaces available on the machine

   try {
      /* checks if port is in suitable range */
      if(stoi(argv[1]) < 1024 || stoi(argv[1]) > 65535) {
         cerr << "Input Port is not in usable port range" << endl;
         exit(EXIT_FAILURE);
     }
     
   } catch (invalid_argument& e1) { /* exits, if input port is NAN */
      cerr <<"Port was not a number" << endl;
      exit(EXIT_FAILURE);
   }

   // set the port number in the 'address' structure
   // stoi() to convert the command-line argument argv[1] to an integer
   // htons() to convert the command-line argument to network byte order (big-endian)
   address.sin_port = htons(stoi(argv[1]));

   /* ASSIGN AN ADDRESS WITH PORT TO SOCKET */
   if (bind(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1) {
      perror("bind error");
      return EXIT_FAILURE;
   }

   /* ALLOW CONNECTION ESTABLISHING Socket, Backlog (= count of waiting connections allowed) */
   if (listen(create_socket, 5) == -1) {
      perror("listen error");
      return EXIT_FAILURE;
   }

   while (!abortRequested)
   {
      /* ignore errors here... because only information message */
      printf("Waiting for connections...\n");
      
      // store the size of the socket address structure
      addrlen = sizeof(struct sockaddr_in);

      /* ACCEPT CONNECTION SETUP blocking, might have an accept-error on ctrl+c */
      if ((new_socket = accept(create_socket,
                               (struct sockaddr *)&cliaddress,
                               &addrlen)) == -1) {
         if (abortRequested) {
            perror("accept error after aborted");
         }
         else {
            perror("accept error");
         }
         break;
      }

      /* START CLIENT ignore printf error handling */
      printf("Client connected from %s:%d...\n",
             inet_ntoa(cliaddress.sin_addr),
             ntohs(cliaddress.sin_port));

      // FORKING SERVER 
      /* child process */
      if((childpid = fork()) == 0) {
         // close the listening socket create_socket because it doesn't need it for accepting further connections
         close(create_socket);

         // retrieve the client's IP address in string format
         clientIP = inet_ntoa(cliaddress.sin_addr);
         clientCommunication(&new_socket, folder); // returnValue can be ignored
         //new_socket = -1;

         close(new_socket);
         exit(EXIT_SUCCESS);
      }

      /* parent process works here */
      // the parent process (the original server process) closes the client socket 
      // this ensures that the parent process doesn't hold on to the client socket and can continue accepting new connections
      close(new_socket);
   }

   // prevent zombie processes by waiting for all child processes to terminate
   while((childpid = waitpid(-1, NULL, WNOHANG))) {
      if((childpid == -1) && (errno != EINTR)) {
         break;
      }
   }

   // free the descriptor
   if (create_socket != -1) {
      if (shutdown(create_socket, SHUT_RDWR) == -1) {
         perror("shutdown create_socket");
      }
      if (close(create_socket) == -1) {
         perror("close create_socket");
      }
      create_socket = -1;
   }

   return EXIT_SUCCESS;
}

/**
 * @brief Responsible for handling communication with a client connected to the server. 
   It performs various tasks, including sending welcome messages, 
   receiving and processing client commands, and responding to those commands.
 * 
 * @param data a pointer to an integer representing the client socket descriptor
 * @param folder given directory where messages should be persisted
*/
void *clientCommunication(void *data, string folder)
{
   // character array used as a buffer to receive and process data from the client
   char buffer[BUF];
   // integer used to store the size of data received from the client
   int size;
   // current_socket holds the client socket descriptor passed as an argument to the function
   int *current_socket = (int *)data;

   /* SEND welcome message */
   strcpy(buffer, "Welcome to the server!\r\nPlease enter your commands...\r\n");
   if (send(*current_socket, buffer, strlen(buffer), 0) == -1) {
      perror("send failed");
      return NULL;
   }

   do {
      /* RECEIVE */
      size = recv(*current_socket, buffer, BUF - 1, 0);
      if (size == -1) {
         if (abortRequested) {
            perror("recv error after aborted");
         }
         else {
            perror("recv error");
         }
         break;
      }

      if (size == 0) {
         printf("Client closed remote socket\n"); // ignore error
         break;
      }

      // remove ugly debug message, because of the sent newline of client
      if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n') {
         size -= 2;
      }
      else if (buffer[size - 1] == '\n') {
         --size;
      }

      // ensure that the string is properly terminated for subsequent string operations
      buffer[size] = '\0';
      
      /* first part of the buffer is the flag/command */
      string flag = getString(buffer);
      string bufferString = removeString(buffer, flag);
      
      string response = ""; /* response to the client upon the given request */

      
      if(strcasecmp(flag.c_str(), "LOGIN") == 0) {
         response = login(bufferString, folder);
      }
      if(successfulLogin) {
         if (strcasecmp(flag.c_str(), "SEND") == 0) {
            response = receiveFromClient(bufferString, folder) ? "OK" : "ERR";
         } 
         else if (strcasecmp(flag.c_str(), "LIST") == 0) {
            response = list(folder);
         }
         else if (strcasecmp(flag.c_str(), "READ") == 0) {
            response = read(bufferString, folder);
         }
         else if (strcasecmp(flag.c_str(), "DEL") == 0) {
            response = deleteMessage(bufferString, folder) ? "OK" : "ERR";
         } 
      }
      
      if (send(*current_socket, response.c_str(), strlen(response.c_str()), 0) == -1)
      {
         perror("send answer failed");
         return NULL;
      }
      

   } while (strcmp(buffer, "quit") != 0 && !abortRequested);

   // close/free the client socket descriptor if not already
   if (*current_socket != -1) {
      if (shutdown(*current_socket, SHUT_RDWR) == -1) {
         perror("shutdown new_socket");
      }
      if (close(*current_socket) == -1) {
         perror("close new_socket");
      }
      *current_socket = -1;
   }

   return NULL;
}

string login(string buffer, string folder)
{
   char buff[1024];
   // copy the contents of the 'buffer' string into the 'buff' character array for LDAP-related operations
   strcpy(buff, buffer.c_str());
   string username = getString(buffer);
   string password = removeString(buffer, username);
   
   // LDAP

   /* prepare username */
   
   char ldapBindUser[256];
   sprintf(ldapBindUser, "uid=%s,ou=people,dc=technikum-wien,dc=at", username.c_str());
   printf("user set to: %s\n", ldapBindUser);

   /* prepare password */
   
   char ldapBindPassword[256];
   strcpy(ldapBindPassword, password.c_str());
   

   int rc = 0; /* return code */

   /* set up LDAP connection */
   
   // LDAP structure
   LDAP *ldapHandle;
   // initialize an LDAP session
   rc = ldap_initialize(&ldapHandle, ldapUri);
   if (rc != LDAP_SUCCESS) {
      fprintf(stderr, "ldap_init failed\n");
      return "ERR";
   }
   printf("Connected to LDAP server %s\n", ldapUri);

   // set version options 
   rc = ldap_set_option(ldapHandle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
   if(rc != LDAP_OPT_SUCCESS) {
      fprintf(stderr, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(rc));
      // close the LDAP connection
      ldap_unbind_ext_s(ldapHandle, NULL, NULL);
      return "ERR";
   }

   /* bind credentials */
   // structure used to hold credentials for LDAP binding
   BerValue bindCredentials;
   // pointer to credential data
   bindCredentials.bv_val = (char *)ldapBindPassword;
   // length of the credential data
   bindCredentials.bv_len = strlen(ldapBindPassword);

   // server's credentials
   BerValue *servercredp; 
   
   // perform a SASL bind operation on the LDAP connection by authenticates using the provided credentials (username and password)
   // specified by ldapBindUser and bindCredentials
   rc = ldap_sasl_bind_s(
       ldapHandle,
       ldapBindUser,
       LDAP_SASL_SIMPLE,
       &bindCredentials,
       NULL,
       NULL,
       &servercredp);

   /* free memory */
   ldap_unbind_ext_s(ldapHandle, NULL, NULL);

   if(clientIP.empty()) {
      cerr << "Couldn't access the client IP address" << endl;
      return "ERR";
   }

   fstream blacklist; /* file stores users with over 3 login attempts within a minute */
   fstream loginLogFile; /* file logs unsuccessful login attempts */
   string line; /* store each line of text read from the blacklist.txt file */

   time_t now = time(0);

   blacklist.open("blacklist.txt", ios::in);

   /* check if username / IP is on the blacklist */
   while(getline(blacklist, line)) {
      // Strings to hold username, IP address, timestamp
      string un, ip, time;
      string delimiter = ";";
      // for-loop to split each line into three parts: username, IP address, and timestamp
      for(int i = 0; i < 3; i++) {
         size_t pos = line.find(delimiter);
         string token = line.substr(0, pos);
         if(i == 0) {
            un = token;
         } else if (i == 1) {
            ip = token;
         } else if (i == 2) {
            time = token;
         }
         line.erase(0, pos + delimiter.length());
      }

      /* it's been less than a minute since the person has been added to the black list */
      if(stoi(time) + 60 > now) {
         // If the username or IP address from the current line of the blacklist file matches the current user's username or clientIP,
         // it means that the current user is on the blacklist and the function returns and error
         if(strcmp(username.c_str(), un.c_str()) == 0 || strcmp(clientIP.c_str(), ip.c_str()) == 0) {
            blacklist.close();
            return "ERR\nYou have too many failed attempts, please try again later.";
         }
      }
   }

   blacklist.close();

   /* username and password are correct & user isn't on the blacklist -> successful login */
   if(rc == LDAP_SUCCESS) {
      sender = username;
      successfulLogin = true;

   /* check if receiver already has a folder for their messages */
   try {
      /* receiver does not have a folder */
      string senderFolder = folder + "/" + sender;
      if(!fs::exists(senderFolder)) { 
         fs::create_directory(senderFolder);
      }
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      return "ERR";
   }
      return "OK";
   }

   /* unsuccessful login */
   /* open loginLogFile for writing username & IP */
   loginLogFile.open("loginLog.txt", ios_base::app);
   if(!loginLogFile) {
      cerr << "loginLog.txt couldn't be opened" << endl;
      return "ERR";
   }

   // write a line to "loginLog.txt"
   loginLogFile << username << ";" << clientIP << ";" << now << endl;

   /* close loginLogFile */
   loginLogFile.close();

   /* open loginLogFile in input mode */
   loginLogFile.open("loginLog.txt", ios::in);

   /* check if this is the IP's/username's third attempt at logging in and set them on the blacklist */
   int attemptCounter = 0;
   while(getline(loginLogFile, line)) {
      // Strings to hold username, IP address, timestamp
      string un, ip, time;
      string delimiter = ";";
      
      for(int i = 0; i < 3; i++) {
         size_t pos = line.find(delimiter);
         string token = line.substr(0, pos);
         if(i == 0) {
            un = token;
         } else if (i == 1) {
            ip = token;
         } else if (i == 2) {
            time = token;
         }
         line.erase(0, pos + delimiter.length());
      }

      if(stoi(time) + 60 > now) {
         if(strcmp(username.c_str(), un.c_str()) == 0 || strcmp(clientIP.c_str(), ip.c_str()) == 0) {
            attemptCounter++;
            if(attemptCounter == 3) {
               blacklist.open("blacklist.txt", ios_base::app); 
               blacklist << username << ";" << clientIP << ";" << now << endl;
               blacklist.close();   
               loginLogFile.close();
               return "ERR\nYou have too many failed attempts, please try again later.";
            }
         }
      }

   }

   blacklist.close();   
   loginLogFile.close();

   return "ERR\nPlease try again.";

}

/**
 * @brief Responsible for SEND requests from the client. First the string gets split up and sender, receiver, subject, message are 
 * saved accordingly. Then the server checks if the receiver already has a directory for their messages: if not then one is set up for them.
 * Messages each get their own file in the receiver's directory and are named 1.txt, 2.txt, etc.
 * 
 * @param buffer string received from client in the form of SEND\nreceiver\nsubject\nmessage
 * @param folder given directory where messages should be persisted
 * @return true = receive worked/ OK, false = something went wrong/ ERR
*/
bool receiveFromClient(string buffer, string folder){

   string receiver, subject, message;
      
   cout << "buffer: " << buffer << endl;
   receiver = getString(buffer); /* get receiver */
   if(!verifyStringLength(receiver, MAX_NAME)) {
      return false;
   }
   buffer = removeString(buffer, receiver);
   
   subject = getString(buffer); /* get subject */
   if(!verifyStringLength(subject, MAX_SUBJ)) {
      return false;
   }
   buffer = removeString(buffer, subject);
   
   message = buffer; /* get message */

   cout << "Receiver: " << receiver << endl << "Subject: " << subject << endl << "Message: " << message << endl;

   string receiverFolder = folder + "/" + receiver;

   /* checks if receiver already has a folder for their messages */
   try {
      /* receiver does not have a folder */
      if(!fs::exists(receiverFolder)) { 
         fs::create_directory(receiverFolder);
      }
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      return false;
   }

   /* save message in a file */
   ofstream outfile; 
   string newFile = ""; /* name of the new file in which the message will be stored */
   string fileNumber = ""; /* make sure to get the highest file number */
   
   
   fileNumber += getHighestFileNumber(receiverFolder);
   if(strcasecmp(fileNumber.c_str(), "ERR") == 0) {
      return false;
   }
   newFile += receiverFolder + "/" + fileNumber + ".txt";

   // Lock the file
    int fd = open(newFile.c_str(), O_WRONLY | O_CREAT, 0666);
    if (fd == -1) {
        cerr << "Error opening file" << endl;
        return false;
    }

    if (!lockFile(fd)) {
        close(fd);
        return false;
    }
   
   /* write sender(\n)receiver(\n)subject(\n)message into file */
   outfile.open(newFile.c_str()); 
   if(!outfile){
      cerr << "newFile couldn't be opened" << endl;
      unlockFile(fd);
      close(fd);
      return false;
   }
   outfile << sender << endl << receiver << endl << subject << endl << message;
   outfile.close(); 

   // Unlock the file
   unlockFile(fd);
   close(fd);

   return true;
}

/**
 * @brief Responsible for LIST request from the client. Opens username's directory,
 * iterates over messages in the directory and gets the subjects from the messages
 * 
 * @param folder given directory where messages should be persisted
 * @return "ERR" if user/file not found, otherwise: "OK\n<numOfFiles>\n<subject1>\n<subject2>...\n<subjectn>" 
 */
string list(string folder)
{

   if(!verifyStringLength(sender, MAX_NAME)) {
      return "ERR";
   }
   string userFolder = folder + "/" + sender; /* get username's folder */
   
   try {
      if(!fs::exists(userFolder)){ /* username doesn't have a folder -> return 0 */
         cout << userFolder << "does not exist" << endl;
         return to_string(0);
      }
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      return "ERR";
   }
   

   const fs::path path = userFolder; 
   string helperString; /* return string */

   helperString += to_string(getNumOfFiles(userFolder));

   try{
      for (const auto& entry : fs::directory_iterator(path)) {
         const auto filenameStr = entry.path().filename().string(); /* get name of file */
         helperString += SEPARATOR;
         
         /* open the file and get the subject */
         string line;
         string subject; 

         // Lock the file
        int fd = open((userFolder + "/" + filenameStr).c_str(), O_RDONLY);
        if (fd == -1) {
            cerr << "Error opening file" << endl;
            continue;
        }

        if (!lockFile(fd)) {
            close(fd);
            continue;
        }

         /* open the file named "file" */
         ifstream file(userFolder + "/" + filenameStr);
         /* keep track of the lines read */
         int counter = 0;

         if(file.is_open()) {
            while(getline(file, line)){
               ++counter;
               if(counter == 3) { /* subject is in the third line of every file */
                  subject = line;
               }
            }
         } else {
            cerr << strerror(errno);
            cout << "file.is_open() error" << endl;
            unlockFile(fd);
            close(fd);
            return "ERR";
         }

         file.close();
         unlockFile(fd);
         close(fd);
         helperString += subject;

      }
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      return "ERR";
   }
   cout << "Helper string: " << helperString << endl;
   string returnString = "OK\n";
   returnString = returnString + helperString;
   cout << returnString << endl;
   return returnString;
}

/**
 * @brief Responsible for READ requests from client. Parses buffer string, opens messageNumber.txt in username's directory
 * and returns the message in messageNumber.txt
 * 
 * @param buffer string received from client in the form of "READ\n<messageNumber>"
 * @param folder given directory where messages should be persisted
 * @return string "error" if file with messageNumber.txt isn't in the users directory, otherwise returns message
 */
string read(string buffer, string folder)
{
   string messageNumber;

   messageNumber = buffer;
   cout << "read, message number: " << messageNumber << endl;
   string usernameFolder = folder + "/" + sender;
   string searchedFileDirectory;
   int counter = 0;
   for (fs::directory_entry e : fs::directory_iterator(usernameFolder)){
      counter++;
      if(counter > stoi(buffer)){
         return "ERR";
      }
      // the desired message number has been found
      if(counter == stoi(buffer)){
         searchedFileDirectory = e.path();
         break;
      }
   }

   try{
      if(!fs::exists(searchedFileDirectory)){
         cout << "file does not exist" << endl;
         return "ERR";
      }
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      return "ERR";
   }

   string message; /* message to return to client */
   string line; /* line buffer for file */

   int fd = open(searchedFileDirectory.c_str(), O_RDONLY);
    if (fd == -1) {
      cerr << "Error opening file" << endl;
      return "ERR";
    }

   if (!lockFile(fd)) {
      close(fd);
      return "ERR";
   }

   ifstream file(searchedFileDirectory); /* copy entire content of searched File into message */
   if(file.is_open()) {
      while(!file.eof()) { 
         getline(file, line);
         message += line;
         message += "\n";
      }
   } else {
      cerr << "couldn't open file" << endl;
      unlockFile(fd);
      close(fd);
      return "ERR";
   }
   file.close();
   unlockFile(fd);
   close(fd);
   
   return "OK\n" + message;

}

/**
 * @brief Responsible for the DEL request from the client. Searches for the file in the username's directory and deletes it
 * 
 * @param buffer string received from client in the form of "DEL\n<messageNumber>"
 * @param folder given directory where messages should be persisted
 * @return true messageNumber.txt was found and deleted
 * @return false messageNumber.txt doesn't exist/ can't be deleted
 */
bool deleteMessage(string buffer, string folder)
{

   string messageNumber;

   messageNumber = buffer;
   string usernameFolder = folder + "/" + sender;
   string searchedFileDirectory;
   int counter = 0;
   for (fs::directory_entry e : fs::directory_iterator(usernameFolder)){
      counter++;
      // the requested message number is greater than the number of messages in the folder
      if(counter > stoi(buffer)){
         return "ERR";
      }
      // the desired message number has been found
      if(counter == stoi(buffer)){
         searchedFileDirectory = e.path();
         break;
      }
   }

   int fd = open(searchedFileDirectory.c_str(), O_WRONLY);
   if (fd == -1) {
      cerr << "Error opening file" << endl;
      return false;
   }

   if (!lockFile(fd)) {
      close(fd);
      return false;
   }

   try {
      if(!fs::exists(searchedFileDirectory)) {
         unlockFile(fd);
         close(fd);
         return false;
      }
      fs::remove(searchedFileDirectory);
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      unlockFile(fd);
      close(fd);
      return false;
   }
   unlockFile(fd);
   close(fd);
   return true;
}

/**
 * @brief signal handler, safely closes all resources after SIGINT
 * 
 * @param sig SIGINT
 */
void signalHandler(int sig)
{
   // check whether the signal received is SIGINT, which corresponds to the interruption signal typically generated by pressing Ctrl+C in the terminal
   if (sig == SIGINT) {
      printf("abort Requested... \n"); // ignore error
      abortRequested = 1;
      if (new_socket != -1) {
         // With shutdown() one can initiate normal TCP close sequence for both reading and writing (SHUT_RDWR)
         if (shutdown(new_socket, SHUT_RDWR) == -1) {
            perror("shutdown new_socket");
         }
         // release the socket descriptor and free up the associated resources
         if (close(new_socket) == -1) {
            perror("close new_socket");
         }
         new_socket = -1;
      }

      if (create_socket != -1) {
         if (shutdown(create_socket, SHUT_RDWR) == -1) {
            perror("shutdown create_socket");
         }
         if (close(create_socket) == -1) {
            perror("close create_socket");
         }
         create_socket = -1;
      }
   }
   else
   {
      exit(sig);
   }
}

/**
 * @brief prints correct usage of the program
 */
void printUsage(void)
{
    printf("Incorrect usage. Start the server using: \"./twmailer-server <port> <mail-spool-directoryname>\"\n");
    exit(EXIT_FAILURE);
}

/**
 * @brief Get the number of existent files in the given folder
 * 
 * @param folder user directory where files(messages) are stored
 * @return int - number of files in the given folder
 */
int getNumOfFiles(string folder)
{
   int count = 0;
   try {
      fs::path path = folder;

      for (auto& p : fs::directory_iterator(path)) {
         count++;
      }
   } catch (fs::filesystem_error& error) {
      cerr << error.what() << endl;
      exit(EXIT_FAILURE);
   }
   return count; 
}

/**
 * @brief Read the number of files that the user has received from numOfFiles.txt that is in the user's
 * directory. Then update the number to numOfFiles + 1 since a new message is being added and this
 * method is only called in the receive method. This way repeats due to deletes should be impossible.
 * 
 * @param folder user's directory where messages are stored
 * @return string numOfFiles if okay, ERR if something went wrong
 */
string getHighestFileNumber(string folder)
{
   fs::directory_entry e;
   for(int i = 1; ; i++){
      e = fs::directory_entry(folder + "/" + to_string(i) + ".txt");
      if(!e.exists()){
         return to_string(i);
      }

   }
}

/**
 * @brief Get the string until the delimiter ";"
 * 
 * @param buffer string with the form "%s1%;..."
 * @return string until the delimiter ";"
 */
string getString(string buffer)
{
   string helper;
   size_t pos = buffer.find(SEPARATOR);
   helper = buffer.substr(0, pos);
   return helper;
}

/**
 * @brief Used to update buffer and change it from the form "%s1%;%s2%" to the form "%s2%"
 * 
 * @param buffer string with the form "%s1%;%s2%"
 * @param s1 string with the form "%s1%;"
 * @return string buffer without "%s1%;"
 */
string removeString(string buffer, string s1)
{
   return buffer.erase(0, s1.length() + 1);
}

/**
 * @brief verify that the given string isn't longer than maxStringLength
 * @return true string is shorter than maxStringLength
 * @return false string is longer than maxStringLength
 */
bool verifyStringLength(string string, int maxStringLength)
{
   return (string.length() <= (unsigned)maxStringLength);
}

bool lockFile(int fd) {
   if(flock(fd, LOCK_SH | LOCK_NB)) {  /* non-blocking */
      if(errno == EWOULDBLOCK) { /* File is locked, let's wait */
         if(flock(fd, LOCK_SH) == -1 ){ /* attempts to acquire a shared lock again */
            cerr << "Failed to lock the file " << endl;
            close(fd);
            return false;
         }
      } else {  /* where flock failed for reasons other than the file being already locked */
         cerr << "Failed to lock the file " << endl;
         close(fd);
         return false;
      }
   }
   return true;
}

bool unlockFile(int fd) {
   if(flock(fd, LOCK_UN) == -1) {
      cerr << "Failed to unlock the file!" << endl;
      close(fd);
      return false;
   }
   close(fd);
   return true;
}

