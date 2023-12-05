#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#define PORT 6543
#define MAX_SUBJ 80;
#define BUF 1024;
#define MAX_NAME 8;
#define SEPARATOR "\n";
#define CORRECT_SERVER_RESPONSE "OK";

using namespace std;
bool loginSuccessful = false;
string login_username;

//functions and variables in auxillary are used in namespace client_functions
namespace auxilliary{
    string separator = SEPARATOR;
    //calculate max. Message size
    unsigned int max_name = MAX_NAME;
    unsigned int max_subj = MAX_SUBJ;
    unsigned int buffer = BUF;
    unsigned int max_msg = buffer - max_subj-(2*max_name)-1;

    //checks is input name is viable
    bool isNameOk(string name){
        if(name.length() > max_name){
            cout<<"Given name is to long\n";
            return false;
        }
        if(name.length() <= 0){
            cout<<"Entered empty name\n";
            return false;
        }
        //checks for illegal characters in name
        for(char c : name){
            if (!std::isalpha(c) && !std::isdigit(c)){
                cout << "Given name contains illegal characters\n";
                return false;
            }
        }
        return true;

    }
    //checks if subject is not longer than max_subj characters
    bool isSubjectOk(string subject){
        if(subject.length() > max_subj){
            printf("Subject may only be up to %i characters long;\nInput Subject-length was: %li\n", max_subj, subject.length());
            return false;
        }
        return true;
    }

    //checks if message is not longer than max_msg characters
    bool isMessageOk(string message){
        if(message.length() > max_msg){
            printf("Message may only be up to %i characters long;\nInput Message-length was: %li\n", max_msg, message.length());
            return false;
        }
        return true;
    }
    
    //checks if number is neither empty nor contains non digits
    bool isNumberOk(string number){
        if(number.length() <= 0){
            cout << "No number was put in\n";
            return false;
        }
        for(char c : number){
            if (!std::isdigit(c)){
                cout<<"Given String contains non-digit characters\n";
                return false;
            }
        }
        return true;
    }
}

namespace client_functions {
    using namespace auxilliary;

    /**
     * @brief login to make the program accessible to the client, credentials are authorized in the server
     * 
     * @return string in the form of "LOGIN\n<username>\n<password>" for the server
     */
    string login() 
    {
        string username, password, package;

        do {
            cout << "<Username>: ";
            getline(cin, username);

        } while(!isNameOk(username));

        password = getpass("<Password>: ");

        package = "LOGIN\n" + username + '\n' + password;
        login_username = username;
        
        return package;
    }

    /**
     * @brief creates a package, that sends the server a message
     * @return a string in the format "SEND\n$receiver\n$subject\n$message"
     */
    string send()
    {
        string receiver, subject, message, hs, package;
        do {
            cout << "<Receiver>: ";
            getline(cin, receiver);
        } while(!isNameOk(receiver));
        do {
            cout << "<Subject>: ";
            getline(cin, subject);
        } while(!isSubjectOk(subject));
        do {
            cout << "<Message>:\n";
            do {
                hs = "";
                getline(cin, hs);
                if(hs!="."){
                    message += hs;
                    message += "\n";
                }
            } while(hs != ".");
        } while(!isMessageOk(message));

        package = "SEND" + separator + receiver 
                    + separator + subject + separator + message;
        return package;
    }
    /**
     * @brief creates package, that asks the server for all messages of a user
     * @return a string in the format "LIST"
     */
    string list(){
        string package = "LIST" + separator;
        return package;
    }

    /**
     * @brief creates package, that asks the server for a specified message of user
     * @return a string in the format "READ\n<message number>"
     */
    string read()
    {
        string msg_number, package;
        do{
            cout << "<Message-Number>: ";
            getline(cin, msg_number);
        } while(!isNumberOk(msg_number));

        package = "READ" + separator + msg_number;
        return package;

    }

    /**
     * @brief creates package, that asks the server to delete a specified message of a user
     * @return a string in the format "DEL\n<$msg_number>"
     */
    string del()
    {
        string package, msg_number;
        do {
            cout << "<Message-Number>: ";
            getline(cin, msg_number);
        } while(!isNumberOk(msg_number));
        
        package = "DEL" + separator + msg_number;
        return package;
    }

    /**
     * @brief prints login response
     * 
     * @return true login successful/needs another try
     * @return false something went wrong in the server
     */
    bool printLogin(string s) 
    {
        char buffer[1024];
        strcpy(buffer, s.c_str());
        string hs = strtok(buffer, ";");

         if(strcmp(hs.c_str(), "OK") == 0) {
            cout << "<< Login Successful" << endl;
            return true;
        } else if(strcmp(hs.c_str(), "ERR") == 0) {
            cerr << "A server-site error occured\n";
            return false;
        } 

        cout << buffer << endl;
        return true;
    }
    
    /**
     * @brief displays a subject list
     * @param s string of format "OK;$NrOfSubjects;$Subject1;$Subject2;...;$SubjectN"
     * @return returns true on sucess or false on server-site error
     **/
    bool printList(string s)
    {
        //cuts OK from string
        char buffer[1024];
        strcpy(buffer, s.c_str());
        string hs = strtok(buffer, "\n");
        //prints Subject list
        if(strcmp(hs.c_str(), "OK") == 0) {
            hs = strtok(NULL,"\n");
            cout << "<< " << hs << endl;
            for(int i = 1; i <= stoi(hs); i++) {
                printf("<< <Message-Nr.>%i <Subject> %s\n", i, strtok(NULL,"\n"));
            }
            return true;
        }
        cerr << "A server-site error occured\n";
        return false;
    }

    /**
     * @brief displays a message
     * @param s string of format "OK;$Message"
     * @return returns true on sucess or false on server-site error
     **/
    bool printMessage(string s){
        //cuts OK from string
        char buffer[1024];
        strcpy(buffer, s.c_str());
        string hs = strtok(buffer, "\n");
        cout << "<< " << hs << "\n";
        //prints Message
        if(strcmp(hs.c_str(),"OK")==0){
            cout << "<Sender> " << strtok(NULL, "\n") << "\n";
            cout << "<Receiver> " << strtok(NULL, "\n") << "\n";
            cout << "<Subject> " << strtok(NULL,"\n") << "\n";
            cout << "<Message>\n" << strtok(NULL,"") << "\n";
            return true;;
        }
        cout << "<< ERR" << endl;
        cerr <<"A server-side error occured\n";
        return false;
    }

    /**
     * @brief Prints server replies for the SEND/DEL command
     * @param s string of format "OK" or "ERR"
     * @return true on sucess or false on server-site error
     */
    bool printReply(string s){
        char buffer[1024];
        strcpy(buffer, s.c_str());

        //prints Message
        if(strcmp(buffer, "OK") == 0) {
            cout << "<< OK" << endl;
            return true;;
        }
        cout << "<< ERR" << endl;
        cerr << "A server-side error occured\n";
        return false;
    }


}

using namespace client_functions;

int main(int argc, char **argv){

    const size_t BUFFER_SIZE = BUF;
    int client_socket;
    char buffer[buffer];
    struct sockaddr_in address;
    int size;
    bool isEntryCorrect;
    bool isLogin = false;
    bool isSend = false;
    bool isList = false;
    bool isMessage = false;
    bool isDel = false;
    string hs;

    if((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error when creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    //ARGUMENT HANDLING
    if(argc != 3) {
        cout << "Incorrect Usage. Start the Client using ./twmailer-client $Ip-Adress $Port\n";
        exit(EXIT_FAILURE);
    }
    else{
        //checks if given ip-address is viable
        if(inet_pton(AF_INET, argv[1], &address.sin_addr) == 0) {
            cout << "Input IP-address is not valid\n";
            exit(EXIT_FAILURE);
        }
        try {
            //checks if port is in suitable range
            if(stoi(argv[2]) < 1024 || stoi(argv[2]) > 65535){
            cout << "Input Port is not in usable port range\n";
            exit(EXIT_FAILURE);
        }
        //exits, if input port is NAN
        } catch(invalid_argument&) {
            cout << "Port was not a number\n";
            exit(EXIT_FAILURE);
        }
        address.sin_port = htons(stoi(argv[2]));

    }

    if(connect(client_socket, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("Server could not be reached");
        exit(EXIT_FAILURE);
    }

    printf("Connection with server (%s) established\n",
        inet_ntoa(address.sin_addr));

    size = recv(client_socket, buffer, BUFFER_SIZE-1, 0);
    switch(size){
        case -1:
            perror("recv error");
            break;
        case 0:
            printf("Server closed remote socket\n");
            break;
        default:
            buffer[size] = '\0';
            printf("%s", buffer);
    }

    do {
        printf(">> ");
        if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
            int size = strlen(buffer);
            // remove new-line signs from string at the end
            if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n'){
                size -= 2;
                buffer[size] = 0;
            }
            else if (buffer[size - 1] == '\n'){
                --size;
                buffer[size] = 0;
            }
            if(strcasecmp(buffer, "quit") == 0){
                if (client_socket != -1){
                    if (shutdown(client_socket, SHUT_RDWR) == -1){

                        perror("shutdown create_socket"); 
                    }
                    if (close(client_socket) == -1){

                        perror("close create_socket");
                    }
                    client_socket = -1;
                }

                return EXIT_SUCCESS;

            }

            if(strcasecmp(buffer, "login") == 0) {
                if(loginSuccessful) {
                    cout << "Please log out of your current user before trying to log in to a new one!" << endl;
                    continue;
                }  

                hs = login();
                isEntryCorrect = true;
                isLogin = true;

            }
            
            /* Following commands are only allowed if user is already logged in */
            if(loginSuccessful) {
                //checks for any suitable commands
                if(strcasecmp(buffer,"send") == 0){
                    hs = send();
                    isEntryCorrect = true;
                    isSend = true;
                }
                else if(strcasecmp(buffer,"list") == 0){
                    hs = list();
                    isEntryCorrect = true;
                    isList = true;
                }
                else if(strcasecmp(buffer,"read") == 0){
                    hs = read();
                    isEntryCorrect = true;
                    isMessage = true;
                }
                else if(strcasecmp(buffer, "del") == 0){
                    hs = del();
                    isEntryCorrect = true;
                    isDel = true;
                }
                else {
                    cout << ">>Command not found\n";
                    isEntryCorrect = false;
                }
            } else {
                if(!isLogin) {
                    cout << "You need to login before you can use the mailer!" << endl;
                    isEntryCorrect = false;
                }
                
            }

            //if a suitable command is found
            if(isEntryCorrect){
                //copies package from hs into buffer
                strcpy(buffer,hs.c_str());
                size = strlen(buffer);
                if(send(client_socket, buffer, size, 0) == -1){
                    perror("An error while sending data occured");
                    break;
                }
                //waits for response
                size = recv(client_socket, buffer, BUFFER_SIZE-1, 0);
                if (size == -1){
                    perror("recv error");
                    break;
                }
                else if (size == 0){
                    printf("Server closed remote socket\n"); // ignore error
                    break;
                }
                else{
                    //either just prints out OK or ERR, or displays a subject list / Message
                    buffer[size] = '\0';
                    if(isLogin) {
                        if(!printLogin(buffer)){
                            fprintf(stderr, "<< Server error occured, abort\n");
                            exit(EXIT_FAILURE);
                        }
                        if(strcmp(buffer, "OK") == 0) {
                            loginSuccessful = true;
                        }
                        isLogin = false;
                    }
                    else if(isList){
                        if(!printList(buffer)){
                            fprintf(stderr, "<< Server error occured, abort\n");
                            exit(EXIT_FAILURE);
                        }
                        isList = false;
                    }
                    else if(isMessage){
                        if(!printMessage(buffer)){
                            fprintf(stderr, "<< Server error occured, abort\n");
                            exit(EXIT_FAILURE);
                        }
                        isMessage = false;
                    }
                    else if(isDel || isSend) {
                        if(!printReply(buffer)){
                            fprintf(stderr, "<< Server error occured, abort\n");
                            exit(EXIT_FAILURE);
                        }
                        isDel = false;
                        isSend = false;
                    }
                }
            }         
        }
    } while (true);
}