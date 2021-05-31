#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <dirent.h>



#define SOCK_PATH "/usr/antivirus/socket"

int main(int argc, char* argv[])
{
    int s, t, len;
    struct sockaddr_un remote;
    char str[PATH_MAX];

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    printf("Trying to connect...\n");

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, SOCK_PATH, sizeof(SOCK_PATH));
    len = (int)strlen(remote.sun_path) + (int)sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        perror("connect");
        exit(1);
    }
    printf("Connected.\n");

    int c;

    //get input
    while(printf("\n> "), fgets(str, PATH_MAX, stdin), !feof(stdin)) {
        if(memcmp(str, "exit", 4)==0) {
            break;
        }
        if (send(s, str, strlen(str), 0) == -1) {
            perror("send");
            exit(1);
        }

        //clear input buffer
        if(!strchr(str, '\n')) {
            while (((c = getchar()) != EOF) && (c != '\n')) /* void */;
            if (c == EOF){
                perror("input error");
                exit(1);
            }
        }

        //clear str buffer
        memset(str,0,PATH_MAX);

        //wait on response
        printf("av> ");
        for(;;) {
            if ((t = recv(s, str, PATH_MAX, 0)) > 0) {
                printf("%s", str);
                if(str[PATH_MAX-1]=='\0')
                    break;
            } else {
                if (t < 0) perror("recv");
                else printf("Server closed connection\n");
                exit(1);
            }
        }
    }

    close(s);
    return 0;
}
