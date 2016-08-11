#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <termios.h>
#include <unistd.h>

int getch() { // http://www.gnu.org/savannah-checkouts/gnu/libc/manual/html_node/getpass.html
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}

char * getline1(void) {
    char * line = malloc(32), * linep = line;
    size_t lenmax = 32, len = lenmax;
    int c;

    if(line == NULL)
        return NULL;

    for(;;) {
        c = getch();
        if(c == EOF)
            break;

        if(--len == 0) {
            len = lenmax;
            char * linen = realloc(linep, lenmax *= 2);

            if(linen == NULL) {
                free(linep);
                return NULL;
            }
            line = linen + (line - linep);
            linep = linen;
        }

        if((*line++ = c) == '\n')
            break;
    }
    *line = '\0';
    return linep;
}

int main()
{
    char *path = "/tmp/tresorsgxsetkey";
    int fd;

    char *buf = {0};
    buf = getline1();
 
    fd = open(path, O_WRONLY);
    write(fd, buf, strlen(buf));
    printf("Set key of len: %lu\n", strlen(buf));
    memset(buf, 0, 32); // clear msg text

    close(fd);    
    free(buf);

    return 0;
}
