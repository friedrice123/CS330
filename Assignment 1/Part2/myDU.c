#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

int main(int argc, char *argv[]) {
    // We take the arguments from the command line
    if (argc != 2) {
        printf("Unable to execute");
        exit(-1);
    }

    const char *path = argv[1];
    // Creating the parent Directory
    DIR *dir;
    struct dirent *subentry;
    struct stat st;
    // Storing the initial size of the parent directory
    if (stat(path, &st) == -1) {
        printf("Unable to execute");
        exit(-1);
    }
    off_t size=st.st_size;
    long totalSize = size;
    // Opening the directory
    if ((dir = opendir(path)) == NULL) {
        printf("Unable to execute");
        exit(-1);
    }

    //Read the contents of the directory
	while ((subentry = readdir(dir)) != NULL){
        // We create the full relative path with respect to the parent directory for each entry of the directory
        char subentryPath[1024];
        snprintf(subentryPath, sizeof(subentryPath), "%s/%s", path, subentry->d_name);
        if (strcmp(subentry->d_name, ".") == 0 || strcmp(subentry->d_name, "..") == 0) continue;

        // Calculate the size of the sub entry
        if (stat(subentryPath, &st) == -1) {
            printf("Unable to execute");
            exit(-1);
        }
        // If the given entry is not a directory, i.e. it is a regular file or symbolic link etc.
        if (!S_ISDIR(st.st_mode)) {
            off_t size=st.st_size;
            totalSize+=size;
        }
        // If we have a directory
        else{
            // Creating a pipe for redirection of child's output to parent's input
            int pipe_fd[2];
            if (pipe(pipe_fd) == -1) {
                printf("Unable to execute");
                exit(-1);
            }
            // Creating a child process and a parent process using fork
            pid_t child_pid = fork();
            if (child_pid == -1) {
                printf("Unable to execute");
                exit(-1);
            }
            // Child process
            if (child_pid == 0) {
                if(dup2(pipe_fd[1], STDOUT_FILENO)==-1){ // Redirect stdout
                    printf("Unable to execute");
                    exit(-1);
                } 
                // Execute the program again for the child subdirectory
                execlp("./myDU", "./myDU", subentryPath, (char *)NULL); // Execute myDU recursively
                printf("Unable to execute");
                exit(-1);
            }
            // Parent process
            else {
                close(pipe_fd[1]); // Close write end of the pipe
                // Creating a buffer for the input stream and adding the final size obtained by the child to the total size
                char buffer[32];
                ssize_t bytesRead;
                while ((bytesRead = read(pipe_fd[0], buffer, sizeof(buffer))) > 0) {
                    totalSize += atoll(buffer);
                }
                close(pipe_fd[0]); // Close read end of the pipe
            }
        }
    }
    // Close directory
    closedir(dir);
    // Printing the total size to STDOUT
    printf("%ld\n",totalSize);
	return 0;
}
