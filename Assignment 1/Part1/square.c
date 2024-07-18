#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	// Calculate the required value
	unsigned long num=atoi(argv[argc-1]) * atoi(argv[argc-1]);
	// If the arguments are lesser than 2, we cannot perform the operations
	if(argc<2){
		printf("Unable to execute");
		exit(-1);
	}
	// If number of arguments is 2 then we have to perform a single operation only
	else if(argc == 2){  
       printf("%ld\n",num);
    } 
	else{
		// We create a new list of arguments which excludes the first executable
		char* newargv[argc];
		for(unsigned long i=1;i<argc;i++){
			newargv[i-1]=argv[i];
		}
		sprintf(newargv[argc-2], "%ld", num);
		newargv[argc - 1] = NULL;
		unsigned long len=sizeof(newargv[0])/sizeof(char);
		// Making the command for the execution of the second executable
		char s[len+2];
		s[0]='.';
		s[1]='/';
		for(int i=2;i<len+2;i++){
			s[i]=newargv[0][i-2];
		}
		newargv[0]=s;
		// Calling exec on the new arguments with one less executable that has been taken care of
		execv(newargv[0],newargv);
		printf("Unable to execute");
		exit(-1);
	}
	return 0;
}
