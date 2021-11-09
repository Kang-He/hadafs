#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

/*
 * print unfinished file if memcache xlator flush to disk error 
 */
void usage(const char *prog)
{
        fprintf( stdout,"Usage: %s [LOGFILE]\n", prog);
}

int main(int argc, char* argv[]){
	int fd;
	void *start = NULL;
	char *p = NULL;
        char *q = NULL;
	//char path[1024];
	//char towrite[32];
	int size1 = 1024;
	int size2 = 32;
	int i;
	struct stat st;
	char *path = malloc(1024);
	char *towrite = malloc(32);
	if (argc != 2){
		usage(argv[0]);
		exit(1);
	}
	stat(argv[1], &st);
	if (st.st_size != 17301504){
		printf("wrong logfile, please check the volume file to find memcache logfile\n");
		exit(1);
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
                perror("open failed");
                exit(1);
        }
	start = mmap(NULL, 17301504, PROT_READ, MAP_SHARED, fd, 0);
	if (start == MAP_FAILED) {
        	perror("mmap");
                exit(1);
	}
	p = start;
	close(fd);
	for (i=0; i<16384; i++){
		if(strncmp(p, "/", 1) == 0){
			q=p;
			memcpy(path, q, size1);
			strcat(path, "\0");
			q = q+size1;
			memcpy(towrite, q, size2);
			strcat(towrite, "\0");
			printf("file: %s, size left to flush: %s\n", path, towrite);
		}
		p=p+size1+size2;
	}
	
}
