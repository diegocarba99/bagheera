#include <unistd.h>
 
int main(void) {

	int a = 2;
	int b = 1;
	int c = 3;
	int d = 4;
	if (a < b) 
		d = a;
	else
		c = b;

  	char *binaryPath = "/bin/ls";
  	char *args[] = {binaryPath, NULL};
 
  	execv(binaryPath, args);
 
  return 0;
}