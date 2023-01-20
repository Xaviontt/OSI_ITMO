#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
  unsigned int pid;
  FILE *file = fopen("/sys/kernel/debug/lab2/filetocnange", "r+");
  if (file == NULL) {
    printf("Возникли технические неполадки\n");
    return 0;
  }
  if (sscanf(argv[1], "%x", &pid)) {
    char *buffer[BUFFER_SIZE];
    fprintf(file, "pid: %x", pid);
    while (!feof(file)) {
      char *result = fgets(buffer, BUFFER_SIZE, file);
      printf(result);
    }
  } else {
      printf("Что-то пошло не так");	 
  }
  fclose(file);
  return 0;
}
