#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void validate_address(const void* t);
void exit(int status);
void close(int fd);
unsigned int filesize(int fd);
int read (int fd, void *buffer, unsigned size);

#endif /* userprog/syscall.h */
