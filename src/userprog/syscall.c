#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

//edited
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  validate_address((const void*)f->esp);
  int syscall_number = *(int*) f->esp;

  int* args = (int*)f->esp + 1;
  for (int i = 0; i < 3; i++)
   validate_address(args + i);
  
  switch (syscall_number)
  {
  case SYS_HALT:
  {
    halt();
    break;
  }
  case SYS_EXIT: 
  {  
    exit(args[0]);
    f->eax = args[0];
    break;
  } 
  case SYS_WAIT:
  {
    f->eax = process_wait(args[0]);
    break;
  }
  case SYS_EXEC:
  {
    validate_address((const char*) args[0]);

    f->eax = exec((const char*) args[0]);
    break;
  }
  case SYS_CREATE:
  {
    validate_address((const char*)args[0]);
    f->eax = filesys_create((const char*)args[0], (unsigned)args[1]);
    break;
  }
  case SYS_REMOVE:
  {
    validate_address((const char*)args[0]);
    f->eax = filesys_remove((const char*)args[0]);
    break;
  }
  case SYS_OPEN:
  {
    validate_address((const char*)args[0]);
    f->eax = open((const char *) args[0]);
    break;
  }
  case SYS_CLOSE:
  {
    close(args[0]);
    break;
  }
  case SYS_FILESIZE:
  {
    f->eax = filesize(args[0]);
    break;
  }
  case SYS_READ:
  {
    validate_address((const void*)args[1]);
    validate_address((const void*)(args[1] + args[2]));//size

    f->eax = read(args[0], (void *)args[1], (unsigned)args[2]);
    break;
  }
  case SYS_WRITE: 
  {
    validate_address((const void*)args[1]);//str
    validate_address((const void*)(args[1] + args[2]));//size

    f->eax =  write(args[0], (void*)args[1], (unsigned)args[2]);
    break;
  }
  default:
  {
    printf ("unknown system call!\n");
    exit(-1);
    break;
  }
  }
}

void halt(void){
  shutdown_power_off();
}

void validate_address(const void* addr)
{
  if( !(is_user_vaddr(addr) && 
      pagedir_get_page(thread_current()->pagedir, addr)))
   exit(-1);
}

void exit(int status)
{
  struct thread *t = thread_current();
  t->exit_code = status;

  while(!list_empty(&thread_current ()->file_list))
  {
    struct owned_file *tmp_file = list_entry(list_begin(&t->file_list), 
      struct owned_file, file_elem);
    close(tmp_file->fd);
  }

  thread_exit();
}

void close(int fd)
{
  if(fd <= 1)
    return;
  struct thread* cur = thread_current();
  for (struct list_elem *e = list_begin (&cur->file_list);
   e != list_end (&cur->file_list); e = list_next (e))
  {
    struct owned_file *tmp_file = list_entry (e, struct owned_file, file_elem);
    if(tmp_file->fd == fd)
    {
      file_close(tmp_file->file);
      list_remove(&tmp_file->file_elem);
      free(tmp_file);
      return;
    }
  }
}

tid_t exec(const char *cmd_line){

  char* name = (char*)malloc(25);
  char* saveptr;
  strlcpy(name, cmd_line, 25);
  name = strtok_r(name, " ", &saveptr);
  struct file* file = filesys_open(name);

  if(!file)
    return -1;

  file_close(file);
  return process_execute(cmd_line);
}


int open(const char * file_){
  struct file* file = filesys_open(file_);
  if(!file) 
    return -1;

  struct thread* t = thread_current();
  struct owned_file* new_file = (struct owned_file*) malloc(sizeof(struct owned_file));
  new_file->fd = t->fd_count++;
  new_file->file = file;
  list_push_back(&t->file_list, &new_file->file_elem);
  return new_file->fd;
}

unsigned int filesize(int fd)
{
  struct thread* cur = thread_current();
  for (struct list_elem *e = list_begin (&cur->file_list);
   e != list_end (&cur->file_list); e = list_next (e))
  {
    struct owned_file *tmp_file = list_entry (e, struct owned_file, file_elem);
    if(tmp_file->fd == fd)
      return file_length(tmp_file->file);
  }
  return 0;
}

int read (int fd, void *buffer, unsigned size){
  if(fd == 0) //stdin
  {
    for(int i = 0; i < size; i++)
      buffer = input_getc();
    return size;
  }  
  struct thread* cur = thread_current();
  for (struct list_elem *e = list_begin (&cur->file_list);
   e != list_end (&cur->file_list); e = list_next (e))
  {
    struct owned_file *tmp_file = list_entry (e, struct owned_file, file_elem);
    if(tmp_file->fd == fd)
      return file_read(tmp_file->file, buffer, size);
  }
}


int write (int fd, const void *buffer, unsigned size){
  if(fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  struct thread* cur = thread_current();
  for (struct list_elem *e = list_begin (&cur->file_list); 
    e != list_end (&cur->file_list); e = list_next (e))
  {
    struct owned_file *tmp_file = list_entry (e, struct owned_file, file_elem);
    if(tmp_file->fd == fd)
      return file_write(tmp_file->file, buffer, size);
  }
}

// enum 
//   {
//     /* Projects 2 and later. */
//     SYS_HALT,                   /* Halt the operating system. */
//     SYS_EXIT,                   /* Terminate this process. */
//     SYS_EXEC,                   /* Start another process. */
//     SYS_WAIT,                   /* Wait for a child process to die. */
//     SYS_CREATE,                 /* Create a file. */
//     SYS_REMOVE,                 /* Delete a file. */
//     SYS_OPEN,                   /* Open a file. */
//     SYS_FILESIZE,               /* Obtain a file's size. */
//     SYS_READ,                   /* Read from a file. */
//     SYS_WRITE,                  /* Write to a file. */
//     SYS_CLOSE,    