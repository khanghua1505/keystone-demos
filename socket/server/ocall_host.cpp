/* Copyright (c) 2017-2018, The Regents of the University of California (Regents).
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Regents nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * IN NO EVENT SHALL REGENTS BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
 * SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING
 * OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF REGENTS HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * REGENTS SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE. THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED
 * HEREUNDER IS PROVIDED "AS IS". REGENTS HAS NO OBLIGATION TO PROVIDE
 * MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

#ifndef _CONTROLLER_H_
#define _CONTROLLER_H_

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "edge_call.h"
#include "edge_syscall.h"
#include "sargs.h"
#include "report.h"
#include "test_dev_key.h"

extern int do_print(const char* str);
extern int do_copy_report(uint8_t *buffer);

static inline void _esys_ret(struct edge_call *edgecall, 
                             void *data, size_t size)
{
  uintptr_t data_section = edge_call_data_ptr();
  
  edgecall->return_data.call_status = CALL_STATUS_OK;
  
  memcpy((void *) data_section, data, size);
  
  if (edge_call_setup_ret(edgecall, 
            (void *) data_section, size) != 0) {
    edgecall->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
}

static void _esys_socket(struct edge_call *edgecall, 
                         struct edge_syscall *syscall, 
                         size_t size)
{
  sargs_sys_socket *args = (sargs_sys_socket *) syscall->data;
  
  int ret = socket(args->domain, args->type, args->protocol);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_setsockopt(struct edge_call *edgecall, 
                             struct edge_syscall *syscall, 
                             size_t size)
{
  int ret = 0;
  sargs_sys_setsockopt *args =  \
      (sargs_sys_setsockopt *) syscall->data;
  
  ret = setsockopt(args->sockfd, args->level, 
                   args->optname, args->optval, args->optlen);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_bind(struct edge_call *edgecall, 
                       struct edge_syscall *syscall, 
                       size_t size)
{
  int ret = 0;
  sargs_sys_bind *args =  \
      (sargs_sys_bind *) syscall->data;
      
  struct sockaddr_in *addr = (struct sockaddr_in *) args->sockaddr;
      
  ret = bind(args->sockfd, (struct sockaddr *) args->sockaddr, 
             args->addrlen);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_listen(struct edge_call *edgecall, 
                         struct edge_syscall *syscall, 
                         size_t size)
{
  int ret = 0;
  sargs_sys_listen *args = \
      (sargs_sys_listen *) syscall->data;
      
  ret = listen(args->sockfd, args->backlog);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_accept(struct edge_call *edgecall, 
                         struct edge_syscall *syscall, 
                         size_t size)
{
  int ret = 0;
  uint8_t addr[256];
  uint8_t buffer[256];
  size_t bufflen;
  socklen_t addrlen;
  
  sargs_sys_accept *args = \
      (sargs_sys_accept *) syscall->data;
      
  addrlen = args->addrlen;
  memcpy(addr, args->addr, args->addrlen);
      
  ret = accept(args->sockfd, (struct sockaddr *)addr, &addrlen);
  
  memcpy(buffer, &ret, sizeof(int));
  memcpy(buffer + sizeof(int), &addrlen, sizeof(socklen_t));
  memcpy(buffer + sizeof(int) + sizeof(socklen_t), addr, addrlen);
  bufflen = sizeof(int) + sizeof(socklen_t) + addrlen;
  
  edgecall->return_data.call_status = CALL_STATUS_OK;
  if (edge_call_setup_wrapped_ret(edgecall, buffer, bufflen) != 0) {
    edgecall->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
}

static void _esys_connect(struct edge_call *edgecall, 
                          struct edge_syscall *syscall, 
                          size_t size)
{
  int ret = 0;
  sargs_sys_connect *args = \
      (sargs_sys_connect *) syscall->data;
      
  ret = connect(args->sockfd, (struct sockaddr *) args->addr, 
                args->addrlen);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_open(struct edge_call *edgecall, 
                       struct edge_syscall *syscall, 
                       size_t size)
{
  int ret;
  sargs_sys_open *args = \
      (sargs_sys_open *) syscall->data;
      
  ret = open((char *) args->path, args->oflags);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_close(struct edge_call *edgecall, 
                       struct edge_syscall *syscall, 
                       size_t size)
{
  int ret;
  sargs_sys_close *args = \
      (sargs_sys_close *) syscall->data;
      
  ret = close(args->fd);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

static void _esys_write(struct edge_call *edgecall, 
                       struct edge_syscall *syscall, 
                       size_t size)
{
  ssize_t ret;
  sargs_sys_write *args = \
      (sargs_sys_write *) syscall->data;
      
  ret = write(args->fd, (void *) args->buf, args->len);
  
  _esys_ret(edgecall, &ret, sizeof(ssize_t));
}

static void _esys_read(struct edge_call *edgecall, 
                       struct edge_syscall *syscall, 
                       size_t size)
{
  ssize_t ret;
  uint8_t buffer[512];
  sargs_sys_read *args = \
      (sargs_sys_read *) syscall->data;
      
  ret = read(args->fd, buffer + sizeof(ssize_t), args->len);
  memcpy(buffer, &ret, sizeof(ssize_t));
      
  edgecall->return_data.call_status = CALL_STATUS_OK;
  if (edge_call_setup_wrapped_ret(edgecall, buffer, 
                sizeof(ssize_t) + ret) != 0) {
    edgecall->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
}

static void _esys_send(struct edge_call *edgecall, 
                       struct edge_syscall *syscall, 
                       size_t size)
{
  ssize_t ret;
  sargs_sys_send *args = \
      (sargs_sys_send *) syscall->data;
  
  ret = send(args->sockfd, (void *) args->buf, args->len, args->flags);
  
  _esys_ret(edgecall, &ret, sizeof(ssize_t));
}
    
void ocall_esyscall_handle(void *buffer)
{
  uintptr_t call_args_ptr;
  size_t call_args_len;
  
  struct edge_call *edgecall = (struct edge_call *) buffer;
  if (edge_call_args_ptr(edgecall, &call_args_ptr, &call_args_len) != 0) {
    edgecall->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  
  struct edge_syscall *syscall = (struct edge_syscall *)call_args_ptr;
  
  switch (syscall->syscall_num) {
    case SYS_socket:
      _esys_socket(edgecall, syscall, call_args_len);
      break;
    case SYS_setsockopt:
      _esys_setsockopt(edgecall, syscall, call_args_len);
      break;
    case SYS_listen:
      _esys_listen(edgecall, syscall, call_args_len);
      break;
    case SYS_accept:
      _esys_accept(edgecall, syscall, call_args_len);
      break;
    case SYS_connect:
      _esys_connect(edgecall, syscall, call_args_len);
      break;
    case SYS_bind:
      _esys_bind(edgecall, syscall, call_args_len);
      break;
    case SYS_open:
      _esys_open(edgecall, syscall, call_args_len);
      break;
    case SYS_close:
      _esys_close(edgecall, syscall, call_args_len);
      break;
    case SYS_write:
      _esys_write(edgecall, syscall, call_args_len);
      break;
    case SYS_read:
      _esys_read(edgecall, syscall, call_args_len);
      break;
    case SYS_send:
      _esys_send(edgecall, syscall, call_args_len);
      break;
  }
}

void ocall_print_handle(void *buffer)
{
  int ret = 0;
  uintptr_t call_args_ptr;
  size_t call_args_len;
  struct edge_call *edgecall =  \
        (struct edge_call *) buffer;
  
  if (edge_call_args_ptr(edgecall, &call_args_ptr, &call_args_len) != 0) {
    edgecall->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  
  ret = do_print((char *) call_args_ptr);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

void ocall_copy_report_handle(void *buffer)
{
  int ret = 0;
  uintptr_t call_args_ptr;
  size_t call_args_len;
  struct edge_call *edgecall =  \
        (struct edge_call *) buffer;
        
  if (edge_call_args_ptr(edgecall, &call_args_ptr, &call_args_len) != 0) {
    edgecall->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  
  ret = do_copy_report((uint8_t *) call_args_ptr);
  
  _esys_ret(edgecall, &ret, sizeof(int));
}

#endif  // _CONTROLLER_H_


