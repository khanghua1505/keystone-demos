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

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "string.h"
#include "malloc.h"
#include "edge_call.h"
#include "syscall.h"
#include "edge_syscall.h"
#include "sargs.h"
#include "ocall.h"
#include "../debug.h"

#define OCALL_ID_ESYSCALL       (3)

int socket(int domain, int type, int protocol)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_socket *args;
  const size_t pkgsize = 
        sizeof(sargs_sys_socket) + sizeof(struct edge_syscall);
  uint8_t buffer[pkgsize];
  
  syscall = (struct edge_syscall *) buffer;
  args = (sargs_sys_socket *) syscall->data;
  
  syscall->syscall_num = SYS_socket;
  args->domain = domain;
  args->type = type;
  args->protocol = protocol;
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ret));
  
  return ret;
}

int setsockopt(int sockfd, int level, int optname, 
                   const void *optval, socklen_t optlen)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_setsockopt *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                            + sizeof(sargs_sys_setsockopt) \
                            + optlen;
                            
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_setsockopt *) syscall->data;

  syscall->syscall_num = SYS_setsockopt;
  args->sockfd = sockfd;
  args->level = level;
  args->optname = optname;
  args->optlen = optlen;
  memcpy(args->optval, optval, optlen);

  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ret));
  
  free(syscall);

  return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_bind *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_bind) \
                           + addrlen;
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_bind *) syscall->data;
  
  syscall->syscall_num = SYS_bind;
  args->sockfd = sockfd;
  args->addrlen = addrlen;
  memcpy(args->sockaddr, addr, addrlen);
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ret));
  
  free(syscall);
  
  return ret;
}

int listen(int sockfd, int backlog)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_listen *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_listen);
  uint8_t buffer[pkgsize];
  
  syscall = (struct edge_syscall *) buffer;
  args = (sargs_sys_listen *) syscall->data;
  
  syscall->syscall_num = SYS_listen;
  args->sockfd = sockfd;
  args->backlog = backlog;
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ret));
  
  return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int ret = 0;
  uint8_t *buffer;
  struct edge_data retval;
  struct edge_syscall *syscall;
  sargs_sys_accept *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_accept)
                           + (*addrlen);
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  args = (sargs_sys_accept *) syscall->data;
  
  syscall->syscall_num = SYS_accept;
  args->sockfd = sockfd;
  args->addrlen = *addrlen;
  memcpy(args->addr, addr, *addrlen);
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &retval, sizeof(retval));
  
  free(syscall);
  
  if (retval.size == 0) {
    return -EINVAL;
  } 
  
  buffer = (uint8_t *) malloc(retval.size + 1);
  if (buffer == NULL) {
    return -ENOMEM;
  }
  
  copy_from_shared(buffer, retval.offset, retval.size);
  
  memcpy(&ret, buffer, sizeof(int));
  memcpy(addrlen, buffer + sizeof(int), sizeof(socklen_t));
  memcpy(addr, buffer + sizeof(int) + sizeof(socklen_t), *addrlen);
  
  free(buffer);
  
  return ret;
}

int connect(int sockfd, const struct sockaddr *addr, 
                socklen_t addrlen)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_connect *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_connect) \
                           + addrlen;
                  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_connect *) syscall->data;
  
  syscall->syscall_num = SYS_connect;
  args->sockfd = sockfd;
  args->addrlen = addrlen;
  memcpy(args->addr, addr, addrlen);
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(int));
  
  free(syscall);
  
  return ret;
}

int open(const char *path, int oflags, ...)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_open *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_open)
                           + strlen((char *)path);
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_open *) syscall->data;
  
  syscall->syscall_num = SYS_open;
  args->oflags = oflags;
  memcpy(args->path, path, strlen(path));
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(int));
  
  free(syscall);
  
  return ret;
}

int close(int fd)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_close *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_close);
                           
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_close *) syscall->data;
  
  syscall->syscall_num = SYS_close;
  args->fd = fd;
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(int));
  
  free(syscall);
  
  return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
  ssize_t ret;
  struct edge_syscall *syscall;
  sargs_sys_write *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                            + sizeof(sargs_sys_write) \
                            + count;
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_write *) syscall->data;

  syscall->syscall_num = SYS_write;
  args->fd = fd;
  args->len = count;
  memcpy(args->buf, buf, count);
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ssize_t));
  
  free(syscall);
  
  return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
  ssize_t ret;
  struct edge_data retval;
  struct edge_syscall *syscall;
  sargs_sys_read *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                            + sizeof(sargs_sys_read);
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  args = (sargs_sys_read *) syscall->data;
  
  syscall->syscall_num = SYS_read;
  args->fd = fd;
  args->len = count;
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &retval, sizeof(retval));
  
  if (retval.size == 0) {
    return -EINVAL;
  } 
  
  uint8_t *buffer = (uint8_t *) malloc(retval.size);
  if (buffer == NULL) {
    free(syscall);
    return -ENOMEM;
  }
  
  copy_from_shared(buffer, retval.offset, retval.size);
  
  memcpy(&ret, buffer, sizeof(ssize_t));
  memcpy(buf, buffer + sizeof(ssize_t), retval.size - sizeof(ssize_t));
  
  free(syscall);
  free(buffer);
  
  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
  ssize_t ret;
  struct edge_syscall *syscall;
  sargs_sys_send *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                            + sizeof(sargs_sys_send) + 
                            + len;
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  args = (sargs_sys_send *) syscall->data;
  
  syscall->syscall_num = SYS_send;
  args->sockfd = sockfd;
  args->flags = flags;
  args->len = len;
  memcpy(args->buf, buf, len);
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ssize_t));
  
  free(syscall);
  
  return ret;
}


