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

#ifndef _SYSCALL_H_
#define _SYSCALL_H_

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "string.h"
#include "malloc.h"
#include "edge_call.h"
#include "syscall.h"
#include "edge_syscall.h"
#include "sargs.h"

#define OCALL_ID_ESYSCALL       (3)

int sys_socket(int domain, int type, int protocol)
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

int sys_setsockopt(int sockfd, int level, int optname, 
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

int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
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

int sys_listen(int sockfd, int backlog)
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

int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int ret;
  uint8_t *buffer;
  struct edge_data retval;
  struct edge_syscall *syscall;
  sargs_sys_accept *args;
  const size_t pkgsize = sizeof(struct edge_syscall) \
                           + sizeof(sargs_sys_accept);
  
  syscall = (struct edge_syscall *) malloc(pkgsize);
  if (syscall == NULL) {
    return -ENOMEM;
  }
  
  args = (sargs_sys_accept *) syscall->data;
  
  syscall->syscall_num = SYS_accept;
  args->sockfd = sockfd;
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &retval, sizeof(retval));
  
  if (retval.size == 0) {
    return -EINVAL;
  } 
  
  buffer = (uint8_t *) malloc(retval.size);
  if (buffer == NULL) {
    free(syscall);
    return -ENOMEM;
  }
  
  copy_from_shared(buffer, retval.offset, retval.size);
  
  memcpy(&ret, buffer, sizeof(int));
  memcpy(&addrlen, buffer + sizeof(int), sizeof(socklen_t));
  memcpy(&addr, buffer + sizeof(int) + sizeof(socklen_t), *addrlen);
  
  free(syscall);
  free(buffer);
  
  return ret;
}

int sys_connect(int sockfd, const struct sockaddr *addr, 
                socklen_t addrlen)
{
  int ret;
  struct edge_syscall *syscall;
  sargs_sys_connect *args;
  int pkgsize = sizeof(struct edge_syscall) \
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
  
  ocall(OCALL_ID_ESYSCALL, syscall, pkgsize, &ret, sizeof(ret));
  
  free(syscall);
  
  return ret;
}

#endif  // _SYSCALL_H_


