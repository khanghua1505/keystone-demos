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

#ifndef _SARGS_H_
#define _SARGS_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cpluscplus
extern "C" {
#endif  // __cplusplus
    
typedef struct sargs_SYS_socket
{
  int domain;
  int type;
  int protocol;
} sargs_sys_socket;

typedef struct sargs_SYS_setsockopt
{
  int sockfd;
  int level;
  int optname;
  socklen_t optlen;
  uint8_t optval[];
} sargs_sys_setsockopt;

typedef struct sargs_SYS_bind
{
  int sockfd;
  socklen_t addrlen;
  uint8_t sockaddr[];
} sargs_sys_bind;

typedef struct sargs_SYS_listen
{
  int sockfd;
  int backlog;
} sargs_sys_listen;

typedef struct sargs_SYS_accept
{
  int sockfd;
  socklen_t addrlen;
  uint8_t addr[];
} sargs_sys_accept;

typedef struct ret_SYS_accept
{
  int ret;
  uintptr_t addr;
  socklen_t addrlen;
} ret_sys_accept;

typedef struct sargs_SYS_connect
{
  int sockfd;
  socklen_t addrlen;
  uint8_t addr[];
} sargs_sys_connect;
    
#ifdef __cpluscplus
}
#endif  // __cplusplus

#endif  // _SARGS_H_


