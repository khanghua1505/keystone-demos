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
#include <unistd.h>
#include <fcntl.h>
#include "string.h"
#include "debug.h"
#include "eapp_utils.h"

void EAPP_ENTRY eapp_entry()
{
  char buffer[128];
  ssize_t size;
  const char* input_file = "/root/foo.txt";
  const char* output_file = "/root/output.txt";
  
  int infd = open(input_file, O_RDONLY);
  if (infd < 0) {
    PRINTF("Error: %s is not existence\n", input_file);
    EAPP_RETURN(-1);
  }
  
  int outfd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC);
  if (outfd < 0) {
    PRINTF("Error: Can't open file %s\n", output_file);
    EAPP_RETURN(-1);
  }
  
  PRINTF("Read from file: \n");
  
  while ((size=read(infd, buffer, 64)) > 0) {
    buffer[size] = '\0';
    
    write(outfd, buffer, size);
    PRINTF("Copy to host and write to file: %s\n", buffer);
  }
  
  close(infd);
  close(outfd);
  
  EAPP_RETURN(0);
}
