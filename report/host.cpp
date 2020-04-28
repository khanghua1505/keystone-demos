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

#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include "defines.h"
#include "keystone.h"
#include "ocall_host.h"

#define DEFAULT_SELF_TIMING         (0)
#define DEFAULT_LOAD_ONLY           (0)
#define DEFAULT_UNTRUSRTED_SIZE     (MBYTES(2))

bool fexists(const char* file_path)
{
    FILE* fp = fopen(file_path, "r");
    
    if (fp == NULL) {
        return false;
    } 
    
    fclose(fp);
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 8) {
        std::cout<<"Usage: \n"
                   "host <eapp> <runtime> \n"
                   "[--utm-size SIZE(k)] [--utm-ptr 0x..x]\n"
                   "[--freemem-size SIZE(k)]\n"
                   "[--load-only]\n";
        return -EINVAL;
    }
    
    const char* eapp_file = argv[1];
    const char* runtime_file = argv[2];
    size_t untrusted_size = DEFAULT_UNTRUSRTED_SIZE;
    uintptr_t untrusted_ptr = DEFAULT_UNTRUSTED_PTR;
    size_t freemem_size = DEFAULT_FREEMEM_SIZE;
    int load_only = DEFAULT_LOAD_ONLY;
    
    struct option long_options[] = {
		{"load-only", no_argument, &load_only, 1},
		{"utm-size", required_argument, 0, 'u'},
		{"utm-ptr", required_argument, 0, 'p'},
		{"freemem-size", required_argument, 0, 'f'},
    };
     
    if (!fexists(eapp_file)) {
        std::cerr<< eapp_file << " is not existence"<< std::endl;
        return -EINVAL;
    } else if (!fexists(runtime_file)) {
        std::cerr<< runtime_file << " is not existence"<< std::endl;
        return -EINVAL;
    }
    
    int opt, opt_index;
    while (true) {
        opt = getopt_long(argc, argv, "u:p:f", 
                          long_options, &opt_index);
        if (opt == -1) {
            break;
        }
        
        switch (opt) {
        case 'u':
            untrusted_size = atoi(optarg) * 1024;
            break;
        case 'p':
            untrusted_ptr = strtoll(optarg, NULL, 16);
            break;
        case 'f':
            freemem_size = atoi(optarg) * 1024;
            break;
        }
    }
    
    Params params;
    Keystone keystone;
    
    params.setFreeMemSize(freemem_size);
	params.setUntrustedMem(untrusted_ptr, untrusted_size);
    
    keystone.init(eapp_file, runtime_file, params);
    
    keystone.registerOcallDispatch(incoming_call_dispatch);
    register_call(OCALL_ID_PRINT, ocall_print_handle);
    register_call(OCALL_ID_ESYSCALL, ocall_esyscall_handle);
    register_call(OCALL_ID_COPY_REPORT, ocall_copy_report_handle);
    edge_call_init_internals((uintptr_t) keystone.getSharedBuffer(),
                            keystone.getSharedBufferSize());
    
    if (!load_only) {
        keystone.run();
    }
    
    return 0;
}
