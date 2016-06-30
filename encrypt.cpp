#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "../../cacheutils.h"
#include <map>
#include <vector>

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (300)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (1064)

unsigned char key[] =
{
  /* 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, */
  /* 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, */
  /* 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, */
  /* 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 */
  0x11, 0x5d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0x7c, 0x4f, 0x6e, 0x9c,
  0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};

size_t sum;
size_t scount;

char* base;
char* probe;
char* end;

uint64_t basetime;


int main(int argc, char *argv[])
{
  int l = argv[1][0] - '0';
  basetime = rdtsc();
  int fd = open("./libcrypto.so", O_RDONLY);
  if(fd == -1){
      printf("can't open the file\n");
      return 0;
  }
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);
  end = base + size;

  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  unsigned char restoredtext[128];

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);

  uint64_t min_time = rdtsc();
  srand(min_time);
  sum = 0;
  probe = base + 0x11F7A0 - 20;
  uint64_t timeForEncryption = rdtsc();
  for (size_t byte = 0; byte < 32; byte += 16)
  {
    plaintext[0] = byte;

    AES_encrypt(plaintext, ciphertext, &key_struct);
            for (int k = 0; k < 4*1024; k += 64)
            {
              for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
              {
                for (size_t j = 0; j < 16; ++j)
                  plaintext[j] = rand() % 256;
                plaintext[l*4 + 0] |= 0xF0;
                plaintext[l*4 + 1] |= 0xF0;
                plaintext[l*4 + 2] |= 0xF0;
                plaintext[l*4 + 3] |= 0xF0;
                //arr[i] = rdtsc();
                AES_encrypt(plaintext, ciphertext, &key_struct);
                for (int p = 0; p < 26; ++p)
                  sched_yield();
              }
            }
  }

  //printf("time taken by parent stop:%ld start:%ld diff:%ld\n", rdtsc() - basetime,timeForEncryption-basetime,rdtsc()-timeForEncryption);

  //for(int i=0; i<NUMBER_OF_ENCRYPTIONS; i++)
  //  printf("parent %d %d\n", i, abs(arr[i])); 
  close(fd);
  munmap(base, map_size);
  //printf("parent ended");
  fflush(stdout);
  return 0;
}

