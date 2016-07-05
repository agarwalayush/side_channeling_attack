#include<iostream>
#include<string.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<linux/perf_event.h>
#include<asm/unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<proc/procps.h>
#include<proc/readproc.h>
#include<signal.h>

using namespace std;

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
               int cpu, int group_fd, unsigned long flags){
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
   return ret;
}





int main(){
  proc_t p;
  struct perf_event_attr pe, pi;
  long long count;
  int fd;
  FILE* pf;
  int pid;
  int pids[100], i=0;
  char mystring[100]; 
  PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLUSR);
  memset(&p, 0, sizeof(p)); 

  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(struct perf_event_attr);
  pe.config = PERF_COUNT_HW_CACHE_MISSES;
  pe.inherit = 1;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  
  

  while(1){
          pf = popen("pgrep spy", "r");
          if(pf != NULL){
            if(fgets(mystring, 100, pf) != NULL){
              cout<<"saw our process running "<<puts(mystring)<<endl;
              pid = stoi(mystring, NULL, 10);
              fd = perf_event_open(&pe, pid, -1, -1, 0);
              if (fd == -1) {
                 fprintf(stderr, "Error opening leader %llx\n", pe.config);
                 continue;
              }
              ioctl(fd, PERF_EVENT_IOC_RESET, 0);
              ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
              usleep(10000);
              ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
              read(fd, &count, sizeof(long long));
     
              printf("misses %lld \n", count);
              close(fd);
            }
            fclose(pf);
            continue;
          }
          else
            continue;
          while (readproc(proc, &p) != NULL) {
            if(!strcmp(p.ruser,"ayush"))
              //printf("%s  %13s:\t%5ld\t%5lld\t%5lld %d\n", p.euser, p.cmd, p.resident, p.utime, p.stime, p.pgrp);
              
              pids[i++] = p.tid;
          }
          int j=0;
          while(i--){
              if(pids[i] == getpid()) continue;
              if(!kill(pids[i], SIGCONT)) cout<<"started";
              cout<<"\t "<<pids[i]<<endl;
          }
          closeproc(proc);
  }

  return 0;
}
