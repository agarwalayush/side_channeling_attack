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

int mypid;
int myppid;
int victim;     //victim process pid

int fd;   //file descriptor for the perf_events

//system call abstraction for the perf_event call
long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
               int cpu, int group_fd, unsigned long flags){
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
   return ret;
}

void get_process_name(int pid, char * name) {
  char procfile[200];
  sprintf(procfile, "/proc/%d/cmdline", pid);
  FILE* f = fopen(procfile, "r");
  if (f) {
    size_t size;
    size = fread(name, sizeof (char), sizeof (procfile), f);
    if (size > 0) {
      if ('\n' == name[size - 1])
        name[size - 1] = '\0';
    }
    fclose(f);
  }
}




//recursive function to find the spy process. l and r stands for left and right and pids is a pointer to an array of pids 
int binary_search(int *pids, int l, int r){
  int i = l;
  int count;
  int  m = (l+r)/2;
  if(l >= r)
      return pids[l];

  //sending interrupt(SIGSTOP) signal to half the processes
  while(i <= m ){
    if(kill(pids[i], SIGSTOP)) cout<<"Some Error!! please check";
    i++;
  } 
  
  //measuring the performance of the victim after SIGSTOP for 10000 micro secs
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  usleep(10000);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  read(fd, &count, sizeof(long long));
  
  //sending continue(SIGCONT) signal to half the processes
  i = l;
  while(i <= m ){
    if(kill(pids[i], SIGCONT)) cout<<"Some Error!! please check";
    i++;
  } 
  
  cout<<count<<" m is "<<pids[m]<<endl;
  if(count > 700){ //rough estimate of cache misses
    cout<<"attack is still going on\n";
    return binary_search(pids, m+1, r);
  }
  else{
    cout<<"the attack has freezed"<<endl;
    return binary_search(pids, l, m);
  }
}

int main(){
  proc_t p;
  struct perf_event_attr pe;
  long long count;
  FILE* pf;
  int pid;
  int pids[100], i=0;
  char mystring[100]; 
  char attacker_proc[200];

  //saving the pids and ppids
  mypid = getpid();
  myppid = getppid();

  //for process list 
  PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLUSR);
  memset(&p, 0, sizeof(p)); 

  //initiallizing the perf counter
  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(struct perf_event_attr);
  pe.config = PERF_COUNT_HW_CACHE_MISSES;
  pe.inherit = 1;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  
  while(1){ 
          //find if the victim process has started
          pf = popen("pgrep encrypt", "r");

          if(pf != NULL){
            if(fgets(mystring, 100, pf) != NULL){  //store its stats in mystring
              
              cout<<"saw our process running "<<mystring<<endl; //just for debug purposes
              
              victim = stoi(mystring, NULL, 10);    //getting the victim process id
              
              fd = perf_event_open(&pe, victim, -1, -1, 0);  //file descriptor of the perf_event
              if (fd == -1) {
                 fprintf(stderr, "Error opening leader %llx\n", pe.config);
                 continue;
              }
              i = 0;
              while (readproc(proc, &p) != NULL) {
                if(!strcmp(p.ruser,"ayush")){
                  //printf("%s  %13s:\t%5ld\t%5lld\t%5lld %d\n", p.euser, p.cmd, p.resident, p.utime, p.stime, p.pgrp);
                  if(p.tid == mypid || p.tid == myppid || p.tid == victim) continue;
                  pids[i++] = p.tid;
                }
              }
              int j = 0;
              while(j<i)
                      cout<<j<<" process "<<pids[j++]<<endl;
              int attacker = binary_search(pids, 0, i-1);
              get_process_name(attacker, attacker_proc);
              cout<<"spy was "<<attacker<<" "<<attacker_proc<<endl;
              kill(attacker, SIGINT);
              cout<<"the attacker is killed"<<endl;
              break;
            }
            fclose(pf);
          }
  }
  fclose(pf);
  closeproc(proc);
  return 0;
}
