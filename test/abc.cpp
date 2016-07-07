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

int fd, fi;   //file descriptor for the perf_events

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

int p_inst;



//recursive function to find the spy process. l and r stands for left and right and pids is a pointer to an array of pids 
int binary_search(int *pids, int l, int r){
  int i = l;
  long long count = 0, inst = 0;
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
  ioctl(fi, PERF_EVENT_IOC_RESET, 0);
  int p=0;
  do {
    if(p!=0) cout<<"--- repeating ---"<<endl;
    ioctl(fi, PERF_EVENT_IOC_ENABLE, 0);
    usleep(3000);
    ioctl(fi, PERF_EVENT_IOC_DISABLE, 0);
    read(fi, &inst, sizeof(long long));
    p++;
  } while(inst < 10000);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  read(fd, &count, sizeof(long long));
  
  i = l;
  while(i <= m ){
    if(kill(pids[i], SIGCONT)) cout<<"Some Error!! please check";
    i++;
  } 
  //sending continue(SIGCONT) signal to half the processes
  
  if(getpgid(victim) < 0){
          cout<<"process is dead already"<<endl;
          //return 0;
  }
  //inst+=p_inst;
  //if(inst < 100) return binary_search(pids, l, r);
  cout<<"no of inst is "<<inst<<endl;
  cout<<count<<" m is "<<pids[m]<<endl;
  p_inst = 0;
  if(count > 40){ //rough estimate of cache misses
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
  p_inst = 0;
  struct perf_event_attr pe, pi;
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
  memset(&pi, 0, sizeof(struct perf_event_attr));
  pi.type = pe.type = PERF_TYPE_HARDWARE;
  pi.size = pe.size = sizeof(struct perf_event_attr);
  pe.config = PERF_COUNT_HW_CACHE_MISSES;
  pi.config = PERF_COUNT_HW_INSTRUCTIONS;
  pi.inherit = pe.inherit = 1;
  pi.disabled = pe.disabled = 1;
  pi.exclude_kernel = pe.exclude_kernel = 1;
  pi.exclude_hv = pe.exclude_hv = 1;
  char gdb_string[100];
  fgets(gdb_string, 100, popen("pgrep gdb", "r"));
  int gdb = stoi(gdb_string, NULL, 10);
  
  while(1){ 
          //find if the victim process has started
          pf = popen("pgrep encrypt", "r");

          if(pf != NULL){
            if(fgets(mystring, 100, pf) != NULL){  //store its stats in mystring
              int prev = victim;
              victim = stoi(mystring, NULL, 10);    //getting the victim process id
              if(victim == prev) continue;
              cout<<"saw our process running "<<mystring<<endl; //just for debug purposes
              
              
              fd = perf_event_open(&pe, victim, -1, -1, 0);  //file descriptor of the perf_event
              fi = perf_event_open(&pi, victim, -1, -1, 0);  //file descriptor of the perf_event
              if (fd == -1 || fi == -1) {
                 fprintf(stderr, "Error opening leader %llx\n", pe.config);
                 continue;
              }
              i = 0;
              while (readproc(proc, &p) != NULL) {
                if(!strcmp(p.ruser,"ayush")){
                  //printf("%s  %13s:\t%5ld\t%5lld\t%5lld %d\n", p.euser, p.cmd, p.resident, p.utime, p.stime, p.pgrp);
                  if(p.tid == mypid || p.tid == myppid || p.tid == victim || p.tid == gdb) continue;
                  pids[i++] = p.tid;
                }
              }
              int j = 0;
              while(j<i)
                      cout<<j<<" process "<<pids[j++]<<endl;
              usleep(1000);
              cout<<getpgid(victim)<<endl;
              int attacker = binary_search(pids, 0, i-1);
              get_process_name(attacker, attacker_proc);
              cout<<"spy was "<<attacker<<" "<<attacker_proc<<endl;
              kill(attacker, SIGINT);
              cout<<"the attacker is killed"<<endl;
              j = 0;
              while(j <= i-1 ){
                if(kill(pids[j], SIGCONT)) cout<<"Some Error!! please check";
                j++;
              }
              break;
            }
            fclose(pf);
          }
  }
  fclose(pf);
  closeproc(proc);
  return 0;
}
