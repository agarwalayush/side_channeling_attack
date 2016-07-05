#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
               int cpu, int group_fd, unsigned long flags){
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
   return ret;
}

int main(int argc, char **argv){
   struct perf_event_attr pe, pi;
   long long count;
   int fd, fi;

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
   
   fd = perf_event_open(&pe, 0, -1, -1, 0);
   fi = perf_event_open(&pi, 0, -1, -1, 0);
   if (fd == -1 || fi == -1) {
      fprintf(stderr, "Error opening leader %llx\n", pe.config);
      exit(EXIT_FAILURE);
   }

   ioctl(fd, PERF_EVENT_IOC_RESET, 0);
   ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
   ioctl(fi, PERF_EVENT_IOC_RESET, 0);
   ioctl(fi, PERF_EVENT_IOC_ENABLE, 0);

   //printf("Measuring instruction count for this printf\n");
   system("LD_PRELOAD=$PWD/libcrypto.so ./spy");

   ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
   read(fd, &count, sizeof(long long));

   printf("misses %lld \n", count);
   ioctl(fi, PERF_EVENT_IOC_DISABLE, 0);
   read(fi, &count, sizeof(long long));

   printf("Used %lld instructions\n", count);

   close(fd);
   close(fi);
}
