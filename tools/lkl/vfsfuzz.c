// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

#include <linux/major.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <lkl/linux/time.h>

#include <lkl.h>
#include <lkl_host.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE     _IO('c', 100)
#define KCOV_DISABLE    _IO('c', 101)
#define COVER_SIZE      (64<<10)

#define KCOV_TRACE_PC  1
#define KCOV_TRACE_CMP 1

int main(int argc, char** argv)
{
  if (argc < 3) {
    fprintf(stderr, "[-] usage: %s [fsimg] [fstype]\n", argv[0]);
    return -1;
  }
  long ret;
  struct lkl_disk disk;
  char mpoint[32];
  unsigned int disk_id;

  const char* fsimg = argv[1];
  const char* fstype = argv[2];

  disk.fd = open(fsimg, O_RDWR);
  if (disk.fd < 0) {
    printf("could not open image: %s\n", strerror(errno));
    return -1;
  }
  disk.ops = NULL;
  lkl_host_ops.print = NULL;

  ret = lkl_init(&lkl_host_ops);
  if (ret < 0) {
    fprintf(stderr, "lkl init failed: %s\n", lkl_strerror(ret));
    return -1;
  }

  ret = lkl_disk_add(&disk);
  if (ret < 0) {
    fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
    return -1;
  }
  disk_id = ret;
  printf("added disk id: %u\n", disk_id);

  printf("starting kernel\n");
  ret = lkl_start_kernel("mem=2048M loglevel=8 kasan.fault=panic");
  /* ret = lkl_start_kernel("mem=1024M printflevel=8"); */
  if (ret < 0) {
    printf("lkl_start_kernel failed: %s\n", lkl_strerror(ret));
    lkl_cleanup();
    return -1;
  }
  printf("lkl kernel started\n");

  ret = lkl_mount_dev(disk_id, 0, fstype, 0, NULL, mpoint, sizeof(mpoint));
  if (ret) {
    fprintf(stderr, "can't mount disk: %s\n", lkl_strerror(ret));
    return -1;
  }

  printf("mount point: %s\n", mpoint);

  ret = lkl_sys_chdir(mpoint);
  if (ret) {
    fprintf(stderr, "can't chdir to %s: %s\n", mpoint,
        lkl_strerror(ret));
    return -1;
  }

  int fd = lkl_sys_open("testfile", LKL_O_CREAT | LKL_O_RDWR, 0);
  if (fd < 0) {
    fprintf(stderr, "open failed: %s\n", lkl_strerror(fd));
  }
  printf("open fd: %d\n", fd);

  ret = lkl_sys_close(fd);
  if (ret < 0) {
    printf("failed to close fd %d: %s\n", fd, lkl_strerror(ret));
  }

  ret = lkl_umount_dev(disk_id, 0, 0, 1000);
  if (ret < 0) {
    fprintf(stderr, "umount failed: %s\n", lkl_strerror(ret));
  }

  lkl_disk_remove(disk);
  lkl_sys_halt();
  lkl_cleanup();
  close(disk.fd);

  return 0;
}
