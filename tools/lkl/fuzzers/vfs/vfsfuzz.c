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
#include <linux/major.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <lkl/linux/time.h>

#include <lkl.h>
#include <lkl_host.h>

void __llvm_profile_initialize_file(void);
int __llvm_profile_write_file(void);

static char mpoint[32];
static unsigned int disk_id;
static struct lkl_disk disk;


void flush_coverage(void)
{
  printf("Flushing coverage data...\n");
  __llvm_profile_write_file();
  printf("Done...\n");
}

void cleanup(void) {
  flush_coverage();
  lkl_sys_halt();
  lkl_cleanup();
  lkl_disk_remove(disk);
  close(disk.fd);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  long ret;

  printf("--- prep disk ---\n");

  disk.fd = open("images/ext4.img", O_RDWR);
  if (disk.fd < 0) {
    fprintf(stderr, "could not open image: %s\n", strerror(errno));
    return -1;
  }
  disk.ops = NULL;

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

  printf("--- boot ---\n");
  ret = lkl_start_kernel("mem=1024M kasan.fault=report loglevel=8");
  if (ret < 0) {
    fprintf(stderr, "lkl_start_kernel failed: %s\n", lkl_strerror(ret));
    lkl_cleanup();
    return -1;
  }

  __llvm_profile_initialize_file();
  atexit(cleanup);

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  unsigned int ret;

  ret = lkl_sys_unlink("/mnt/0000fe00");
  if (ret < 0) {
    fprintf(stderr, "error unlinking mnt_str: %s\n", lkl_strerror(ret));
  } else {
    fprintf(stderr, "unlinked mnt_str\n");
  }

  printf("--- mount ---\n");
  ret = lkl_mount_dev(disk_id, 0, "ext4", 0, NULL, mpoint, sizeof(mpoint));
  if (ret) {
    fprintf(stderr, "can't mount disk: %d %s\n", ret, lkl_strerror(ret));
    return -1;
  }

  printf("mount point: %s\n", mpoint);

  ret = lkl_sys_chdir(mpoint);
  if (ret) {
    fprintf(stderr, "can't chdir to %s: %s\n", mpoint,
        lkl_strerror(ret));
    return -1;
  }

  /* run syscalls here */


  /* XXX: disk needs to be remounted as read-only for clean unmount */
  char dev_str[] = { "/dev/xxxxxxxx" };
  snprintf(dev_str, sizeof(dev_str), "/dev/%08x", disk_id);
  printf("dev_str: %s\n", dev_str);
  for (;;) {
    ret = lkl_sys_mount(dev_str, mpoint, "ext4", LKL_MS_RDONLY|LKL_MS_REMOUNT, NULL);
    if (ret == 0)
      break;
    if (ret == -EBUSY) {
      struct __lkl__kernel_timespec ts = {
        .tv_sec = 1,
        .tv_nsec = 0,
      };
      lkl_sys_nanosleep(&ts, NULL);
      continue;
    } else if (ret < 0) {
      fprintf(stderr, "cannot remount mount disk read-only: %s\n", lkl_strerror(ret));
      break;
    }
  }

  ret = lkl_umount_dev(disk_id, 0, 0, 1000);
  if (ret < 0) {
    fprintf(stderr, "umount failed: %s\n", lkl_strerror(ret));
  } else {
    printf("unmounted %d\n", disk_id);
  }

  ret = lkl_sys_chdir("/");
  if (ret) {
    fprintf(stderr, "can't chdir to /: %s\n", lkl_strerror(ret));
    return -1;
  }

  ret = lkl_sys_unlink("/mnt/0000fe00");
  if (ret < 0) {
    fprintf(stderr, "error unlinking mnt_str: %s\n", lkl_strerror(ret));
  } else {
    fprintf(stderr, "unlinked mnt_str\n");
  }

  ret = lkl_sys_unlink("/dev/0000fe00");
  if (ret < 0) {
    fprintf(stderr, "error unlinking internal dev_str: %s\n", lkl_strerror(ret));
  } else {
    fprintf(stderr, "unlinked internal dev_str\n");
  }

  ret = lkl_sys_unlink(dev_str);
  if (ret < 0) {
    fprintf(stderr, "error unlinking dev_str: %s\n", lkl_strerror(ret));
  } else {
    fprintf(stderr, "unlinked dev_str\n");
  }

  /*
   * printf("--- clean ---\n");
   * lkl_sys_halt();
   * lkl_cleanup();
   * lkl_disk_remove(disk);
   * close(disk.fd);
   */

  printf("--- done ---\n");

}
