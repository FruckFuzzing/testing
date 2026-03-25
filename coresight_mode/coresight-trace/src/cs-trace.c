/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"

#include "libcsdec.h"

#include "common.h"
#include "config.h"
#include "utils.h"

#define DEFAULT_TRACE_BITMAP_SIZE_POW2 (16)
#define DEFAULT_TRACE_BITMAP_SIZE (1U << (DEFAULT_TRACE_BITMAP_SIZE_POW2))

extern int registration_verbose;

extern char *board_name;
extern int udmabuf_num;
extern bool decoding_on;
extern int trace_cpu;
extern bool export_config;
extern cov_type_t cov_type;

extern unsigned char *trace_bitmap;
extern unsigned int trace_bitmap_size;
char *ld_forksrv_path;

void child(char *argv[])
{
  long ret;

  ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  if (ret < 0) {
    perror("ptrace");
  }
  
  char *ld_preload = "LD_PRELOAD=";
  char *ld_library_path = "LD_LIBRARY_PATH=";

  char *cs_ld_preload = getenv("CS_LD_PRELOAD");
  char *cs_ld_lib_path = getenv("CS_LD_LIBRARY_PATH");
  char *ld_no_forksrv = getenv("CS_NO_LD_FORKSRV");

  if(cs_ld_preload != NULL){
    ld_preload = append_string(ld_preload,cs_ld_preload);
  }
  if(ld_library_path != NULL){
    ld_library_path = append_string(ld_library_path, cs_ld_lib_path);
  }

  if(ld_no_forksrv == NULL){
    ld_preload = append_string(ld_preload,ld_forksrv_path);
  }

  char* envp[] = {ld_preload, ld_library_path, NULL};

  fprintf(stdout, "Try run %s \nwith envp:\n", argv[0]);
   for (int i = 0; envp[i] != NULL; i++) {
        fprintf(stdout, " %s\n", envp[i]);
    }
  
  ret = execve(argv[0],argv, envp);

  if(ret !=0) {
    fprintf(stderr, "Error with execvp\n");
    exit(EXIT_FAILURE);
  }
}

void parent(pid_t pid, int *child_status)
{
  int wstatus;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &wstatus, 0); 
    init_trace(getpid(), pid);
    start_trace(pid, true);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
  }

  while (1) {
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
      stop_trace(true);
      fini_trace();
      break;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
      trace_suspend_resume_callback();
    }
  }

  if (child_status) {
    *child_status = wstatus;
  }
}

static void usage(char *argv0)
{
  fprintf(stderr, "Usage: %s [OPTIONS] -- EXE [ARGS]\n", argv0);
  fprintf(stderr, "CoreSight process tracer\n");
  fprintf(stderr, "[OPTIONS]\n");
  fprintf(stderr, "  -b, --board=NAME\t\tspecify board name (default: %s)\n",
          board_name);
  fprintf(stderr,
          "  -c, --cpu=INT\t\t\tbind traced process to CPU (default: %d)\n",
          trace_cpu);
  fprintf(stderr,
          "  -d, --decoding={edge,path}\tenable trace decoding (default: "
          "off)\n");
  fprintf(stderr, "  -e, --export\t\t\tenable exporting config (default: %d)\n",
          export_config);
  fprintf(stderr,
          "  -u, --udmabuf=INT\t\tspecify u-dma-buf device number to use "
          "(default: %d)",
          udmabuf_num);
  fprintf(stderr,
          "  -v, --verbose[=INT]\t\tverbose output level (default: %d)\n",
          registration_verbose);
  fprintf(stderr, "  -h, --help\t\t\tshow this help\n");
}

int main(int argc, char *argv[])
{
  const struct option long_options[] = {
      {"board", required_argument, NULL, 'b'},
      {"cpu", required_argument, NULL, 'c'},
      {"decoding", required_argument, NULL, 'd'},
      {"export", no_argument, NULL, 'e'},
      {"udmabuf", required_argument, NULL, 'u'},
      {"verbose", optional_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };

  char **argvp;
  pid_t pid;
  int opt;
  int option_index;

  argvp = NULL;
  registration_verbose = 0;
  trace_bitmap_size = DEFAULT_TRACE_BITMAP_SIZE;

  ld_forksrv_path=get_libforksrv_path("libforksrv.so");
  if(access(ld_forksrv_path, F_OK) != 0){
    fprintf(stderr, "Error: libforksrv.so not found\n");
    return -1;
  }

  if (geteuid() != 0) {
      fprintf(stderr, "Error: Superuser (root) are required\n");
      exit(EXIT_FAILURE);
  }
  
  if(check_udmabuf() != 0){
      fprintf(stderr, "Error: u-dma-buf kernel module are required\n");
      exit(EXIT_FAILURE);
  }

  if (argc < 3) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  while ((opt = getopt_long(argc, argv, "b:c:d:ev::h", long_options,
                            &option_index)) != -1) {
    switch (opt) {
      case 'b':
        board_name = optarg;
        break;
      case 'c':
        trace_cpu = atoi(optarg);
        break;
      case 'd':
        if (!strcmp(optarg, "edge")) {
          cov_type = edge_cov;
        } else if (!strcmp(optarg, "path")) {
          cov_type = path_cov;
        } else {
          fprintf(stderr, "Unknown coverage type '%s'\n", optarg);
          exit(EXIT_FAILURE);
        }
        decoding_on = true;
        break;
      case 'e':
        export_config = true;
        break;
      case 'u':
        udmabuf_num = atoi(optarg);
        break;
      case 'v':
        if (optarg) {
          registration_verbose = atoi(optarg);
        } else {
          registration_verbose = 1;
        }
        break;
      case 'h':
        usage(argv[0]);
        exit(EXIT_SUCCESS);
        break;
      default:
        break;
    }
  }

  if (argc <= optind || strcmp(argv[optind - 1], "--")) {
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  argvp = &argv[optind];
  if (!argvp) {
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  pid = fork();
  switch (pid) {
    case 0:
      child(argvp);
      break;
    case -1:
      perror("fork");
      exit(EXIT_FAILURE);
      break;
    default:
      parent(pid, NULL);
      wait(NULL);
      break;
  }

  return 0;
}
