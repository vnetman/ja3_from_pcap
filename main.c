#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "ja3_from_pcap.h"

static void print_usage_and_exit (char **argv) {
  printf("Usage:\n");
  printf("%s --pcap <file>\n\n", argv[0]);
  exit(0);
}

/* Parse the command line arguments and return the name of the PCAP
   file to be processed. */
static char const * parse_arguments (int argc, char **argv) {
  extern char *optarg;
  extern int optind;

  /* struct passed to getopt_long() */
  struct option options[] = {
    {"help",  no_argument, 0, 'h'},
    {"pcap", required_argument, 0, 'p'},
    {0, 0, 0, 0}};

  int longindex = 0;
  char const *pcap_file_name = 0;
  
  while (1) {
    int go_result = getopt_long_only(argc, argv, "", &(options[0]), &longindex);

    if (go_result == '?') {
      return 0;
    } else if (go_result == -1) {
      break;
    } else if (go_result == 'h') {
      print_usage_and_exit(argv);
    } else if (go_result == 'p') {
      if (pcap_file_name) {
	fprintf(stderr, "ERROR: option \"--pcap\" encountered multiple times "
		"(\"%s\" and \"%s\")\n", pcap_file_name, optarg);
	return 0;
      } else {
	pcap_file_name = optarg;
      }
    } else {
      fprintf(stderr, "ERROR: Unexpected option (%d) encountered when parsing the "
	      "command line.\n", go_result);
      return 0;
    }
  }
  if (!pcap_file_name) {
    fprintf(stderr, "ERROR: Need to specify a PCAP file with the \"--pcap\" option\n");
  }
  return pcap_file_name;
}

int main (int argc, char **argv) {
  int ret;
  
  char const *pcap_file_name = parse_arguments(argc, argv);
  if (!pcap_file_name) {
    return -1;
  }
  
  if (!md5_init()) {
    return -1;
  }

  ret = process_pcap_file(pcap_file_name);

  md5_shut();
  return ret;
}
