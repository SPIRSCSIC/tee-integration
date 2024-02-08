#include "mondrian.h"
#include "common.h"

void mondrian_test() {
  DATASET = "/root/tee.csv";
  OUTPUT = "/root/output.csv";
  MODE = "strict";
  parse_dataset();
  mondrian();
  free_mem();
}
