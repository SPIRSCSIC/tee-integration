#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/rand.h>

#include "groupsig.h"
#include "kty04.h"
#include "ps16.h"
#include "cpy06.h"
#include "common.h"
#include "mondrian.h"
#include "shim/base64.h"

char *DIRE = "/root/groupsig";
char *AFFIX = "";
char GRPKEY[1024];
char MGRKEY[1024];
char GML[1024];
char CRL[1024];
char *SIG_PATH = NULL;
char *MSG_PATH = NULL;
char *FINAL_PATH = "/root/.last";
char SCHEME[10];
groupsig_t *GSIG = NULL;
int PHASE = -1;
int CODE = -1;
int REV = 0;
int STAT = 0;
int JOIN = 0;
int VER = 0;
static int groupsig_flag;
static int mondrian_flag;
static int anonymize_flag;
static int relaxed_flag;
static int results_flag;
static int quiet_flag;


void setup_seed() {
  unsigned char buffer[2048];
  FILE* fd = fopen("/dev/urandom", "r");
  fread(buffer, 1, 2048, fd);
  fclose(fd);
  RAND_seed(buffer, 2048);
}

void check_ptr(void *ptr, char *msg) {
  if (ptr == NULL) {
    fprintf(stderr, "Error: %s initialization\n", msg);
    exit(1);
  }
}

void check_rc(int rc, char *msg) {
  if (rc != IOK) {
    fprintf(stderr, "Error: %s incorrect return value\n", msg);
    exit(1);
  }
}

void check_size(int size1, int size2, char *msg) {
  if (size1 != size2) {
    fprintf(stderr, "Error: incorrect %s export size (%d): expected %d\n",
            msg, size1, size2);
    exit(1);
  }
}

int file_readable(char* file) {
  FILE *fp = fopen(file, "r");
  if (fp == NULL) {
    return 0;
  } else {
    fclose(fp);
    return 1;
  }
}

void check_digit(char* str, char* msg) {
  for (int i = 0; i < strlen(optarg); i++) {
    if (!isdigit(optarg[i])) {
      fprintf(stderr, "k-Anonymity value must be integer\n");
      exit(1);
    }
  }
}

int valid_schemes() {
  if (!strcmp(SCHEME, "dl21") || !strcmp(SCHEME, "dl21seq"))
    return 0;
  return 1;
}

void metadata_from_code() {
  GSIG = groupsig_get_groupsig_from_code(CODE);
  if (!GSIG) {
    fprintf(stderr, "Error: Could not detect scheme from code\n");
    exit(1);
  }
}

void scheme_from_code() {
  strcpy(SCHEME, GSIG->desc->name);
  for (char *p = SCHEME; *p; ++p) *p = tolower(*p);
}

void print_data(void *data, int type) {
  char *msg1 = "grpkey_print";
  char *msg2 = "grpkey";
  int (*get_size)(groupsig_key_t *) = &groupsig_grp_key_get_size;
  int (*export)(byte_t **, uint32_t *, groupsig_key_t *) = &groupsig_grp_key_export;
  if (type == 2) {
    msg1 = "memkey_print";
    msg2 = "memkey";
    get_size = &groupsig_mem_key_get_size;
    export = &groupsig_mem_key_export;
  }
  int len = (*get_size)(data);
  int rc = 255;
  byte_t *bytes = NULL;
  uint32_t size;
  rc = (*export)(&bytes, &size, data);
  check_rc(rc, msg1);
  check_size(size, len, msg2);
  char *enc = base64_encode(bytes, size, 0);
  printf("%s\n", enc);
  free(enc);
}

void save_data(void *data, int type) {
  char *msg1 = "grpkey_export";
  char *msg2 = "grpkey";
  int (*get_size)(groupsig_key_t *) = &groupsig_grp_key_get_size;
  int (*export)(byte_t **, uint32_t *, groupsig_key_t *) = &groupsig_grp_key_export;
  char *file = GRPKEY;
  if (type == 1) {
    msg1 = "mgrkey_export";
    msg2 = "mgrkey";
    file = MGRKEY;
    get_size = &groupsig_mgr_key_get_size;
    export = &groupsig_mgr_key_export;
  } else if (type == 3) {
    msg1 = "gml_export";
    msg2 = "gml";
    file = GML;
    export = &gml_export;
  }
  int len;
  if (type != 3)
    len = (*get_size)(data);
  int rc = 255;
  byte_t *bytes = NULL;
  uint32_t size;
  rc = (*export)(&bytes, &size, data);
  check_rc(rc, msg1);
  if (type != 3)
    check_size(size, len, msg2);
  char *enc = base64_encode(bytes, size, 0);
  FILE *fp = fopen(file, "w");
  if (fp != NULL) {
    fwrite(enc, sizeof(char), strlen(enc), fp);
    fclose(fp);
  } else {
    fprintf(stderr, "Error: File %s cannot be written\n", file);
    exit(1);
  }
  free(enc);
}

void load_message(message_t **msg) {
  FILE *fp = fopen(MSG_PATH, "r");
  char *data;
  if (fp != NULL) {
    if (!fscanf(fp, "%ms", &data)) {
      fclose(fp);
      fprintf(stderr, "Error: %s incorrect format\n", MSG_PATH);
      exit(1);
    }
    fclose(fp);
  } else {
    fprintf(stderr, "Error: %s file cannot be read\n", MSG_PATH);
    exit(1);
  }
  *msg = message_from_base64(data);
}

void load_data(void **data, int type) {
  char *msg1 = "grpkey_import";
  groupsig_key_t *(*import)(unsigned char, unsigned char *, unsigned int) = &groupsig_grp_key_import;
  char *file = GRPKEY;
  if (type == 1) {
    msg1 = "mgrkey_import";
    file = MGRKEY;
    import = &groupsig_mgr_key_import;
  } else if (type == 3) {
    msg1 = "gml_import";
    file = GML;
    import = &gml_import;
  } else if (type == 4) {
    msg1 = "sig_import";
    file = SIG_PATH;
    import = &groupsig_signature_import;
  }
  FILE *fp = fopen(file, "r");
  char *enc;
  if (fp != NULL) {
    if (!fscanf(fp, "%ms", &enc)) {
      fclose(fp);
      fprintf(stderr, "Error: %s incorrect format\n", file);
      exit(1);
    }
    fclose(fp);
  } else {
    fprintf(stderr, "Error: %s file cannot be read\n", file);
    exit(1);
  }
  uint64_t dec_len;
  byte_t *dec_buff = base64_decode(enc, &dec_len);
  if (CODE == -1) {
    CODE = dec_buff[0];
    metadata_from_code();
    scheme_from_code();
    int rc = 255;
    rc = groupsig_init(CODE, time(NULL));
    check_rc(rc, "init");
  }
  if (type == 3 && !strlen(dec_buff)) {
    *data = gml_init(CODE);
  } else {
    *data = (*import)(CODE, (unsigned char*) dec_buff, dec_len);
    check_ptr(data, msg1);
  }
  free(dec_buff);
}


void join(message_t *msg,
          groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
          gml_t *gml) {
  int rc = 255;
  uint8_t start, seq;
  rc = GSIG->get_joinstart(&start);
  check_rc(rc, "joinstart");
  rc = GSIG->get_joinseq(&seq);
  check_rc(rc, "joinseq");
  int n_phases = (seq - start) / 2 + 1;
  int *phases = malloc(sizeof(int) * n_phases);
  if (!phases) {
    fprintf(stderr, "Error: Memory allocation failed for phases\n");
    exit(1);
  }
  int correct = 0;
  for(int i=0; i<n_phases; i++) {
    phases[i] = start + i * 2;
    if (PHASE == phases[i])
      correct = 1;
  }
  if (!correct) {
    fprintf(stderr, "Error: Only phase(s) [");
    for(int i=0; i<n_phases-1; i++) {
      fprintf(stderr, "%d, ", phases[i]);
    }
    fprintf(stderr, "%d] allowed\n", phases[n_phases-1]);
    exit(1);
  }
  message_t *msg_out = message_init();
  if (start == 1 && seq == 1) { // kty04
    rc = groupsig_join_mgr(&msg_out, gml, mgrkey, PHASE, msg, grpkey);
    check_rc(rc, "join_mgr");
    groupsig_key_t *memkey = groupsig_mem_key_init(grpkey->scheme);
    memkey = groupsig_mem_key_import(CODE, msg_out->bytes, msg_out->length);
    print_data(memkey, 2);
    groupsig_mem_key_free(memkey); memkey = NULL;
    save_data(gml, 3);
    FILE *fp = fopen(FINAL_PATH, "w");
    if (fp == NULL) {
      fprintf(stderr, "Error: File %s cannot be written\n", FINAL_PATH);
      exit(1);
    }
    fclose(fp);
  } else {
    rc = groupsig_join_mgr(&msg_out, gml, mgrkey, PHASE, msg, grpkey);
    check_rc(rc, "join_mgr");
    char* out = message_to_base64(msg_out);
    FILE *fp = fopen(MSG_PATH, "w");
    if (fp != NULL) {
      fwrite(out, sizeof(char), strlen(out), fp);
      fclose(fp);
    } else {
      fprintf(stderr, "Error: File %s cannot be written\n", MSG_PATH);
      exit(1);
    }
    if (PHASE == phases[n_phases-1]) {
      save_data(gml, 3);
      FILE *fp = fopen(FINAL_PATH, "w");
      if (fp == NULL) {
        fprintf(stderr, "Error: File %s cannot be written\n", FINAL_PATH);
        exit(1);
      }
      fclose(fp);
    }
    free(out);
  }
  message_free(msg_out); msg_out = NULL;
}

void verify_signature(groupsig_key_t *grpkey,
                      groupsig_signature_t *sig,
                      message_t *msg) {
  uint8_t ret = 255;
  int rc = 255;
  rc = groupsig_verify(&ret, sig, msg, grpkey);
  check_rc(rc, "verify");
  printf("%d\n", ret); // 0 means OK
}

void revoke_signature_identity(groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
                               gml_t *gml, crl_t *crl,
                               groupsig_signature_t *sig) {
  uint64_t idx = 255;
  groupsig_proof_t *proof_op;
  int rc = 255;
  proof_op = groupsig_proof_init(grpkey->scheme);
  rc = groupsig_open(&idx, proof_op, crl, sig, grpkey, mgrkey, gml);
  check_rc(rc, "open");
  trapdoor_t *trapdoor_mem = NULL;
  trapdoor_mem = trapdoor_init(grpkey->scheme);
  check_ptr(trapdoor_mem, "trapdoor");
  rc = groupsig_reveal(trapdoor_mem, crl, gml, idx);
  check_rc(rc, "reveal");
  rc = crl_export(crl, CRL, CRL_FILE);
  check_rc(rc, "crl");
  printf("%d\n", 1);
}

void status_signature_identity(groupsig_key_t *grpkey,
                               gml_t *gml, crl_t *crl,
                               groupsig_signature_t *sig) {
  uint8_t ret = 255;
  int rc = 255;
  // everybody can use this function, but we provide here in OCSP-like API
  rc = groupsig_trace(&ret, sig, grpkey, crl, NULL, gml);
  check_rc(rc, "trace");
  printf("%d\n", ret); // 1 means revoked
}

void groupsig_mode() {
  if ((JOIN + VER + REV + STAT) > 1) {
    fprintf(stderr, "Error: join, verify, revoke or status are mutually exclusive\n");
    exit(1);
  }
  setup_seed();
  groupsig_key_t *grpkey;
  groupsig_key_t *mgrkey;
  gml_t *gml;
  crl_t *crl;
  if (!file_readable(GRPKEY) || !file_readable(MGRKEY)
      || !file_readable(GML)) {
    if (SCHEME[0] == '\0') {
      fprintf(stderr, "Error: scheme missing, allowed values are ps16, gl19 and kty04\n");
      exit(1);
    } else if (!valid_schemes()) {
      fprintf(stderr, "Error: invalid scheme, allowed values are ps16, gl19 and kty04\n");
      exit(1);
    } else {
      int rc = 255;
      rc = groupsig_get_code_from_str(&CODE, SCHEME);
      check_rc(rc, "get_code_from_str");
      metadata_from_code();
      rc = groupsig_init(CODE, time(NULL));
      check_rc(rc, "init");
    }
    grpkey = groupsig_grp_key_init(CODE);
    check_ptr(grpkey, "grpkey");
    mgrkey = groupsig_mgr_key_init(CODE);
    check_ptr(mgrkey, "mgrkey");
    gml = gml_init(CODE);
    check_ptr(gml, "gml");
    if (GSIG->desc->has_crl) {
      crl = crl_init(CODE);
      check_ptr(crl, "crl");
    }
    int rc = 255;
    rc = groupsig_setup(CODE, grpkey, mgrkey, gml);
    check_rc(rc, "groupsig_setup");
    save_data(grpkey, 0);
    save_data(mgrkey, 1);
    save_data(gml, 3);
    if (GSIG->desc->has_crl) {
      rc = crl_export(crl, CRL, CRL_FILE);
      check_rc(rc, "crl");
    }
  } else {
    load_data(&grpkey, 0);
    load_data(&mgrkey, 1);
    load_data(&gml, 3);
    if (GSIG->desc->has_crl)
      crl = crl_import(CODE, CRL_FILE, CRL);
    if (!grpkey || !mgrkey || !gml){
      fprintf(stderr, "Error: importing groupsig material, does scheme match?\n");
      exit(1);
    }
  }
  if (!JOIN && !VER && !REV && !STAT && !quiet_flag) {
    print_data(grpkey, 0);
  } else if (JOIN) {
    if (!MSG_PATH) {
      fprintf(stderr, "Error: message missing\n");
      exit(1);
    }
    message_t *msg;
    if (!PHASE) {
      msg = message_init();
    } else {
      load_message(&msg);
    }
    join(msg, grpkey, mgrkey, gml);
    message_free(msg); msg = NULL;
  } else if (VER) {
    if (!MSG_PATH) {
      fprintf(stderr, "Error: message missing\n");
      exit(1);
    }
    message_t *msg;
    load_message(&msg);
    groupsig_signature_t *sig;
    load_data(&sig, 4);
    verify_signature(grpkey, sig, msg);
    groupsig_signature_free(sig); sig = NULL;
    message_free(msg); msg = NULL;
  } else if (REV) {
    if (!GSIG->desc->has_crl) {
      fprintf(stderr, "Error: %s scheme does not support revoke\n", SCHEME);
      exit(1);
    }
    groupsig_signature_t *sig;
    load_data(&sig, 4);
    revoke_signature_identity(grpkey, mgrkey, gml, crl, sig);
    groupsig_signature_free(sig); sig = NULL;
  } else if (STAT) {
    if (!GSIG->desc->has_crl) {
      fprintf(stderr, "Error: %s scheme does not support status\n", SCHEME);
      exit(1);
    }
    groupsig_signature_t *sig;
    load_data(&sig, 4);
    status_signature_identity(grpkey, gml, crl, sig);
    groupsig_signature_free(sig); sig = NULL;
  }
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  gml_free(gml); gml = NULL;
  if (GSIG->desc->has_crl) {
    crl_free(crl); crl = NULL;
  }
  groupsig_clear(CODE);
}

void mondrian_mode() {
  if (anonymize_flag)
    ANON = 1;
  if (relaxed_flag)
    MODE = "relaxed";
  else
    MODE = "static";
  if (results_flag)
    RES = 1;
  if (!DATASET)
    DATASET = "/root/tee.csv";
  if (!OUTPUT)
    OUTPUT = "/root/output.csv";
  parse_dataset();
  mondrian();
  free_mem();
}

void toolbox_usage(char** argv, int error) {
  FILE *out = stdout;
  if (error) {
    out = stderr;
    fprintf(out, "\n");
  }
  fprintf(out,
          "Usage: \n"
          "\t%s MODE [MODE_FLAGS] [MODE_OPTS]\n\n"
          "Mode:"
          "\tdemo\t\t\t Demos functionality\n"
          "\tbenchmark\t\t Benchmark functionality\n"
          "\tgroupsig\t\t Groupsig functionality\n"
          "\tmondrian\t\t Mondrian functionality\n"
          "\thelp\t\t\t This help\n\n"
          "Groupsig options:\n"
          "\t--scheme|-s SCHEME\t Scheme to be used: ps16, kty04\n"
          "\t--revoke|-r SIG\t\t Signature file path to revoke\n"
          "\t--status|-r SIG\t\t Signature file path to check revocation status\n"
          "\t--verify|-r SIG\t\t Signature file path to verify\n"
          "\t--join|-j PHASE\t\t Join phase to execute\n"
          "\t--message|-m MSG\t Message file path\n"
          "\t--directory|-m DIR\t Group signature crypto material path. Must exist.\n"
          "\t--affix|-m AFFIX\t Affix to add at the end of each crypto material file\n"
          "\t--quiet\t\t Do not print group key\n\n"
          "Mondrian flags:\n"
          "\t--anonymize\t\t If present, anonymize output attributes\n"
          "\t--relaxed\t\t If present, run on relaxed mode instead of strict\n"
          "\t--results\t\t If present, only generate results (no output file)\n\n"
          "Mondrian options:\n"
          "\t--input|-i INPUT\t Input file path. Default: ../datasets/adults.csv\n"
          "\t--output|-o OUTPUT\t Output file path. Default: output.csv\n"
          "\t--k|-k VALUE\t\t k-Anonymity value. Default: 10\n",
          argv[0]);
  exit(error);
}

int toolbox_main(int argc, char** argv) {
  int opt;
  int opt_idx = 0;
  static struct option long_options[] = {
    /* Flag arguments */
    {"groupsig", no_argument, &groupsig_flag, 1},
    {"mondrian", no_argument, &mondrian_flag, 1}, /* this should be an argument instead of flag to be similar to groupsig schemes */
    /* libgroupsig options */
    {"scheme", required_argument, 0, 's'},
    {"join", required_argument, 0, 'j'},
    {"verify", required_argument, 0, 'v'},
    {"revoke", required_argument, 0, 'r'},
    {"status", required_argument, 0, 't'},
    {"message", required_argument, 0, 'm'},
    {"directory", required_argument, 0, 'd'},
    {"affix", required_argument, 0, 'a'},
    {"quiet", no_argument, &quiet_flag, 1},
    /* Mondrian flags */
    {"anonymize", no_argument, &anonymize_flag, 1},
    {"relaxed", no_argument, &relaxed_flag, 1},
    {"results", no_argument, &results_flag, 1},
    /* Mondrian options */
    {"input", required_argument, 0, 'i'},
    {"k", required_argument, 0, 'k'},
    {"output", required_argument, 0, 'o'},

    /* extra */
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "s:j:v:r:t:m:d:a:i:k:o:h",
                            long_options, &opt_idx)) != -1) {
    switch (opt) {
    case 0:
      /* If this option set a flag, do nothing else now. */
      if (long_options[opt_idx].flag != 0)
        break;
    case 's':
      strcpy(SCHEME, optarg);
      for (char *p = SCHEME; *p; ++p) *p = tolower(*p);
      break;
    case 'j':
      check_digit(optarg, "join");
      PHASE = atoi(optarg);
      JOIN = 1;
      break;
    case 'v':
      SIG_PATH = optarg;
      VER = 1;
      break;
    case 'r':
      SIG_PATH = optarg;
      REV = 1;
      break;
    case 't':
      SIG_PATH = optarg;
      STAT = 1;
      break;
    case 'm':
      MSG_PATH = optarg;
      break;
    case 'd':
      DIRE = optarg;
      break;
    case 'a':
      AFFIX = optarg;
      break;
    case 'i':
      DATASET = optarg;
      break;
    case 'k':
      check_digit(optarg, "k-Anonymity");
      GL_K = atoi(optarg);
      break;
    case 'o':
      OUTPUT = optarg;
      break;
    case 'h':
      toolbox_usage(argv, 0);
      break;
    case '?':
      break;
    default:
      toolbox_usage(argv, 1);
    }
  }
  sprintf(GRPKEY, "%s/grpkey%s", DIRE, AFFIX);
  sprintf(MGRKEY, "%s/mgrkey%s", DIRE, AFFIX);
  sprintf(GML, "%s/gml%s", DIRE, AFFIX);
  sprintf(CRL, "%s/crl%s", DIRE, AFFIX);
  if (groupsig_flag && mondrian_flag) {
    fprintf(stderr, "Error: groupsig and mondrian are mutually exclusive\n");
    exit(1);
  } else if (groupsig_flag) {
    groupsig_mode();
  } else if (mondrian_flag) {
    mondrian_mode();
  } else
    toolbox_usage(argv, 0);
  return 0;
}
