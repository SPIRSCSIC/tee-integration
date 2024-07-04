#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>

#include "groupsig.h"
#include "common.h"
#include "mondrian.h"
#include "utils.h"
#include "shim/base64.h"

char *DIRE = "/root/groupsig";
char *AFFIX = "";
char GRPKEY[1024];
char MGRKEY1[1024];
char MGRKEY2[1024];
char GML[1024];
char CRL[1024];
char *SIG_PATH = NULL;
char *MSG_PATH = NULL;
char *MEMKEY = NULL;
char *ASSET_PATH = NULL;
char *LAST_PATH = "/root/.last";
char SCHEME[10];
char *SCOPE = "scp";
groupsig_t *GSIG = NULL;
int PHASE = -1;
uint8_t CODE = 255;
int REV = 0;
int STAT = 0;
int JOIN = 0;
int SIG = 0;
int VER = 0;
static int groupsig_flag;
static int mondrian_flag;
static int anonymize_flag;
static int relaxed_flag;
static int results_flag;
static int quiet_flag;
static int test_flag;
static int benchmark_flag;
// These two macros are defined in utils.h, but are not recognized, who knows why
#define N_BENCH 22
#define N_JOIN 9
clock_t TIMES[N_BENCH];
clock_t **TIMES_JOIN;
int MEMBERS = 10;
int ITER = 5;
char *PATH = "/root";


char *SCHEMES[] = {"bbs04", "ps16", "cpy06",
                   "kty04", "klap20", "gl19",
                   "dl21", "dl21seq"};
const int N_SCHEMES = sizeof(SCHEMES) / sizeof(SCHEMES[0]);

int valid_scheme() {
  for (int i = 0; i < N_SCHEMES; i++) {
    if (!strcmp(SCHEME, SCHEMES[i])) {
      return 1;
    }
  }
  return 0;
}

int multi_mgrkey() {
  if (!strcmp(SCHEME, "klap20") || !strcmp(SCHEME, "gl19"))
    return 1;
  return 0;
}

void setup_seed() {
  unsigned char buffer[2048];
  FILE* fd = fopen("/dev/urandom", "r");
  fread(buffer, 1, 2048, fd);
  fclose(fd);
  RAND_seed(buffer, 2048);
  srand(time(0));
}

void allocate_matrices() {
  TIMES_JOIN = (clock_t **)calloc(N_JOIN, sizeof(clock_t *));
  if (!TIMES_JOIN) {
    fprintf(stderr, "TIMES_JOIN: Memory allocation failed\n");
    exit(1);
  }
  for (int i = 0; i < N_JOIN; i++) {
    TIMES_JOIN[i] = (clock_t *)calloc(MEMBERS, sizeof(clock_t));
    if (!TIMES_JOIN[i]) {
      fprintf(stderr, "TIMES_JOIN[%d]: Memory allocation failed\n", i);
      exit(1);
    }
  }
}

void free_matrices() {
  for (int i = 0; i < N_JOIN; i++)
    free(TIMES_JOIN[i]);
  free(TIMES_JOIN);
}

void test_ptr(void *ptr, char *msg) {
  if (!ptr) {
    fprintf(stderr, "Error: %s initialization\n", msg);
    exit(1);
  }
}

void test_rc(int rc, char *msg) {
  if (rc != IOK) {
    fprintf(stderr, "Error: %s incorrect return value\n", msg);
    exit(1);
  }
}

void test_size(int size1, int size2, char *msg) {
  if (size1 != size2) {
    fprintf(stderr, "Error: incorrect %s export size (%d): expected %d\n",
            msg, size1, size2);
    exit(1);
  }
}

int file_readable(char* file) {
  FILE *fp = fopen(file, "r");
  if (!fp) {
    return 0;
  } else {
    fclose(fp);
    return 1;
  }
}

void check_digit(char* str, char* msg) {
  for (int i = 0; i < strlen(str); i++) {
    if (!isdigit(str[i])) {
      fprintf(stderr, "k-Anonymity value must be integer\n");
      exit(1);
    }
  }
}

void metadata_from_code() {
  GSIG = groupsig_get_groupsig_from_code(CODE);
  if (!GSIG) {
    fprintf(stderr, "Error: Could not detect scheme from code\n");
    exit(1);
  }
}

void scheme_from_code() {
  strncpy(SCHEME, GSIG->desc->name, 10);
  for (char *p = SCHEME; *p; ++p) *p = tolower(*p);
}

void print_data(void *data, int type) {
  char *msg1 = "grpkey_print";
  char *msg2 = "grpkey";
  int (*get_size)(groupsig_key_t *) = &groupsig_grp_key_get_size;
  int (*export)(byte_t **, uint32_t *, groupsig_key_t *) = &groupsig_grp_key_export;
  if (type == 1) {
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
  test_rc(rc, msg1);
  test_size(size, len, msg2);
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
  switch (type) {
  case 2:
    msg1 = "gml_export";
    msg2 = "gml";
    file = GML;
    export = &gml_export;
    break;
  case 3:
    msg1 = "sig_export";
    msg2 = "sig";
    file = SIG_PATH;
    get_size = &groupsig_signature_get_size;
    export = &groupsig_signature_export;
    break;
  case 4:
  case 5:
    msg1 = "mgrkey_export1";
    msg2 = "mgrkey1";
    file = MGRKEY1;
    if (type == 5) {
      msg1 = "mgrkey_export2";
      msg2 = "mgrkey2";
      file = MGRKEY2;
    }
    get_size = &groupsig_mgr_key_get_size;
    export = &groupsig_mgr_key_export;
    break;
  }
  int len;
  if (type != 2)
    len = (*get_size)(data);
  int rc = 255;
  byte_t *bytes = NULL;
  uint32_t size;
  rc = (*export)(&bytes, &size, data);
  test_rc(rc, msg1);
  if (type != 2)
    test_size(size, len, msg2);
  char *enc = base64_encode(bytes, size, 0);
  FILE *fp = fopen(file, "w");
  if (!fp) {
    fprintf(stderr, "Error: File %s cannot be written\n", file);
    exit(1);
  } else {
    fwrite(enc, sizeof(char), strlen(enc), fp);
    fclose(fp);
  }
  free(enc);
}

void load_message(message_t **msg) {
  FILE *fp = fopen(MSG_PATH, "r");
  char *data;
  if (!fp) {
    fprintf(stderr, "Error: %s file cannot be read\n", MSG_PATH);
    exit(1);
  } else {
    if (!fscanf(fp, "%ms", &data)) {
      fclose(fp);
      fprintf(stderr, "Error: %s incorrect format\n", MSG_PATH);
      exit(1);
    }
    fclose(fp);
  }
  *msg = message_from_base64(data);
}

void load_data(void **data, int type) {
  char *msg1 = "grpkey_import";
  groupsig_key_t *(*import)(unsigned char, unsigned char *, unsigned int) = &groupsig_grp_key_import;
  char *file = GRPKEY;
  switch (type) {
  case 1:
    msg1 = "memkey_import";
    file = MEMKEY;
    import = &groupsig_mem_key_import;
    break;
  case 2:
    msg1 = "gml_import";
    file = GML;
    import = &gml_import;
    break;
  case 3:
    msg1 = "sig_import";
    file = SIG_PATH;
    import = &groupsig_signature_import;
    break;
  case 4:
  case 5:
    file = MGRKEY1;
    msg1 = "mgrkey_import1";
    if (type == 5) {
      file = MGRKEY2;
      msg1 = "mgrkey_import2";
    }
    import = &groupsig_mgr_key_import;
    break;
  }
  FILE *fp = fopen(file, "r");
  char *enc;
  if (!fp) {
    fprintf(stderr, "Error: %s file cannot be read\n", file);
    exit(1);
  } else {
    if (!fscanf(fp, "%ms", &enc)) {
      fclose(fp);
      fprintf(stderr, "Error: %s incorrect format\n", file);
      exit(1);
    }
    fclose(fp);
  }
  uint64_t dec_len;
  byte_t *dec_buff = base64_decode(enc, &dec_len);
  if (CODE == 255) {
    CODE = dec_buff[0];
    metadata_from_code();
    scheme_from_code();
    int rc = 255;
    rc = groupsig_init(CODE, time(NULL));
    test_rc(rc, "init");
  }
  if (type == 2 && !strlen(dec_buff)) {
    *data = gml_init(CODE);
  } else {
    *data = (*import)(CODE, (unsigned char*) dec_buff, dec_len);
    test_ptr(data, msg1);
  }
  free(dec_buff);
}


void join(message_t *msg,
          groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
          gml_t *gml) {
  int rc = 255;
  uint8_t start, seq;
  rc = GSIG->get_joinstart(&start);
  test_rc(rc, "joinstart");
  rc = GSIG->get_joinseq(&seq);
  test_rc(rc, "joinseq");
  int n_phases = (seq - start) / 2 + 1;
  int *phases = malloc(sizeof(int) * n_phases);
  if (!phases) {
    fprintf(stderr, "Error: Memory allocation failed for phases\n");
    exit(1);
  }
  int correct = 0;
  for(int i = 0; i < n_phases; i++) {
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
    test_rc(rc, "join_mgr");
    groupsig_key_t *memkey = groupsig_mem_key_init(grpkey->scheme);
    memkey = groupsig_mem_key_import(CODE, msg_out->bytes, msg_out->length);
    print_data(memkey, 1);
    groupsig_mem_key_free(memkey);
    save_data(gml, 2);
    FILE *fp = fopen(LAST_PATH, "w");
    if (!fp) {
      fprintf(stderr, "Error: File %s cannot be written\n", LAST_PATH);
      exit(1);
    }
    fclose(fp);
  } else {
    rc = groupsig_join_mgr(&msg_out, gml, mgrkey, PHASE, msg, grpkey);
    test_rc(rc, "join_mgr");
    char* out = message_to_base64(msg_out);
    FILE *fp = fopen(MSG_PATH, "w");
    if (!fp) {
      fprintf(stderr, "Error: File %s cannot be written\n", MSG_PATH);
      exit(1);
    } else {
      fwrite(out, sizeof(char), strlen(out), fp);
      fclose(fp);
    }
    if (PHASE == phases[n_phases-1]) {
      if (GSIG->desc->has_gml) {
        save_data(gml, 2);
      }
      FILE *fp = fopen(LAST_PATH, "w");
      if (!fp) {
        fprintf(stderr, "Error: File %s cannot be written\n", LAST_PATH);
        exit(1);
      }
      fclose(fp);
    }
    free(out);
  }
  message_free(msg_out);
}

void verify_signature(groupsig_key_t *grpkey,
                      groupsig_signature_t *sig,
                      message_t *msg) {
  uint8_t ret = 255;
  int rc = 255;
  rc = groupsig_verify(&ret, sig, msg, grpkey);
  test_rc(rc, "verify");
  printf("%d\n", ret); // 1 means valid signature
}

void revoke_signature_identity(groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
                               gml_t *gml, crl_t *crl,
                               groupsig_signature_t *sig) {
  uint64_t idx = 255;
  groupsig_proof_t *proof_op;
  int rc = 255;
  proof_op = groupsig_proof_init(grpkey->scheme);
  rc = groupsig_open(&idx, proof_op, crl, sig, grpkey, mgrkey, gml);
  test_rc(rc, "open");
  trapdoor_t *trapdoor_mem = NULL;
  trapdoor_mem = trapdoor_init(grpkey->scheme);
  test_ptr(trapdoor_mem, "trapdoor");
  rc = groupsig_reveal(trapdoor_mem, crl, gml, idx);
  test_rc(rc, "reveal");
  rc = crl_export(crl, CRL, CRL_FILE);
  test_rc(rc, "crl");
  printf("1\n");
}

void status_signature_identity(groupsig_key_t *grpkey,
                               gml_t *gml, crl_t *crl,
                               groupsig_signature_t *sig) {
  uint8_t ret = 255;
  int rc = 255;
  rc = groupsig_trace(&ret, sig, grpkey, crl, NULL, gml);
  test_rc(rc, "trace");
  printf("%d\n", ret); // 1 means revoked
}

message_t *message_from_hash() {
  FILE *fp = fopen(ASSET_PATH, "rb");
  if (!fp) {
    fprintf(stderr, "Error: %s file cannot be read\n", ASSET_PATH);
    exit(1);
  }

  SHA256_CTX sha256;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char buffer[4096];
  size_t bytesRead = 0;
  SHA256_Init(&sha256);
  while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    SHA256_Update(&sha256, buffer, bytesRead);
  fclose(fp);
  SHA256_Final(hash, &sha256);
  char outputBuffer[65];
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
  outputBuffer[64] = 0;
  if (!strcmp(SCHEME, "dl21") || !strcmp(SCHEME, "dl21seq")) {
    char msg[1024];
    snprintf(msg, 1024, "{\"scope\": \"%s\", \"message\": \"%s\"}", SCOPE, outputBuffer);
    return message_from_string(msg);
  } else
    return message_from_string(outputBuffer);
}

void sign() {
  if (!SIG_PATH || !MEMKEY || !ASSET_PATH) {
    fprintf(stderr, "Error: missing required argument --sign/--mkey/--asset\n");
    exit(1);
  }
  groupsig_key_t *gkey;
  load_data(&gkey, 0);
  groupsig_key_t *mkey;
  load_data(&mkey, 1);
  message_t *text = message_from_hash();
  groupsig_signature_t *sig = groupsig_signature_init(CODE);
  test_ptr(sig, "signature_init");
  int rc = groupsig_sign(sig, text, mkey, gkey, UINT_MAX);
  test_rc(rc, "sign");
  save_data(sig, 3);
  message_free(text);
  groupsig_grp_key_free(gkey);
  groupsig_mem_key_free(mkey);
  groupsig_signature_free(sig);
}

void verify() {
  if (!SIG_PATH || !ASSET_PATH) {
    fprintf(stderr, "Error: missing required argument --verify-asset/--asset\n");
    exit(1);
  }
  groupsig_key_t *gkey;
  load_data(&gkey, 0);
  groupsig_signature_t *sig;
  load_data(&sig, 3);
  message_t *text = message_from_hash();
  verify_signature(gkey, sig, text);
  message_free(text);
  groupsig_grp_key_free(gkey);
  groupsig_signature_free(sig);
}

void groupsig_mode() {
  groupsig_key_t *grpkey;
  groupsig_key_t *mgrkey1;
  groupsig_key_t *mgrkey2;
  gml_t *gml;
  crl_t *crl;
  if (!file_readable(GRPKEY) || !file_readable(MGRKEY1)) {
    if (SCHEME[0] == '\0') {
      fprintf(stderr, "Error: scheme missing, allowed values: ");
      for (int i = 0; i < N_SCHEMES; i++)
        fprintf(stderr,"%s", SCHEMES[i]);
      fprintf(stderr,"\n");
      exit(1);
    } else if (!valid_scheme()) {
      fprintf(stderr, "Error: invalid scheme, allowed values: ");
      for (int i = 0; i < N_SCHEMES - 1; i++)
        fprintf(stderr,"%s, ", SCHEMES[i]);
      fprintf(stderr,"%s\n", SCHEMES[N_SCHEMES - 1]);
      exit(1);
    } else {
      int rc = 255;
      rc = groupsig_get_code_from_str(&CODE, SCHEME);
      test_rc(rc, "get_code_from_str");
      metadata_from_code();
      rc = groupsig_init(CODE, time(NULL));
      test_rc(rc, "init");
    }
    grpkey = groupsig_grp_key_init(CODE);
    test_ptr(grpkey, "grpkey");
    mgrkey1 = groupsig_mgr_key_init(CODE);
    test_ptr(mgrkey1, "mgrkey1");
    mgrkey2 = groupsig_mgr_key_init(CODE);
    test_ptr(mgrkey2, "mgrkey2");
    if (GSIG->desc->has_gml) {
      gml = gml_init(CODE);
      test_ptr(gml, "gml");
    }
    if (GSIG->desc->has_crl) {
      crl = crl_init(CODE);
      test_ptr(crl, "crl");
    }
    int rc = 255;
    rc = groupsig_setup(CODE, grpkey, mgrkey1, gml);
    test_rc(rc, "setup1");
    if (multi_mgrkey()) {
      rc = groupsig_setup(CODE, grpkey, mgrkey2, gml);
      test_rc(rc, "setup2");
    }
    save_data(grpkey, 0);
    save_data(mgrkey1, 4);
    if (multi_mgrkey())
      save_data(mgrkey2, 5);
    if (GSIG->desc->has_gml) {
      save_data(gml, 2);
    }
    if (GSIG->desc->has_crl) {
      rc = crl_export(crl, CRL, CRL_FILE);
      test_rc(rc, "crl");
    }
  } else {
    load_data(&grpkey, 0);
    load_data(&mgrkey1, 4);
    if (multi_mgrkey())
      load_data(&mgrkey2, 5);
    if (GSIG->desc->has_gml) {
      if (!file_readable(MGRKEY1)) {
        fprintf(stderr,
                "Error: GML file not readable\n");
        exit(1);
      }
      load_data(&gml, 2);
    }
    if (GSIG->desc->has_crl) {
      if (!file_readable(MGRKEY1)) {
        fprintf(stderr,
                "Error: CRL file not readable\n");
        exit(1);
      }
      crl = crl_import(CODE, CRL_FILE, CRL);
    }
    if (!grpkey || !mgrkey1 || (multi_mgrkey() && !mgrkey2) ||
        (GSIG->desc->has_gml && !gml) ||
        (GSIG->desc->has_crl && !crl)){
      fprintf(stderr, "Error: importing groupsig material, does scheme match?\n");
      exit(1);
    }
  }
  if (!JOIN && !REV && !STAT && !quiet_flag) {
    print_data(grpkey, 0);
  } else if (JOIN) {
    if (!MSG_PATH) {
      fprintf(stderr, "Error: message missing\n");
      exit(1);
    }
    message_t *msg;
    if (!PHASE)
      msg = message_init();
    else
      load_message(&msg);
    join(msg, grpkey, mgrkey1, gml);
    message_free(msg);
  } else if (REV) {
    if (!GSIG->desc->has_crl) {
      fprintf(stderr, "Error: %s scheme does not support revoke\n", SCHEME);
      exit(1);
    }
    groupsig_signature_t *sig;
    load_data(&sig, 3);
    revoke_signature_identity(grpkey, mgrkey1, gml, crl, sig);
    groupsig_signature_free(sig);
  } else if (STAT) {
    if (!GSIG->desc->has_crl) {
      fprintf(stderr, "Error: %s scheme does not support status\n", SCHEME);
      exit(1);
    }
    groupsig_signature_t *sig;
    load_data(&sig, 3);
    status_signature_identity(grpkey, gml, crl, sig);
    groupsig_signature_free(sig);
  }
  groupsig_grp_key_free(grpkey);
  groupsig_mgr_key_free(mgrkey1);
  if (multi_mgrkey())
    groupsig_mgr_key_free(mgrkey2);
  if (GSIG->desc->has_gml)
    gml_free(gml);
  if (GSIG->desc->has_crl)
    crl_free(crl);
  groupsig_clear(CODE);
}

void mondrian_mode() {
  if (anonymize_flag)
    ANON = 1;
  MODE = "static";
  if (relaxed_flag)
    MODE = "relaxed";
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

void test_mode() {
  test_libgroupsig(SCHEME);
}

void benchmark_mode() {
  if (!strcmp(PATH, "."))
    PATH = "/root";
  allocate_matrices();
  for (int i = 0; i < ITER; i++)
    benchmark_libgroupsig(SCHEME, i);
  free_matrices();
}

void toolbox_usage(char** argv, int error) {
  FILE *out = stdout;
  if (error) {
    out = stderr;
    fprintf(out, "\n");
  }
  fprintf(out,
          "Usage: \n"
          "\t%s MODE [MFLAGS] [MOPTS]\n\n"
          "Mode:"
          "\ttest\t\t\t Test functionality\n"
          "\tbenchmark\t\t Benchmark functionality\n"
          "\tgroupsig\t\t Groupsig functionality\n"
          "\tmondrian\t\t Mondrian functionality\n"
          "\thelp\t\t\t This message\n\n"
          "Groupsig options:\n"
          "\t-s|--scheme SCHEME\t Scheme to be used: bbs04, gl19, klap20, ps16, dl21, dl21seq, cpy06, kty04.\n"
          "\t-r|--revoke SIG\t\t Signature file path to revoke\n"
          "\t-t|--status SIG\t\t Signature file path to check revocation status\n"
          "\t-g|--sign SIG\t\t Output signature file path\n"
          "\t-A|--asset ASSET\t\t Asset file path\n"
          "\t-M|--mkey MKEY\t\t Member key file path\n"
          "\t-v|--verify SIG\t\t Signature file path to verify\n"
          "\t-j|--join PHASE\t\t Join phase to execute\n"
          "\t-m|--message MSG\t Message file path\n"
          "\t-d|--directory DIR\t Group signature crypto material path. Must exist.\n"
          "\t-a|--affix AFFIX\t Affix to add at the end of each crypto material file\n"
          "\t--quiet\t\t Do not print group key\n\n"
          "Mondrian flags:\n"
          "\t--anonymize\t\t If present, anonymize output attributes\n"
          "\t--relaxed\t\t If present, run on relaxed mode instead of strict\n"
          "\t--results\t\t If present, only generate results (no output file)\n\n"
          "Mondrian options:\n"
          "\t-i|--input INPUT\t Input file path. Default: ../datasets/adults.csv\n"
          "\t-o|--output OUTPUT\t Output file path. Default: output.csv\n"
          "\t-k|--k VALUE\t\t k-Anonymity value. Default: 10\n"
          "Test/Benchmark options:\n"
          "\t-I|--iterations ITER\t Number of benchmark iterations. Default: 5\n"
          "\t-S|--members SIZE\t Number of members to register in the group. Default: 10\n"
          "\t-P|--benchpath PATH\t\t Output directory of *csv. Default: '.'\n",
          argv[0]);
  exit(error);
}

int toolbox_main(int argc, char** argv) {
  int opt;
  int opt_idx = 0;
  static struct option long_options[] = {
    /* Flag arguments */
    {"groupsig", no_argument, &groupsig_flag, 1},
    {"mondrian", no_argument, &mondrian_flag, 1},
    {"test", no_argument, &test_flag, 1},
    {"benchmark", no_argument, &benchmark_flag, 1},
    /* libgroupsig options */
    {"scheme", required_argument, 0, 's'},
    {"join", required_argument, 0, 'j'},
    {"sign", required_argument, 0, 'g'},
    {"verify", required_argument, 0, 'v'},
    {"revoke", required_argument, 0, 'r'},
    {"status", required_argument, 0, 't'},
    {"message", required_argument, 0, 'm'},
    {"mkey", required_argument, 0, 'M'},
    {"asset", required_argument, 0, 'A'},
    {"directory", required_argument, 0, 'd'},
    {"affix", required_argument, 0, 'a'},
    {"scope", required_argument, 0, 'c'},
    {"quiet", no_argument, &quiet_flag, 1},
    /* Mondrian flags */
    {"anonymize", no_argument, &anonymize_flag, 1},
    {"relaxed", no_argument, &relaxed_flag, 1},
    {"results", no_argument, &results_flag, 1},
    /* Mondrian options */
    {"input", required_argument, 0, 'i'},
    {"k", required_argument, 0, 'k'},
    {"output", required_argument, 0, 'o'},
    /* Test/Benchmark options */
    {"iterations", required_argument, 0, 'I'},
    {"members", required_argument, 0, 'S'},
    {"benchpath", required_argument, 0, 'P'},
    /* extra */
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "s:j:v:r:t:m:d:a:i:k:o:hg:A:M:I:S:P:c",
                            long_options, &opt_idx)) != -1) {
    switch (opt) {
    case 0:
      /* If this option set a flag, do nothing else now. */
      if (long_options[opt_idx].flag != 0)
        break;
    case 's':
      strncpy(SCHEME, optarg, 10);
      for (char *p = SCHEME; *p; ++p) *p = tolower(*p);
      break;
    case 'j':
      check_digit(optarg, "join");
      PHASE = atoi(optarg);
      JOIN = 1;
      break;
    case 'g':
      SIG_PATH = optarg;
      SIG = 1;
      break;
    case 'c':
      SCOPE = optarg;
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
    case 'M':
      MEMKEY = optarg;
      break;
    case 'A':
      ASSET_PATH = optarg;
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
    case 'I':
      check_digit(optarg, "iterations");
      ITER = atoi(optarg);
      break;
    case 'S':
      check_digit(optarg, "members");
      MEMBERS = atoi(optarg);
      break;
    case 'P':
      PATH = optarg;
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
  sprintf(MGRKEY1, "%s/mgrkey%s", DIRE, AFFIX);
  sprintf(MGRKEY2, "%s/mgrkey2%s", DIRE, AFFIX);
  sprintf(GML, "%s/gml%s", DIRE, AFFIX);
  sprintf(CRL, "%s/crl%s", DIRE, AFFIX);
  /* random_seed(); */
  setup_seed();

  if (groupsig_flag && mondrian_flag && test_flag && benchmark_flag) {
    fprintf(stderr, "Error: groupsig, mondrian, test and benchmark are mutually exclusive\n");
    exit(1);
  } else if (groupsig_flag) {
    if ((JOIN + SIG + VER + REV + STAT) > 1) {
      fprintf(stderr, "Error: join, sign, verify, revoke or status are mutually exclusive\n");
      exit(1);
    }
    if (!SIG && !VER)
      groupsig_mode();
    else {
      if (SIG)
        sign();
      else
        verify();
    }
  } else if (mondrian_flag)
    mondrian_mode();
  else if (test_flag || benchmark_flag) {
    if (!valid_scheme()) {
      fprintf(stderr, "Error: invalid scheme, allowed values: ");
      for (int i = 0; i < N_SCHEMES - 1; i++)
        fprintf(stderr,"%s, ", SCHEMES[i]);
      fprintf(stderr,"%s\n", SCHEMES[N_SCHEMES - 1]);
      exit(1);
    }
    if (test_flag)
      test_mode();
    else
      benchmark_mode();
  } else
    toolbox_usage(argv, 0);
  return 0;
}
