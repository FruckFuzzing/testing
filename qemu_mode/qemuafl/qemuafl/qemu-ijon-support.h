//
// Created by wu on 2025/9/30.
//

#ifndef QEMUAFL_QEMU_IJON_SUPPORT_H
#define QEMUAFL_QEMU_IJON_SUPPORT_H


extern uint32_t ijon_hooker_cnt;
extern target_ulong hook_code_addr[0x1000];
extern target_ulong g_var_addr[0x1000];
extern uint32_t g_var_len[0x1000];
extern uint32_t ijon_type[0x1000];


void ijon_max(uint32_t addr, u64 val);
void ijon_min(uint32_t addr, u64 val);
void ijon_set(uint32_t addr, uint32_t val);
void ijon_inc(uint32_t addr, uint32_t val);

/* IJON state management functions */
void ijon_xor_state(uint32_t addr, u64 val);
void ijon_reset_state(uint32_t addr, u64 val);
uint32_t ijon_memdist(char *a, char *b, size_t len);
uint32_t ijon_hashmem(uint32_t old, char *val, size_t len);

#define IJON_LIST                 \
X(ijon_max,        ijon_max)  \
X(ijon_min,        ijon_min)  \
X(ijon_set,        ijon_set)  \
X(ijon_inc,        ijon_inc)  \
X(ijon_xor_state,  ijon_xor_state) \
X(ijon_reset_state, ijon_reset_state)

typedef enum {
#define X(name, func) e_##name,
  IJON_LIST
#undef X
  e_IJON_COUNT
} IJON;

void* ijon_reg_to_addr(const char *reg_str);
const char* ijon_to_str(IJON v);
IJON str_to_ijon(const char* str);
void ijon_dispatch(IJON v, uint32_t addr, u64 val);

#define INSTALL_IJON_HOOKS() \
do { \
  for (int i = 0; i < ijon_hooker_cnt; i++) { \
    if (dc->base.pc_next == hook_code_addr[i]) { \
      TCGv var_addr = tcg_const_tl(g_var_addr[i]); \
      TCGv var_len  = tcg_const_tl(g_var_len[i]); \
      TCGv itype    = tcg_const_tl(ijon_type[i]); \
      TCGv idx      = tcg_const_tl(i); \
      gen_helper_ijon_func_call(var_addr, var_len, itype, idx); \
      fprintf(stderr, "install ijon hook in %lx\n", hook_code_addr[i]); \
      tcg_temp_free(var_addr); \
      tcg_temp_free(var_len); \
      tcg_temp_free(itype); \
      tcg_temp_free(idx); \
    } \
  } \
} while (0)

#endif //QEMUAFL_QEMU_IJON_SUPPORT_H