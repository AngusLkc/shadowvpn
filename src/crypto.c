#include <sodium.h>
#include <string.h>
#include "crypto_secretbox_salsa208poly1305.h"

static unsigned char key[32];

/*
 * 初始化加密库
 */
int crypto_init() {
  if (-1 == sodium_init())
    return 1;
  randombytes_set_implementation(&randombytes_salsa20_implementation);
  randombytes_stir();
  return 0;
}

/*
 * 计算密码的指纹值
 */
int crypto_set_password(const char *password, unsigned long long password_len) {
  return crypto_generichash(key, sizeof key, (unsigned char *)password, password_len, NULL, 0);
}

/*
 * c:输出缓冲区,密文
 * m:输入缓冲区,明文
 * mlen:输入明文长度
 */
int crypto_encrypt(unsigned char *c, unsigned char *m, unsigned long long mlen) {
  unsigned char nonce[8];
  randombytes_buf(nonce, 8);
  int r = crypto_secretbox_salsa208poly1305(c, m, mlen + 32, nonce, key);
  if (r != 0) return r;
  memcpy(c + 8, nonce, 8);
  return 0;
}

/*
 * m:输出缓冲区,明文
 * c:输入缓冲区,密文
 * clen:输入密文长度
 */
int crypto_decrypt(unsigned char *m, unsigned char *c, unsigned long long clen) {
  unsigned char nonce[8];
  memcpy(nonce, c + 8, 8);
  int r = crypto_secretbox_salsa208poly1305_open(m, c, clen + 32, nonce, key);
  if (r != 0) return r;
  return 0;
}
