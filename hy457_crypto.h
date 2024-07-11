
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

ssize_t text_size;

uint8_t *otp_key;

unsigned char playfair_keymatrix [5][5];

uint8_t feistel_keys[8][4];

uint8_t getPseudoRandom();
uint8_t* getPseudoRandomBlock();
uint8_t* otp_encrypt(uint8_t *plaintext, uint8_t *otp_key);
uint8_t* otp_decrypt(uint8_t *ciphertext, uint8_t *otp_key);
uint8_t* caesar_encrypt(uint8_t *plaintext, ushort N);
uint8_t* caesar_decrypt(uint8_t *ciphertext, ushort N);
unsigned char* playfair_encrypt(unsigned char *plaintext);
unsigned char* playfair_decrypt(unsigned char *plaintext);
uint8_t * affine_encrypt(uint8_t *plaintext);
int MultiplicativeInverse(int a);
uint8_t * affine_decrypt(uint8_t *ciphertext);
void initialize_playfair_keymatrix();
void print_playfair_keymatrix();
void fill_playfair_keymatrix(unsigned char *plaintext);
uint8_t* feistel_F(uint8_t* block, uint8_t* key);
uint8_t* feistel_encrypt(uint8_t* plaintext);
uint8_t* feistel_decrypt(uint8_t* plaintext);
void testOTP(char* string);
void testCAESAR(char* string,ushort N);
void testPLAYFAIR(char* string1,char* string2);
void testAFFINE(char* string);
void testFEISTEL(char* string);

