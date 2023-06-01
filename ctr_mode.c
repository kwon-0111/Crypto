#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16 // 블록 하나의 크기, bytes
#define BITS 128 // 블록 하나의 크기, bits

int Gen(U8 *key)
{
    if (key == NULL)
        return 0;
    RAND_bytes(key, BYTES);
    return 1;
}

// U8 *key       : key for AES_set_encrypt_key
// const U8 *msg : message to be encrypted
// U8 *ctr       : ciphertext (output)
// returns length of ciphertext
int ctrEnc(U8 *key, const U8 *msg, U8 *ctr)
{
    int i, j, msg_len = strlen(msg), bottom = BYTES - 1; // bottom에 15 저장.... 왜?
    U8 IV[BYTES], msg_block[17] = {0}, PRF[BYTES]; // 17인 이유: string저장 -> 끝에 NULL 붙이기 위해...?
    AES_KEY enckey;

    AES_set_encrypt_key(key, BITS, &enckey);
    
    if (RAND_bytes(IV, 16) <= 0)
        printf("random error\n");
    
    memcpy(ctr, IV, BYTES);

    // padding 필요 없는 부분(블록 딱 끊기는 만큼 enc)
    for (i = 0; i < msg_len / BYTES; i++)
    {
        // for(int l = 0; l < BYTES; l++)
        // {
        //     printf("%02X",IV[l]);
        // }
        // printf("\n");
        
        j = bottom;
        do
        {
            //printf("i: %d,              j: %d ,           IV[j]: %02X           , IV[j-1]: %02X\n", i, j, IV[j], IV[j-1]);
            IV[j] += 1;
        } while (IV[j--] == 0 && j != 0);
        // printf("------------------------\n");
        AES_encrypt(IV, PRF, &enckey);
        for (j = 0; j < BYTES; j++)
            ctr[(i + 1) * BYTES + j] = PRF[j] ^ msg[(i * BYTES) + j];
    }

    // i에 padding이 들어갈 블록 번호 저장됨 -> i * BYTES에 패딩 안붙는 블록들의 개수 저장
    int mb_len = strlen(msg + i * BYTES); // mb_len : 패딩 필요한 블록의 바이트 수
    // printf("dddd: %s\n", msg + i * BYTES);
    // printf("msg: %ld     i: %d       mb_len: %d\n", strlen(msg), i, mb_len);
    int pad = BYTES - mb_len;   // pad: 패딩할 바이트 수
    memcpy(msg_block, msg + i * BYTES, BYTES);
    // printf("%s\n", msg_block);
    for (j = bottom; j >= mb_len; j--)
        msg_block[j] = pad;
    printf("m_t \t\t: ");
    for (j = 0; j < BYTES; j++)
        printf("%02X", msg_block[j]);
    printf("\n");
    msg_block[BYTES] = 0;
    j = bottom;
    
    do
    {
        IV[j] += 1;
    } while (IV[j--] == 0 && j != 0);
    AES_encrypt(IV, PRF, &enckey);
    for (j = 0; j < BYTES; j++)
        ctr[(i + 1) * BYTES + j] = msg_block[j] ^ PRF[j];
    return (i + 2) * BYTES;
}

// U8 *key       : key for AES_set_encrypt_key
// const U8 *ctr : ciphertext to be decrypted
// int ct_len    : length of ciphertext
// U8* dec_msg   : decrypted message (output)
// returns length of decrypted message
int ctrDec(U8 *key, const U8 *ctr, int ct_len, U8 *dec_msg)
{
    U8 IV[BYTES] = {0}, PRF[BYTES] = {0};
    int i, j, bottom = BYTES - 1;
    AES_KEY enckey;
    AES_set_encrypt_key(key, BITS, &enckey);

    memcpy(IV, ctr, BYTES);
    for (i = 1; i < ct_len / BYTES; i++)
    {
        j = bottom;
        do
        {
            IV[j] += 1;
        } while (IV[j--] == 0 && j != 0);
        AES_encrypt(IV, PRF, &enckey);
        for (j = 0; j < BYTES; j++)
            dec_msg[(i - 1) * BYTES + j] = ctr[(i * BYTES) + j] ^ PRF[j];
    }
    U8 pad = dec_msg[ct_len - 17];
    if (pad <= 0 || pad > BYTES)
        return 0;
    printf("Dec m_t \t: ");
    for (j = 0; j < BYTES; j++)
        printf("%02X", dec_msg[(i - 2) * BYTES + j]);
    printf("\n");
    for (j = 0; j < pad; j++)
        dec_msg[ct_len - 17 - j] = 0;
    return (strlen(dec_msg));
}

int main(int argc, char *argv[])
{
    RAND_status(); // random seed
    U8 key[BYTES];
    //U8 m[] = "If F is a pseudorandom function, then CTR mode is CPA-secure";
    U8 m[] = "abcdefghijabcdefghijabcdefghija";
    int ctr_len = (strlen(m) % BYTES == 0) ? BYTES * (strlen(m) / BYTES + 1) : BYTES * (strlen(m) / BYTES + 2);
    U8 *ctr = (U8 *)calloc(ctr_len, sizeof(U8));
    Gen(key);
   
    ctr_len = ctrEnc(key, m, ctr);
    U8 *dec_msg = (U8 *)calloc(ctr_len - BYTES, sizeof(U8));
    int m_len = ctrDec(key, ctr, ctr_len, dec_msg);
    printf("Enc \t\t: ");
    for (int i = 0; i < ctr_len; i++)
        printf("%02X", ctr[i]);
    printf("\n");
    
    if (m_len > 0)
        printf("Decryption \t: %s\n", dec_msg);
    else
        printf("Error!!!\n");

    free(ctr);
    free(dec_msg);
    return 0;
}
