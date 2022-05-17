#ifndef SECP256K1_SM2_IMPL_H
#define SECP256K1_SM2_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"
#include "sm3.h"
#include "endian.h"
#include "sm2.h"    
#include "../include/random.h"

static int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
{
    SM3_CTX ctx;
    uint8_t counter_be[4];
    uint8_t dgst[SM3_DIGEST_SIZE];
    uint32_t counter = 1;
    size_t len;

    /*
    size_t i; fprintf(stderr, "kdf input : ");
    for (i = 0; i < inlen; i++) fprintf(stderr, "%02x", in[i]); fprintf(stderr, "\n");
    */

    while (outlen)
    {
        PUTU32(counter_be, counter);
        counter++;

        sm3_init(&ctx);
        sm3_update(&ctx, in, inlen);
        sm3_update(&ctx, counter_be, sizeof(counter_be));
        sm3_finish(&ctx, dgst);

        len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
        memcpy(out, dgst, len);
        out += len;
        outlen -= len;
    }

    memset(&ctx, 0, sizeof(SM3_CTX));
    memset(dgst, 0, sizeof(dgst));
    return 1;
}

static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid) {

    unsigned char b[32];
    secp256k1_gej rp;
    secp256k1_ge r;
    secp256k1_scalar tmp;

    int overflow = 0;


    secp256k1_ecmult_gen(ctx, &rp, nonce);
    secp256k1_ge_set_gej(&r, &rp);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_normalize(&r.y);
    secp256k1_fe_get_b32(b, &r.x);
    secp256k1_scalar_set_b32(sigr, b, &overflow);

    if (recid) {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        *recid = (overflow << 1) | secp256k1_fe_is_odd(&r.y);
    }
 
 
    secp256k1_scalar_add(sigr, sigr, message);

    secp256k1_scalar_add(&tmp, sigr, nonce);
    if(secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(&tmp)){
        printf("sigr || sigr+nonce is zero!\n");
        return 0;
    }

    /*
        tmp = sigr*sk
    */    
    secp256k1_scalar_mul(&tmp, sigr, seckey);
    
    secp256k1_scalar_negate(&tmp,&tmp);

    /*
        tmp = k - sigr*sk
    */
    secp256k1_scalar_add(&tmp, nonce, &tmp);

    secp256k1_scalar_add(sigs,&secp256k1_scalar_one,seckey);
  
    secp256k1_scalar_inverse(sigs, sigs);
    
    secp256k1_scalar_mul(sigs, sigs, &tmp);
    
    
    secp256k1_scalar_clear(&tmp);
    secp256k1_gej_clear(&rp);
    secp256k1_ge_clear(&r);

    /* P.x = order is on the curve, so technically sig->r could end up being zero, which would be an invalid signature.
     * This is cryptographically unreachable as hitting it requires finding the discrete log of P.x = N.
    */
    if(secp256k1_scalar_is_zero(sigs)){
        printf("sigs is zero!\n");
        return 0;
    }
   
    return 1;


}



static int secp256k1_sm2_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message)
{

    unsigned char c[32];
    

    secp256k1_scalar t;
    secp256k1_scalar computed_r;
    secp256k1_gej pubkeyj, pr;
    secp256k1_ge pr_ge;



    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs))
    {
        printf("sigr || sigs is zero!\n");
        return 0;
    }

 /*
    t = sigr + sigs
 */   
    secp256k1_scalar_add(&t, sigr, sigs);
    
    if (secp256k1_scalar_is_zero(&t))
    {
        printf("sigr + sigs is zero!\n");
        return 0;
    }
    
    
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
/*
    pr = t*PA+sigs*G
*/
    secp256k1_ecmult(&pr, &pubkeyj, &t, sigs);

    if (secp256k1_gej_is_infinity(&pr))
    {
        printf("pr is infinity!\n");
        return 0;
    }
    


    secp256k1_ge_set_gej_var(&pr_ge, &pr);
    secp256k1_fe_normalize_var(&pr_ge.x);
    secp256k1_fe_get_b32(c, &pr_ge.x);
    secp256k1_scalar_set_b32(&computed_r, c, NULL);

/*
    compute_r = x + message
*/
    secp256k1_scalar_add(&computed_r, &computed_r, message);
    secp256k1_scalar_get_b32(c, &computed_r);
    
    printf("r:");
    /*r is compute_r*/
    print_hex(c, sizeof(c));

    secp256k1_scalar_get_b32(c, sigr);
    printf("R:");
    /* R is sigr*/
    print_hex(c, sizeof(c));
    
    secp256k1_gej_clear(&pr);
    secp256k1_gej_clear(&pubkeyj);
    secp256k1_ge_clear(&pr_ge);

    return secp256k1_scalar_eq(sigr, &computed_r);
}

static int secp256k1_sm2_do_encrypt(const secp256k1_ecmult_gen_context *ctx, unsigned char *ciphertext, const secp256k1_ge *pubkey, const unsigned char *message, const unsigned char kLen, const secp256k1_scalar *nonce)
{
    
    secp256k1_gej rp, pubkeyj;
    secp256k1_ge C1, xy;
    SM3_CTX sm3_ctx;
    int i;
    unsigned char b[64];
    unsigned char C3[32];
    unsigned char C2[kLen];

    
    /*
        compute rp = [nonce]G
        C1 = rp 
    */
    secp256k1_ecmult_gen(ctx, &rp, nonce);
    secp256k1_ge_set_gej(&C1, &rp);
    secp256k1_fe_normalize(&C1.x);
    secp256k1_fe_normalize(&C1.y);

    /*
        compute rp = [k]P
    */
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_ecmult(&rp, &pubkeyj, nonce, NULL);
    secp256k1_ge_set_gej(&xy, &rp);
    secp256k1_fe_normalize(&xy.x);
    secp256k1_fe_normalize(&xy.y);

    /*
        set b = x_2 || y_2
    */
    secp256k1_fe_get_b32(b, &xy.x);
    secp256k1_fe_get_b32(b + 32, &xy.y);
    
    /*
        compute C2 = kdf(b, klen)
    */
    sm2_kdf(b, sizeof(b), kLen, C2);
    if(C2 == 0){
        return 0;
    }
    /*
        compute C2 = M xor C2
    */
    for (i = 0; i < kLen; i++)
    {
        C2[i] ^= message[i];
    }
    /*
        compute C3 = Hash(x_2 || M || y_2)
    */
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, b, 32);
    sm3_update(&sm3_ctx, message, kLen);
    sm3_update(&sm3_ctx, b + 32, 32);
    sm3_finish(&sm3_ctx, C3);
    /*
        compute ciphertext = C1 || C2 || C3
    */
    secp256k1_fe_get_b32(ciphertext, &C1.x);
    secp256k1_fe_get_b32(ciphertext + 32, &C1.y);

    memcpy(ciphertext + 64, C2, sizeof(C2));
    memcpy(ciphertext + 64 + kLen, C3, sizeof(C3));
    
    secp256k1_gej_clear(&rp);
    secp256k1_gej_clear(&pubkeyj);
    secp256k1_ge_clear(&xy);
    secp256k1_ge_clear(&C1);
    
    return 1;
}

static int secp256k1_sm2_do_decrypt(unsigned char *messsage, const unsigned char kLen, const unsigned char *ciphertext, const secp256k1_scalar sec)
{
    int i;
    
    unsigned char C1[64];
    unsigned char C2[kLen];
   

    unsigned char C3[32];
    unsigned char b[64];
    unsigned char t[32];
    unsigned char M[32];
    unsigned char u[32];
    secp256k1_gej c1r, c1;
    secp256k1_ge point;
    secp256k1_fe x, y;
    SM3_CTX sm3_ctx;
    /*
        convert C1||C2||C3 to C1,C2,C3
    */
    for (i = 0; i < 64; i++)
    {
        C1[i] = ciphertext[i];
    }
    memcpy(C1, ciphertext, 64);
    memcpy(C2, ciphertext + 64, kLen);
    memcpy(C3, ciphertext + 64 + kLen, 32);

    /*
        check C1 whether on Curve
    */
    secp256k1_fe_set_b32(&x, C1);
    secp256k1_fe_set_b32(&y, C1 + 32);
    secp256k1_ge_set_xy(&point, &x, &y);
    if (!secp256k1_ge_is_valid_var(&point))
    {
        printf("unvalid point on secp256k1_sm2_do_decrypt\n");
        return 0;
    }

    /*
        compute point = [sec]G
    */
    secp256k1_gej_set_ge(&c1r, &point);
    secp256k1_ecmult(&c1, &c1r, &sec, NULL);
    secp256k1_ge_set_gej(&point, &c1);
    secp256k1_fe_normalize(&point.x);
    secp256k1_fe_normalize(&point.y);

    /*
        set b = x_2 || y_2
    */
    secp256k1_fe_get_b32(b, &point.x);
    secp256k1_fe_get_b32(b + 32, &point.y);

    /*
        compute t = kdf(b, klen)
    */
    sm2_kdf(b, sizeof(b), kLen, t);
    if(t == 0){
        return 0;
    }

    /*
        compute M = C2 xor t
    */
    for (i = 0; i < kLen; i++)
    {
        M[i] = C2[i] ^ t[i];
    }

    /*
        compute u = Hash(x_2 || M || y_2)
    */
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, b, 32);
    sm3_update(&sm3_ctx, M, kLen);
    sm3_update(&sm3_ctx, b + 32, 32);
    sm3_finish(&sm3_ctx, u);

    secp256k1_gej_clear(&c1r);
    secp256k1_gej_clear(&c1);
    secp256k1_ge_clear(&point);

    if (memcmp(C3,u,32) == 0){
        memcpy(messsage, M, sizeof(M));
        return 1;
    }

    return 0;
}
#endif /* SECP256K1_SM2_IMPL_H */
