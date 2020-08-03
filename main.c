#include<stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include "./aes.h"

uint8_t aes_keymode = 1; // 128-bit default
uint8_t aes_keylen, aes_keyexpsize, aes_nk, aes_nr;
uint8_t aes_nb =4;
char aes_mode = 'e'; //ECB default mode;
bool enc = true; //true: cipher, false: decipher

#include "./aes.c"

int main(int argc, char *argv[])
{
    int i;
    FILE *fIN = NULL;
    FILE *fOUT = NULL;
    FILE *key = NULL;
    FILE *ivIN = NULL;
    int error;
    uint8_t key_numread;
    uint8_t *key_uint8;
    uint8_t iv[AES_BLOCKLEN];
    char buf[255+1], opt;
    while((opt = getopt(argc, argv, "h123ebtcCoOd")) != -1){
        switch(opt){
            case 'h':
                display_usage();
                return 0;
            case 'e': case '1': break; //default options, no changes;
            case '2': case '3': //Key length: '1':128(default), '2':196 '3':256
                if(aes_keymode == 1)aes_keymode = opt - '0';
                else{
                    printf("too many key length options.\n");
                    return 1;
                        }
                break;
            //case 'e': //ECB default
            case 'b': //CBC
            case 't': //CTR
            case 'c': //CFB-1
            case 'C': //CFB-8
            case 'o': //OFB-1
            case 'O': //OFB-8
                if (aes_mode == 'e') aes_mode = opt;
                else{
                    printf("too many mode options.\n");
                    return 1;
                }
                break;
            case 'd':
                enc = false;
                break;
            default:
                printf("unknown option %c\n", opt);
                return 1;
        }
    }
    if (aes_keymode == 1){aes_keylen = 16; aes_keyexpsize = 176; aes_nk = 4; aes_nr = 10;}else
    if (aes_keymode == 2){aes_keylen = 24; aes_keyexpsize = 208; aes_nk = 6; aes_nr = 12;}else
    if (aes_keymode == 3){aes_keylen = 32; aes_keyexpsize = 240; aes_nk = 8; aes_nr = 14;}else return 1;
    //Open input file
    if ((error = fopen_s(&fIN,argv[optind],"rb"))!=0){
        //strerror_s(buf, 255, error);
        //printf("error opening in file %s : %s", argv[1], buf);
        printf("opening infile error");
        return 1;
    }
    //Open output file
    if ((error = fopen_s(&fOUT, argv[optind+1], "wb"))!=0){
        //strerror_s(buf, 255, error);
        //ptintf("error creating out file %s : %s", argv[2], buf);
        printf("opening outfile error");
        return 1;
    }
    // open key file
    if ((error = fopen_s(&key, argv[optind+2], "rb"))!=0){
        //strerror_s(buf, 255, error);
        //ptintf("error opening key %s : %s", argv[3], buf);
        printf("opening keyfile error");
        return 1;
    }
    //Read key from file
    key_uint8 = malloc(sizeof(uint8_t) * aes_keylen);
    key_numread = fread(key_uint8, 1, aes_keylen, key);
    if(key_numread < aes_keylen){
        printf("key file doesn't has enough bytes!");
        return 1;
    }

    struct AES_ctx ctx;
    ctx.round_key = malloc(sizeof(uint8_t) * aes_keyexpsize);
    aes_init_ctx(&ctx, key_uint8);
    free(key_uint8);

    //IV init
    if(aes_mode == 'b' || aes_mode == 't' || aes_mode == 'c' || aes_mode == 'C' || aes_mode == 'o' || aes_mode == 'O'){
        if(enc){
            if(aes_gen_random_iv(ctx.Iv)) {printf("iv gen error"); return 1;}
        }else{
            //printf("here");
            if ((error = fopen_s(&ivIN,"iv.txt", "rb"))!=0){
                //strerror_s(buf, 255, error);
                //ptintf("error opening iv.txt %s : %s", argv[3], buf);
                { printf("iv read error"); return 1;}
            }
            if(fread(ctx.Iv, 1, AES_BLOCKLEN, ivIN) < AES_BLOCKLEN){
                printf('text in iv.txt not long enough');
                return 1;
            }
        }
        //printf("\n IV: ");
        //for(i = 0; i < AES_BLOCKLEN; i++) printf("%x ", ctx.Iv[i]);
    }

    uint8_t block[16];
    unsigned long x, y, z;
    fseek(fIN, 0L, SEEK_END);
    long fsize = ftell(fIN);
    fseek(fIN, 0L, SEEK_SET);
    int outlen = 0, numread;
    uint8_t storeNextIv[AES_BLOCKLEN];
    int bi;
    uint8_t *ctr_in, *fb_buffer;
    uint8_t fb_size, fb_temp;

    //ECB
    if(aes_mode == 'e'){
        for(x = 0; x < fsize; x += AES_BLOCKLEN){
            numread = fread(block, 1, AES_BLOCKLEN, fIN);
            if(numread<1)printf("read into block error\n");
            else if(numread<16){
                memset(&block[numread], 0, AES_BLOCKLEN - numread);
            }
            //printf("\nInput: \n");
            //for(y=0; y<AES_BLOCKLEN;y++)printf("%x ",block[y]); printf("\n");
            if(enc){
                cipher((state_t*)block, ctx.round_key);
            }else{
                //for(y=0; y<AES_BLOCKLEN;y++)printf("%d ",block[y]); printf("\n");
                inv_cipher((state_t*)block, ctx.round_key);
            }
            //write to file
            //printf("\nOutput: \n");
            //for(y=0; y<AES_BLOCKLEN;y++)printf("%x ",block[y]); printf("\n");
            fwrite(block, AES_BLOCKLEN, 1, fOUT);
        }
    //CBC
    }else if(aes_mode == 'b'){
        for(x = 0; x < fsize; x += AES_BLOCKLEN){
            numread = fread(block, 1, AES_BLOCKLEN, fIN);
            if(numread<1)printf("read into block error\n");
            else if(numread<16){
                memset(&block[numread], 0, AES_BLOCKLEN - numread);
            }
            //printf("\nblock %d in\n",x/16);
            //for(i=0;i<AES_BLOCKLEN;i++)printf("%x ", block[i]);
            if(enc){
                xor_with_iv(block,ctx.Iv);
                cipher((state_t*)block, ctx.round_key);
                //ctx.Iv = block;
                memcpy(ctx.Iv, block, AES_BLOCKLEN);
            }else{
                memcpy(storeNextIv, block, AES_BLOCKLEN);
                inv_cipher((state_t*)block, ctx.round_key);
                xor_with_iv(block, ctx.Iv);
                memcpy(ctx.Iv, storeNextIv, AES_BLOCKLEN);
            }
            //write to file
            //printf("\nblock %d out\n",x/16);
            //for(i=0;i<AES_BLOCKLEN;i++)printf("%x ", block[i]);
            fwrite(block, AES_BLOCKLEN, 1, fOUT);
        }
    //CTR
    }else if (aes_mode == 't'){
        ctr_in = malloc(sizeof(uint8_t) * fsize);
        fread(ctr_in, 1, fsize, fIN);
        for(y = 0, bi = AES_BLOCKLEN; y < fsize; y++, bi++){
            if(bi == AES_BLOCKLEN){
                memcpy(block, ctx.Iv, AES_BLOCKLEN);
                cipher((state_t*)block, ctx.round_key);

                for (bi = (AES_BLOCKLEN - 1); bi >= 0; bi--){
                    if(ctx.Iv == 255){
                        ctx.Iv[bi] = 0;
                        continue;
                    }
                    ctx.Iv[bi] += 1;
                    break;
                }
                bi = 0;
            }
            ctr_in[y] = (ctr_in[y] ^ block[bi]);
        }
        fwrite(ctr_in, fsize, 1, fOUT);
        free(ctr_in);
    //CFB
    }else if(aes_mode == 'c' || aes_mode == 'C'){
        if(aes_mode == 'c') fb_size = 1; else fb_size = 8;
        fb_buffer = malloc(sizeof(uint8_t) * fb_size);
        memcpy(block, ctx.Iv, AES_BLOCKLEN);
        for(y =0; y < fsize; y += fb_size){
            cipher((state_t*)block, ctx.round_key);
            numread = fread(fb_buffer, 1, fb_size, fIN);
            if(numread < fb_size) memset(&fb_buffer[numread], 0, fb_size - numread);
            for(x = 0; x < fb_size; x++){
                    fb_temp = fb_buffer[x];
                    fb_buffer[x] ^= block[x];
                    block[x] = block[x+fb_size];
                    if(aes_mode == 'c'){
                        for(z = fb_size; z < AES_BLOCKLEN - fb_size; z++){
                            block[z] = block[z+fb_size];
                        }
                    }
                    if(enc) block[AES_BLOCKLEN-fb_size+x] = fb_buffer[x];
                    else    block[AES_BLOCKLEN-fb_size+x] = fb_temp;
            }

            fwrite(fb_buffer, fb_size, 1, fOUT);
        }
        free(fb_buffer);
    //OFB
    }else if(aes_mode == 'o' || aes_mode == 'O'){
        if(aes_mode == 'o') fb_size = 1; else fb_size = 8;
        fb_buffer = malloc(sizeof(uint8_t) * fb_size);
        memcpy(block, ctx.Iv, AES_BLOCKLEN);

        for(y =0; y < fsize; y += fb_size){
            cipher((state_t*)block, ctx.round_key);
            numread = fread(fb_buffer, 1, fb_size, fIN);
            if(numread < fb_size) memset(&fb_buffer[numread], 0, fb_size - numread);
            for(x = 0; x < fb_size; x++){
                fb_buffer[x] ^= block[x];
            }
            fwrite(fb_buffer, fb_size, 1, fOUT);
        }
        free(fb_buffer);
    }else{
        printf("aes_mode invalid");
    }
    free(ctx.round_key);
    fclose(fIN);
    fclose(fOUT);
    fclose(key);

    return 0;
}

static void key_expansion(uint8_t* round_key, const uint8_t* key){
    unsigned i, j, k;
    uint8_t temp[4];
    //printf("\nkey\n");
    //for(i = 0; i < AES_BLOCKLEN; i++) printf("%x ",key[i]);
    //printf("\n");
    for(i = 0; i< aes_nk; i++){
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }
    for(i = aes_nk; i< aes_nb * (aes_nr +1); i++){
        {
            k = (i - 1) * 4;
            temp[0]=round_key[k + 0];
            temp[1]=round_key[k + 1];
            temp[2]=round_key[k + 2];
            temp[3]=round_key[k + 3];
            //printf("%d %d %d %d\n",temp[0],temp[1],temp[2],temp[3]);
        }
        if(i % aes_nk == 0){
            {//rotword
                const uint8_t u8tmp = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = u8tmp;
                //printf("%d %d %d %d\n",temp[0],temp[1],temp[2],temp[3]);
            }
            {//subword
                temp[0] = get_sbox_value(temp[0]);
                temp[1] = get_sbox_value(temp[1]);
                temp[2] = get_sbox_value(temp[2]);
                temp[3] = get_sbox_value(temp[3]);
                //printf("%d %d %d %d\n",temp[0],temp[1],temp[2],temp[3]);
            }
            temp[0] = temp[0] ^ Rcon[i/aes_nk];
        }if(aes_keymode == 3){ //AES256
            if (i % aes_nk == 4){
                // subword
                temp[0] = get_sbox_value(temp[0]);
                temp[1] = get_sbox_value(temp[1]);
                temp[2] = get_sbox_value(temp[2]);
                temp[3] = get_sbox_value(temp[3]);
                //printf("%d %d %d %d\n",temp[0],temp[1],temp[2],temp[3]);
            }
        }
        j = i * 4; k=(i-aes_nk) * 4;
        //printf("j:%d k:%d",j,k);
        //printf("\nKEYB4: %d %d %d %d\n",round_key[j+0],round_key[j+1],round_key[j+2],round_key[j+3]);
        round_key[j+0] = round_key[k+0] ^ temp[0];
        round_key[j+1] = round_key[k+1] ^ temp[1];
        round_key[j+2] = round_key[k+2] ^ temp[2];
        round_key[j+3] = round_key[k+3] ^ temp[3];
        //printf("KEY: %d %d %d %d\n",round_key[j+0],round_key[j+1],round_key[j+2],round_key[j+3]);
    }
    //printf("\nkeyexp\n");
    //for(i = 0; i < aes_keyexpsize; i++) printf("%x ", round_key[i]);
}

void aes_init_ctx(struct AES_ctx* ctx, const uint8_t* key){
    key_expansion(ctx->round_key, key);
}

void aes_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, uint8_t* Iv){
    key_expansion(ctx->round_key, key);
    memcpy(ctx->Iv,Iv, AES_BLOCKLEN);
}

bool aes_gen_random_iv(uint8_t* iv){
    int i;
    srand(time(NULL));
    for(i = 0; i<AES_BLOCKLEN; i++){
        iv[i] = rand() % 256;
    }
    FILE *IV_FILE = NULL;
    IV_FILE = fopen("iv.txt", "w");
    if(NULL == IV_FILE){
        printf("IV write error");
        return true;
    }
    fwrite(iv,1,sizeof(uint8_t)*AES_BLOCKLEN, IV_FILE);
    fclose(IV_FILE);
    return false;
}

static void add_round_key(uint8_t round, state_t* state, const uint8_t* round_key){
    uint8_t i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < 4; j++){
            (*state)[i][j] ^= round_key[(round * aes_nb * 4) + (i * aes_nb) + j];
        }
    }
}

static void cipher(state_t* state, const uint8_t* round_key){
    uint8_t round =0;
    add_round_key(0, state, round_key);
    for(round = 1; round < aes_nr; round++){
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, round_key);
    }
    sub_bytes(state);
    shift_rows(state);
    //printf("\n"); print_state(state);
    add_round_key(aes_nr, state, round_key);
}

static void inv_cipher(state_t* state, const uint8_t* round_key){
    uint8_t round = 0;

    add_round_key(aes_nr, state, round_key);
    for(round = (aes_nr - 1); round> 0; round--){
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, round_key);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(0, state, round_key);
}
