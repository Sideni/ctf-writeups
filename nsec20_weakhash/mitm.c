#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <math.h>

#include <unistd.h>

#include <openssl/des.h>

struct nlist { /* table entry: */
    struct nlist *next; /* next entry in chain */
    unsigned char *name; /* defined name */
    unsigned char *defn; /* replacement text */
};

//#define HASHSIZE 134217728
#define HASHSIZE 75000000
#define BLOCKSIZE 8
struct nlist **hashtab;


/* hash: form hash value for string s */
unsigned hash(unsigned char *s)
{
    unsigned hashval = 0;
    int i;
    //for (hashval = 0; *s != '\0'; s++)
    for (i = 0; i < BLOCKSIZE; i++, s++)
      hashval = *s + 31 * hashval;
    return hashval % HASHSIZE;
}

/* lookup: look for s in hashtab */
struct nlist *lookup(unsigned char *s)
{
    struct nlist *np;
    for (np = hashtab[hash(s)]; np != NULL; np = np->next)
        if (memcmp(s, np->name, BLOCKSIZE) == 0)
          return np; /* found */
    return NULL; /* not found */
}

unsigned char * stringdup(unsigned char *s) /* make a duplicate of s */
{
    unsigned char *p;
    p = (unsigned char *) malloc(BLOCKSIZE+1); /* +1 for ’\0’ */
    if (p != NULL)
       memcpy(p, s, BLOCKSIZE);
    return p;
}
/* install: put (name, defn) in hashtab */
struct nlist *install(unsigned char *name, unsigned char *defn)
{
    struct nlist *np;
    unsigned hashval;
    if ((np = lookup(name)) == NULL) { /* not found */
        np = (struct nlist *) malloc(sizeof(*np));
        if (np == NULL || (np->name = stringdup(name)) == NULL)
          return NULL;
        hashval = hash(name);
        np->next = hashtab[hashval];
        hashtab[hashval] = np;
    } else /* already there */
        free((void *) np->defn); /*free previous defn */
    if ((np->defn = stringdup(defn)) == NULL)
       return NULL;
    return np;
}

void printHex(unsigned char* buf, size_t len) {
    for(int i = 0; i < len; i++)
    {
        printf("0x%02hhX, ", buf[i]);
    }

    puts("");
}

void weakhash(uint8_t *dst, const char *src)
{
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
	size_t u, n;

	memcpy(data, "weakhash", 8);
	n = strlen(src);
	for (u = 0; u < n; u += 8) {
		size_t v;

		for (v = 0; v < 8; v ++) {
			if (u + v < n) {
				key[v] = ((unsigned char)src[u + v] << 1) + 2;
			} else {
				key[v] = 0;
			}
		}
        DES_set_key_unchecked(&key, &ks);
        DES_ecb_encrypt(&data, &data, &ks, 1);
	}
	memcpy(dst, data, 8);
}

void testDES(uint8_t *dst, const char *src)
{
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
	size_t u, n;

	memcpy(data, "weakhash", 8);
	n = strlen(src);
	for (u = 0; u < 8; u++) {
		key[u] = src[u];
	}
        
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt(&data, &data, &ks, 1);
	memcpy(dst, data, 8);
}

void encryptDES(uint8_t *dst, const char *src)
{
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
	size_t u, n;

	memcpy(data, "weakhash", 8);
    n = BLOCKSIZE;
	for (u = 0; u < n; u += 8) {
		size_t v;

		for (v = 0; v < 8; v ++) {
			key[v] = src[u + v];
		}
        
        DES_set_key_unchecked(&key, &ks);
        DES_ecb_encrypt(&data, &data, &ks, 1);
	}
	memcpy(dst, data, 8);
}

void decryptH1(uint8_t *dst, const char *src)
{
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
    static const uint8_t ref_hv1[8] = {
		0xDA, 0x99, 0xD1, 0xEA, 0x64, 0x14, 0x4F, 0x3E
	};
	size_t u, n;

	memcpy(data, ref_hv1, 8);
	n = BLOCKSIZE;
	for (u = 0; u < 8; u++) {
		key[u] = src[u];
	}
        
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt(&data, &data, &ks, 0);
	memcpy(dst, data, 8);
}

void decryptH2(uint8_t *dst, const char *src)
{
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
	static const uint8_t ref_hv2[8] = {
		0x59, 0xA3, 0x44, 0x2D, 0x8B, 0xAB, 0xCF, 0x84
	};
	size_t u, n;

	memcpy(data, ref_hv2, 8);
	n = BLOCKSIZE;
	for (u = 0; u < 8; u++) {
		key[u] = src[u];
	}
        
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt(&data, &data, &ks, 0);
	memcpy(dst, data, 8);
}

static inline int
hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		return c - ('A' - 10);
	} else if (c >= 'a' && c <= 'f') {
		return c - ('a' - 10);
	} else {
		return -1;
	}
}

static int
hv_eq(const uint8_t *hv1, const uint8_t *hv2)
{
	int i, s;

	s = 0;
	for (i = 0; i < 8; i ++) {
		s |= hv1[i] ^ hv2[i];
	}
	return s == 0;
}

void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=0;i<size;i++)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
        printf(" ");
    }
    puts("");
}


void printTwoCompStr(size_t const size, unsigned char* buf)
{
    int i;
    for(i = 0; i < size; i++)
    {
        printf("\\x%02x", (unsigned char)-(unsigned char)buf[i]);
    }
    puts("");
}

void createWeakKeys(size_t nb_keys, unsigned char** buf)
{
    int u, v;
    unsigned char a;
    for (u = 0; u < nb_keys; u++) {
	    for (v = 0; v < 8; v++) {
            buf[u][v] = (unsigned char)((unsigned char)buf[u][v] - 2) >> 1;
	    }
    }
}

void printCharToKeyMapping() {
    int i;
	for (i = 1; i < 256; i++) {
		printf("'\\x%02x':'\\x%02x',\n", i, (((unsigned char)i << 1) + 2) & 0xff);
	}
}

void testSignificantBits() {
    unsigned char legal_chars[] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe};
	unsigned char key[8];
    unsigned char tmp_key[8];
    uint8_t hv1[8];
    uint8_t hv2[8];
    int i;
    
    

    //Print useless bits    
    memcpy(key, legal_chars, 8);
    testDES(hv1, (char *)key);

    for(i = 0; i < 64; i++)
    {
        int byte_i = i / 8;
        int bit_i = i % 8;
        memcpy(tmp_key, key, 8);

        tmp_key[byte_i] ^= (unsigned char) pow(2.0f,bit_i);
        testDES(hv2, tmp_key);
        if(hv_eq(hv1, hv2))
            printf("Byte : %d\tBit : %d\n", byte_i, bit_i);
    }

    // Useless bits are the LSB (No gain here because of the legal bytes ...)
}

unsigned long getIndexFromKey(const unsigned char * key) {
    unsigned char legal_chars[] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe};
	int i;
    unsigned char k_char;
    unsigned long index = 0;

    for (i = 0; i < 8; i++) {
        
    }
}

void bruteforce() {
    unsigned char legal_chars[] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe};
	unsigned char key[8];
    uint8_t hh[8];
    int a, b, c, d, e, f, g, h, i;
    struct nlist * entry;

    printf("Starting to try keys !!!\n------------------------------------------------------------------------------------------\n");

    unsigned long long count = 0;
    for (a = 0; a < 128; a++){
    for (b = 0; b < 128; b++){
    for (c = 0; c < 128; c++){
    for (d = 0; d < 128; d++){
    for (e = 0; e < 128; e++){
    for (f = 0; f < 128; f++){
    for (g = 0; g < 128; g++){
    for (h = 0; h < 128; h++){
        key[0] = legal_chars[a];
        key[1] = legal_chars[b];
        key[2] = legal_chars[c];
        key[3] = legal_chars[d];
        key[4] = legal_chars[e];
        key[5] = legal_chars[f];
        key[6] = legal_chars[g];
        key[7] = legal_chars[h];
        encryptDES(hh, key);

        entry = lookup(hh);
        if(entry != NULL) {
            printf("FOUND !!!!!!!!!!!\nTHE KEY IS : ");
            for(int i = 0; i < BLOCKSIZE; i++)
            {
                printf("\\x%02hhX, ", key[i]);
            }
            for(int i = 0; i < BLOCKSIZE; i++)
            {
                printf("\\x%02hhX, ", entry->defn[i]);
            }
            printf("\n");
            exit(0);
        }
        count++;
        if(count % 5000000 == 0) {
            printf("Count = %llu\n", count);
            printHex(key, 8);
        }
    }}}}}}}}
}

int main(int argc, char * argv[])
{
    hashtab = malloc(HASHSIZE * 8);
    printCharToKeyMapping();
    
    int start = 0, end = 128;
    if (argc > 3) {
        start = atoi(argv[1]);
        end = atoi(argv[2]);
    }    

    unsigned char legal_chars[] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe};
	unsigned char key[8];
    uint8_t primeh1[8], primeh2[8];
    int a, b, c, d, e, f, g, h, i;
    
    struct nlist * entry;

    printf("Starting to hoard keys !!!\n------------------------------------------------------------------------------------------\n");

    unsigned long long count = 0;
    for (a = start; a < end; a++){
    for (b = 0; b < 128; b++){
    for (c = 0; c < 128; c++){
    for (d = 0; d < 128; d++){
    for (e = 0; e < 128; e++){
    for (f = 0; f < 128; f++){
    for (g = 0; g < 128; g++){
    for (h = 0; h < 128; h++){
        key[0] = legal_chars[a];
        key[1] = legal_chars[b];
        key[2] = legal_chars[c];
        key[3] = legal_chars[d];
        key[4] = legal_chars[e];
        key[5] = legal_chars[f];
        key[6] = legal_chars[g];
        key[7] = legal_chars[h];
         
        decryptH1(primeh1, key);
        decryptH2(primeh2, key);
        
        
        install(primeh1, key);
        install(primeh2, key);
        
        count++;
        if(count % 5000000 == 0) {
            printf("Count = %llu\n", count);
            printHex(key, 8);
        }
        if(count >= HASHSIZE) {
            bruteforce();
            exit(0);
        }
    }}}}}}}}
	return 0;
}

