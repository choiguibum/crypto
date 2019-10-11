#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define READ_BYTE 32
int do_crypt(unsigned char*key, unsigned char * iv, FILE *ifp, FILE *ofp,int Option) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//Cipher 구조체 변수 호출 및 메모리 할당
	if (ctx == NULL) {
		printf("CTX : 할당 에러\n");
		return -1;
	}
	int result = EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, Option);//초기화
	if (result != 1) {
		printf("CTX : 초기화 에러\n");
		return -1;
	}
	unsigned char* itxtbuf = (unsigned char*)malloc(READ_BYTE);//읽을 데이터의 버퍼 할당
	unsigned char* otxtbuf = (unsigned char*)malloc(READ_BYTE);//기록할 데이터의 버퍼 할당
	if (itxtbuf == NULL || otxtbuf == NULL) {
		printf("버퍼 할당 에러\n");
		return -1;
	}
	int itxtlen = 0, otxtlen = 0;
	while (1) {
		int itxtlen = fread(itxtbuf, 1, READ_BYTE, ifp);//평문데이터를 32바이트씩 읽음
		if (itxtlen <= 0)
			break;
		result = EVP_CipherUpdate(ctx, otxtbuf, &otxtlen, itxtbuf, itxtlen);//32바이트씩 암호화
		if (result != 1) {
			printf("암/복호화 에러\n");
			return -1;
		}
		fwrite(otxtbuf, 1, otxtlen, ofp);//32바이트씩 암호화된 값을 기록
	}
	EVP_CipherFinal_ex(ctx, otxtbuf, &otxtlen);//뒷부분 암/복호화(32바이트씩 읽으므로 나머지 부분이 존재)
	fwrite(otxtbuf, 1, otxtlen, ofp);
	EVP_CIPHER_CTX_free(ctx);//메모리 반납
	free(itxtbuf);//메모리 반납
	free(otxtbuf);//메모리 반납
	return 0;
}
int main() {
	FILE* ifp = fopen("plaintext.txt","r");
	FILE* ofp = fopen("ciphertext.bin", "w");
	if (ifp == NULL || ofp == NULL) {
		printf("Encrypt : 암호화 파일 열기 실패\n");
		return -1;
	}
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//Cipher 구조체 변수 호출 및 메모리 할당
	if (ctx == NULL) {
		printf("Encrypt : 할당 에러 \n");
		return -1;
	}
	unsigned char* key = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx));//암복호화에 필요한 키생성
	RAND_bytes(key, EVP_CIPHER_CTX_key_length(ctx));
	if (key == NULL) {
		printf("키생성 실패\n");
		return -1;
	}
	unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx));//암복호화에 필요한 IV생성
	RAND_bytes(iv, EVP_CIPHER_CTX_key_length(ctx));
	if (iv == NULL) {
		printf("IV생성 실패\n");
		return -1;
	}
	//암호화
	do_crypt(key,iv,ifp,ofp,1);// 키와 iv, 읽을파일과 기록할파일을 넘겨주고 1일 경우 암호화 0일 경우 복호화
	fclose(ifp);//파일 닫기
	fclose(ofp);//파일 닫기

	//복호화
	ifp = fopen("ciphertext.bin", "r");//암호화된 바이너리 파일 읽기
	ofp = fopen("decrypttext.txt", "w");//복호화된 값을 기록
	if (ifp == NULL || ofp == NULL) {
		printf("Decrypt : 복호화 파일 열기 실패\n");
		return -1;
	}
	do_crypt(key, iv, ifp, ofp, 0);// 키와 iv, 읽을파일과 기록할파일을 넘겨주고 1일 경우 암호화 0일 경우 복호화
	fclose(ifp);//파일닫기
	fclose(ofp);//파일닫기
	EVP_CIPHER_CTX_free(ctx);//Cipher 구조체 메모리 반납
	return 0;
}