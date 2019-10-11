#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define READ_BYTE 32
int do_crypt(unsigned char*key, unsigned char * iv, FILE *ifp, FILE *ofp,int Option) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//Cipher ����ü ���� ȣ�� �� �޸� �Ҵ�
	if (ctx == NULL) {
		printf("CTX : �Ҵ� ����\n");
		return -1;
	}
	int result = EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, Option);//�ʱ�ȭ
	if (result != 1) {
		printf("CTX : �ʱ�ȭ ����\n");
		return -1;
	}
	unsigned char* itxtbuf = (unsigned char*)malloc(READ_BYTE);//���� �������� ���� �Ҵ�
	unsigned char* otxtbuf = (unsigned char*)malloc(READ_BYTE);//����� �������� ���� �Ҵ�
	if (itxtbuf == NULL || otxtbuf == NULL) {
		printf("���� �Ҵ� ����\n");
		return -1;
	}
	int itxtlen = 0, otxtlen = 0;
	while (1) {
		int itxtlen = fread(itxtbuf, 1, READ_BYTE, ifp);//�򹮵����͸� 32����Ʈ�� ����
		if (itxtlen <= 0)
			break;
		result = EVP_CipherUpdate(ctx, otxtbuf, &otxtlen, itxtbuf, itxtlen);//32����Ʈ�� ��ȣȭ
		if (result != 1) {
			printf("��/��ȣȭ ����\n");
			return -1;
		}
		fwrite(otxtbuf, 1, otxtlen, ofp);//32����Ʈ�� ��ȣȭ�� ���� ���
	}
	EVP_CipherFinal_ex(ctx, otxtbuf, &otxtlen);//�޺κ� ��/��ȣȭ(32����Ʈ�� �����Ƿ� ������ �κ��� ����)
	fwrite(otxtbuf, 1, otxtlen, ofp);
	EVP_CIPHER_CTX_free(ctx);//�޸� �ݳ�
	free(itxtbuf);//�޸� �ݳ�
	free(otxtbuf);//�޸� �ݳ�
	return 0;
}
int main() {
	FILE* ifp = fopen("plaintext.txt","r");
	FILE* ofp = fopen("ciphertext.bin", "w");
	if (ifp == NULL || ofp == NULL) {
		printf("Encrypt : ��ȣȭ ���� ���� ����\n");
		return -1;
	}
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//Cipher ����ü ���� ȣ�� �� �޸� �Ҵ�
	if (ctx == NULL) {
		printf("Encrypt : �Ҵ� ���� \n");
		return -1;
	}
	unsigned char* key = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx));//�Ϻ�ȣȭ�� �ʿ��� Ű����
	RAND_bytes(key, EVP_CIPHER_CTX_key_length(ctx));
	if (key == NULL) {
		printf("Ű���� ����\n");
		return -1;
	}
	unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx));//�Ϻ�ȣȭ�� �ʿ��� IV����
	RAND_bytes(iv, EVP_CIPHER_CTX_key_length(ctx));
	if (iv == NULL) {
		printf("IV���� ����\n");
		return -1;
	}
	//��ȣȭ
	do_crypt(key,iv,ifp,ofp,1);// Ű�� iv, �������ϰ� ����������� �Ѱ��ְ� 1�� ��� ��ȣȭ 0�� ��� ��ȣȭ
	fclose(ifp);//���� �ݱ�
	fclose(ofp);//���� �ݱ�

	//��ȣȭ
	ifp = fopen("ciphertext.bin", "r");//��ȣȭ�� ���̳ʸ� ���� �б�
	ofp = fopen("decrypttext.txt", "w");//��ȣȭ�� ���� ���
	if (ifp == NULL || ofp == NULL) {
		printf("Decrypt : ��ȣȭ ���� ���� ����\n");
		return -1;
	}
	do_crypt(key, iv, ifp, ofp, 0);// Ű�� iv, �������ϰ� ����������� �Ѱ��ְ� 1�� ��� ��ȣȭ 0�� ��� ��ȣȭ
	fclose(ifp);//���ϴݱ�
	fclose(ofp);//���ϴݱ�
	EVP_CIPHER_CTX_free(ctx);//Cipher ����ü �޸� �ݳ�
	return 0;
}