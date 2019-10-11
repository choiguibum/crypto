#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
//����, �ҹ���,�빮�� �迭
unsigned char array[63] = { '0','1','2', '3','4','5','6','7','8','9',
				   'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
				   'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };
void print(unsigned char * print) {
	for (int a = 0; a < SHA256_DIGEST_LENGTH; a++)
		printf("%x", print[a]);
	printf("\n");
}
void hashcheck(unsigned char * crackpass, char * sha256pass, unsigned char * cmppass) {
	SHA256_CTX ctx;//sha256����ü ���� ����
	SHA256_Init(&ctx);//���� �ʱ�ȭ
	SHA256_Update(&ctx, cmppass,8 );//���� 8�ڸ��� ��й�ȣ�� �ؽ÷� ��ȯ�� ctx�� ����
	SHA256_Final(crackpass, &ctx);//ctx�� ����� �ؽð��� crackpass�� ����
	char tmp[10] = {0};//������ ������ �н������� ���� ����� �迭
	char crack[100] = { 0, };//������ ������ �н������� �ؽð��� ��Ʈ������ ����� �迭
	printf("��й�ȣ ã����  : ");
	for (int i = 0; i < 8; i++)
		printf("%c",cmppass[i]);
	printf("\n");
	print(crackpass);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {//������ ������ �н������� �ؽð��� ��Ʈ�������� ��ȯ
		sprintf(tmp, "%x",crackpass[i]);//crackpass�� ����� �ؽð� �迭�� 16������ tmp�� ����
		strcat(crack, tmp);//tmp�� ����� ���� crack�� �̾����
	}
	if (strcmp(sha256pass,crack) == 0) {//�Էµ� ��й�ȣ�� �ؽð��� ������ ������ �н������� �ؽð��� ��
		printf("\n�н����� ã��!!! : ");
		for (int i = 0; i < 8; i++)
			printf("%c", cmppass[i]);
		printf("\n");
		exit(0);//��й�ȣ�� ã�����Ƿ� ���̻� ������ �����Ƿ� exit
	}
}
void bruteforce(char* sha256pass) {
	unsigned char crackpass[SHA256_DIGEST_LENGTH] = { 0 };//ũ��ŷ�� ��й�ȣ�� �ؽð��� ����� �迭
	unsigned char cmppass[8] = { 0 };//���Ե� ��й�ȣ
	//�������ڸ����� �����ؼ� ù��° �ڸ����� ����
	for (int a = 0; a < 62; a++) { //ù��° �ڸ�
		cmppass[0] = array[a];
		for (int b = 0; b < 62; b++) {//�ι�° �ڸ�
			cmppass[1] = array[b];
			for (int c = 0; c < 62; c++) {//����° �ڸ�
				cmppass[2] = array[c];
				for (int d = 0; d < 62; d++) {//�׹�° �ڸ�
					cmppass[3] = array[d];
					for (int e = 0; e < 62; e++) {//�ټ���° �ڸ�
						cmppass[4] = array[e];
						for (int f = 0; f < 62; f++) {// ������° �ڸ�
							cmppass[5] = array[f];
							for (int g = 0; g < 62; g++) {//�ϰ���° �ڸ�
								cmppass[6] = array[g];
								for (int h = 0; h < 62; h++) {//������° �ڸ�
									cmppass[7] = array[h];
									hashcheck(crackpass, sha256pass, cmppass);//�ؽ��� ������ ��
								}
							}
						}
					}

				}
			}
		}
	}
}
int main() {
	char password[8] = {0};
	unsigned char sha256pass[SHA256_DIGEST_LENGTH] = {0};
	char tmp[10] = {0};
	char sha256[100] = {0};//��Ʈ������ ����� �迭
	
	SHA256_CTX ctx;
	printf("�н����� 8�ڸ��� �Է��ϼ���. \n");
	scanf("%s", password);
	SHA256_Init(&ctx);//���� �ʱ�ȭ
	SHA256_Update(&ctx, password, 8);//�Էµ� 8�ڸ��� �н����带 �ؽú�ȯ �Ͽ� ctx�� ����
	SHA256_Final(sha256pass, &ctx);//ctx�� ����� �迭�� 
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {//�н����� �ؽð��� md5�� �ٿ��� ��Ʈ�������� ��ȯ
		sprintf(tmp, "%x", sha256pass[i]);
		strcat(sha256, tmp);
	}
	printf("�Էµ� ��й�ȣ : %s\n", password);
	printf("�Էµ� ��й�ȣ�� �ؽð� : ");
	print(sha256pass);
	bruteforce(sha256);

	return 0;
}


