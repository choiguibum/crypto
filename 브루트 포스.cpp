#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
//숫자, 소문자,대문자 배열
unsigned char array[63] = { '0','1','2', '3','4','5','6','7','8','9',
				   'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
				   'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };
void print(unsigned char * print) {
	for (int a = 0; a < SHA256_DIGEST_LENGTH; a++)
		printf("%x", print[a]);
	printf("\n");
}
void hashcheck(unsigned char * crackpass, char * sha256pass, unsigned char * cmppass) {
	SHA256_CTX ctx;//sha256구조체 변수 선언
	SHA256_Init(&ctx);//변수 초기화
	SHA256_Update(&ctx, cmppass,8 );//평문인 8자리의 비밀번호를 해시로 변환후 ctx에 저장
	SHA256_Final(crackpass, &ctx);//ctx에 저장된 해시값을 crackpass에 저장
	char tmp[10] = {0};//무작위 대입한 패스워드의 값이 저장될 배열
	char crack[100] = { 0, };//무작위 대입한 패스워드의 해시값의 스트링형이 저장될 배열
	printf("비밀번호 찾는중  : ");
	for (int i = 0; i < 8; i++)
		printf("%c",cmppass[i]);
	printf("\n");
	print(crackpass);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {//무작위 대입한 패스워드의 해시값을 스트링형으로 변환
		sprintf(tmp, "%x",crackpass[i]);//crackpass에 저장된 해시값 배열을 16진수로 tmp에 저장
		strcat(crack, tmp);//tmp에 저장된 값을 crack에 이어붙임
	}
	if (strcmp(sha256pass,crack) == 0) {//입력된 비밀번호의 해시값과 무작위 대입한 패스워드의 해시값을 비교
		printf("\n패스워드 찾음!!! : ");
		for (int i = 0; i < 8; i++)
			printf("%c", cmppass[i]);
		printf("\n");
		exit(0);//비밀번호를 찾았으므로 더이상 실행이 없으므로 exit
	}
}
void bruteforce(char* sha256pass) {
	unsigned char crackpass[SHA256_DIGEST_LENGTH] = { 0 };//크래킹된 비밀번호의 해시값이 저장될 배열
	unsigned char cmppass[8] = { 0 };//대입된 비밀번호
	//마지막자리부터 시작해서 첫번째 자리까지 대입
	for (int a = 0; a < 62; a++) { //첫번째 자리
		cmppass[0] = array[a];
		for (int b = 0; b < 62; b++) {//두번째 자리
			cmppass[1] = array[b];
			for (int c = 0; c < 62; c++) {//세번째 자리
				cmppass[2] = array[c];
				for (int d = 0; d < 62; d++) {//네번째 자리
					cmppass[3] = array[d];
					for (int e = 0; e < 62; e++) {//다섯번째 자리
						cmppass[4] = array[e];
						for (int f = 0; f < 62; f++) {// 여섯번째 자리
							cmppass[5] = array[f];
							for (int g = 0; g < 62; g++) {//일곱번째 자리
								cmppass[6] = array[g];
								for (int h = 0; h < 62; h++) {//여덟번째 자리
									cmppass[7] = array[h];
									hashcheck(crackpass, sha256pass, cmppass);//해쉬가 같은지 비교
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
	char sha256[100] = {0};//스트링형이 저장될 배열
	
	SHA256_CTX ctx;
	printf("패스워드 8자리를 입력하세요. \n");
	scanf("%s", password);
	SHA256_Init(&ctx);//변수 초기화
	SHA256_Update(&ctx, password, 8);//입력된 8자리의 패스워드를 해시변환 하여 ctx에 저장
	SHA256_Final(sha256pass, &ctx);//ctx에 저장된 배열을 
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {//패스워드 해시값을 md5에 붙여서 스트링형으로 변환
		sprintf(tmp, "%x", sha256pass[i]);
		strcat(sha256, tmp);
	}
	printf("입력된 비밀번호 : %s\n", password);
	printf("입력된 비밀번호의 해시값 : ");
	print(sha256pass);
	bruteforce(sha256);

	return 0;
}


