
#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "keymng_msg.h"

int mywritefile(unsigned char *buf, int len)
{
	FILE *fp = NULL;
	fp = fopen("c:/teacher.ber", "wb+");
	if (fp == NULL)
	{
		printf("fopen file error \n");
		return -1;
	}
	fwrite(buf, 1, len, fp);
	fclose(fp);
	return 0;
}

/* 
int MsgEncode(
	void			*pStruct,
	int				type,
	unsigned char	**outData, 
	int				*outLen)
int MsgMemFree(void **point, int type)
*/
int main()
{
	int				ret = 0;
	Teacher			t1;

	unsigned char	*out = NULL;
	int				outlen = 0;

	Teacher			*outPstruct = NULL;
	int				iType = 0;
	
	printf("main enter....\n");
	printf("main 进入....\n");

	memset(&t1, 0, sizeof(Teacher));
	strcpy(t1.name, "myname");
	t1.age = 32;
	t1.p = (char *)malloc(100);
	strcpy(t1.p, "aaaaaa");
	t1.plen = 6;

	ret = MsgEncode((void *)&t1, ID_MsgType_Teacher, &out, &outlen);
	if (ret != 0)
	{
		printf("func MsgEncode() err:%d \n", ret);
		return ret;
	}

	/* 
	if (out != NULL)
	{
		free(out);
	} */

	//mywritefile(out, outlen);


	ret = MsgDecode(out, outlen, (void **)&outPstruct, &iType);
	if (ret != 0)
	{
		printf("func MsgDecode() err:%d \n", ret);
		return ret;
	}
	
	printf("编码和解码运行ok....\n");

	MsgMemFree((void **)&out, 0);
	MsgMemFree((void **)&outPstruct, iType);
		
	printf("hello...\n");
	system("pause");
	return 0;
}