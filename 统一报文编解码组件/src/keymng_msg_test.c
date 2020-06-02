


#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "keymng_msg.h"


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


	ret = MsgDecode(out, outlen, &outPstruct, &iType);
	if (ret != 0)
	{
		printf("func MsgDecode() err:%d \n", ret);
		return ret;
	}

	MsgMemFree((void **)&out, 0);
	MsgMemFree((void **)&outPstruct, iType);
		


	printf("hello...\n");
	system("pause");
	return 0;
}