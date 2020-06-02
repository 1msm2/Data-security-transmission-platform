
#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "itcast_asn1_der.h"
#include "itcastderlog.h"


typedef struct _Teacher
{
	char	name[64];
	int		age;
	char	*p;
	int		plen;
}Teacher;
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
typedef struct ITCAST_ANYBUF_{
	unsigned char *pData;
	ITCAST_UINT32     dataLen;
	ITCAST_UINT32     unusedBits;  // for bit string
	ITCAST_UINT32     memoryType;
	ITCAST_UINT32     dataType;
	struct ITCAST_ANYBUF_ *next;    //for sequence and set 
	struct ITCAST_ANYBUF_ *prev;
}ITCAST_ANYBUF;

ITCAST_INT
DER_ItAsn1_WritePrintableString(ITASN1_PRINTABLESTRING *pPrintString, ITASN1_PRINTABLESTRING **ppDerPrintString);
*/
//报文编码
int Teacher_Encode(Teacher *pstruct, unsigned char **p, int *len)
{
	int					ret = 0;
	ITCAST_ANYBUF		*pTmp = NULL, *pHeadBuf = NULL;
	ITCAST_ANYBUF		*pTmpBuf = NULL;
	ITCAST_ANYBUF		*pOutData = NULL;

	unsigned char		*tmpOut = NULL;
	int					tmpOutLen = 0;

	// 编码name
	//C语言的char buf类型 转化 ITASN1_PRINTABLESTRING
	ret = DER_ITCAST_String_To_AnyBuf(&pTmp, pstruct->name, strlen(pstruct->name));
	if (ret != 0)
	{
		printf("func DER_ITCAST_String_To_AnyBuf() err:%d \n", ret);
		return ret;
	}

	//对name进行TLV操作
	ret = DER_ItAsn1_WritePrintableString(pTmp, &pHeadBuf);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pTmp);
		printf("func DER_ItAsn1_WritePrintableString() err:%d \n", ret);
		return ret;
	}
	DER_ITCAST_FreeQueue(pTmp);
	pTmpBuf = pHeadBuf;

	//编码age
	ret = DER_ItAsn1_WriteInteger(pstruct->age, &(pTmpBuf->next));
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);  //释放链表 头节点
		printf("func DER_ItAsn1_WriteInteger() err:%d \n", ret);
		return ret;
	}
	pTmpBuf = pTmpBuf->next; //辅助指针变量 下移

	//编码p
	ret = EncodeChar(pstruct->p, pstruct->plen, &pTmpBuf->next);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);  //释放链表 头节点
		printf("func EncodeChar() err:%d \n", ret);
		return ret;
	}
	pTmpBuf = pTmpBuf->next; //辅助指针变量 下移

	//编码plen
	ret = DER_ItAsn1_WriteInteger(pstruct->plen, &(pTmpBuf->next));
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);  //释放链表 头节点
		printf("func DER_ItAsn1_WriteInteger() err:%d \n", ret);
		return ret;
	}

	//TLV结构体
	ret = DER_ItAsn1_WriteSequence(pHeadBuf, &pOutData);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);  //释放链表 头节点
		printf("func DER_ItAsn1_WriteSequence() err:%d \n", ret);
		return ret;
	}

	DER_ITCAST_FreeQueue(pHeadBuf);  //释放链表 头节点
	//分配内存 
	tmpOut = (unsigned char *)malloc(pOutData->dataLen);
	memcpy(tmpOut, pOutData->pData, pOutData->dataLen);

	//间接赋值 是指针存在最大意义
	*p = tmpOut;
	*len = pOutData->dataLen;

	DER_ITCAST_FreeQueue(pOutData);  //释放链表 头节点
	
	return ret;
}


int Teacher_Decode(unsigned char *p, int len, Teacher **pstruct)
{
	int					ret = 0;
	ITCAST_ANYBUF		*pTmp = NULL, *pHead = NULL;
	ITCAST_ANYBUF		*pTmpDABuf = NULL;
	ITCAST_ANYBUF		*pOutData = NULL;
	ITCAST_ANYBUF		*inAnyBuf = NULL;
	int					tmpNum = 0;
	Teacher				*pTmpStru = NULL;

	inAnyBuf = (ITCAST_ANYBUF *)malloc(sizeof(ITCAST_ANYBUF));
	if (inAnyBuf == NULL)
	{
		ret = 1;
		printf("func Teacher_Decode() err: %d. malloc err \n", ret);
		return ret;
	}
	memset(inAnyBuf, 0, sizeof(ITCAST_ANYBUF)); //赋值很重要
	inAnyBuf->pData = (unsigned char *)malloc(len);
	if (inAnyBuf->pData == NULL)
	{
		ret = 2;
		DER_ITCAST_FreeQueue(inAnyBuf);
		printf("func Teacher_Decode() err: %d. malloc err \n", ret);
		return ret;
	}
	inAnyBuf->dataLen = len;
	memcpy(inAnyBuf->pData, p, len);

	ret = DER_ItAsn1_ReadSequence(inAnyBuf, &pHead);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(inAnyBuf);
		printf("func DER_ItAsn1_ReadSequence() err:%d \n", ret);
		return ret;
	}
	DER_ITCAST_FreeQueue(inAnyBuf);
	pTmp = pHead;

	//分配老师结构体
	pTmpStru = (Teacher *)malloc(sizeof(Teacher));
	if (pTmpStru == NULL)
	{
		DER_ITCAST_FreeQueue(pHead);
		ret = 3;
		printf("func Teacher_Decode() err: %d. malloc err \n", ret);
		return ret;
	}
	memset(pTmpStru, 0, sizeof(Teacher));

	//解码name
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		printf("func DER_ItAsn1_ReadPrintableString() err:%d \n", ret);
		return ret;
	}
	strncpy(pTmpStru->name, pTmpDABuf->pData, pTmpDABuf->dataLen);
	pTmp = pTmp->next;
	DER_ITCAST_FreeQueue(pTmpDABuf);

	//解码age
	ret = DER_ItAsn1_ReadInteger(pTmp, &pTmpStru->age);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		printf("func DER_ItAsn1_ReadInteger() err:%d \n", ret);
		return ret;
	}
	pTmp = pTmp->next;

	//解码p
	ret = DER_ItAsn1_ReadPrintableString(pTmp, &pTmpDABuf);
	if (ret != 0)
	{
		printf("func DER_ItAsn1_ReadPrintableString() err:%d \n", ret);
		return ret;
	}
	pTmpStru->p = (unsigned char *)malloc(pTmpDABuf->dataLen + 1);
	if (pTmpStru->p == NULL)
	{
		DER_ITCAST_FreeQueue(pTmpDABuf);
		DER_ITCAST_FreeQueue(pHead); 
		ret = 4;
		printf("func Teacher_Decode() err: %d. malloc err \n", ret);
		return ret;
	}
	memcpy(pTmpStru->p, pTmpDABuf->pData, pTmpDABuf->dataLen);
	pTmpStru->p[pTmpDABuf->dataLen] = '\0';
	pTmp = pTmp->next;
	DER_ITCAST_FreeQueue(pTmpDABuf);

	//解码plen
	ret = DER_ItAsn1_ReadInteger(pTmp, &pTmpStru->plen);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHead);
		printf("func DER_ItAsn1_ReadInteger() err:%d \n", ret);
		return ret;
	}

	*pstruct = pTmpStru;
	DER_ITCAST_FreeQueue(pHead);

	return ret;
}

//一级指针
void Teacher_Free(Teacher *pStruct)
{
	if (pStruct == NULL)
	{
		return;
	}
	if (pStruct->p)
	{
		free(pStruct->p);
	}
			
	free(pStruct);
}

//不但把指针所指向的内存空间释放,同时把实参修改成NULL 避免野指针
void Teacher_Free2(Teacher **pStruct)
{
	Teacher *tmp = NULL;

	if (pStruct == NULL)
	{
		return;
	}
	tmp = *pStruct;

	if (tmp == NULL)
	{
		return;
	}


	if (tmp->p)
	{
		free(tmp->p);
	}

	free(tmp);
	*pStruct = NULL;

}


int mainxxxx()
{
	int				ret = 0;
	Teacher			t1;

	unsigned char	*out = NULL;
	int				outlen = 0;

	Teacher			*outPstruct = NULL;

	memset(&t1, 0, sizeof(Teacher));
	strcpy(t1.name, "myname");
	t1.age = 32;
	t1.p = (char *)malloc(100);
	strcpy(t1.p, "aaaaaa");
	t1.plen = 6;

	ret = Teacher_Encode(&t1, &out, &outlen);
	if (ret != 0)
	{
		printf("func Teacher_Encode() err:%d \n", ret);
		return ret;
	}

	mywritefile(out, outlen);
	//return 0;

	ret = Teacher_Decode(out, outlen, &outPstruct);
	if (ret != 0)
	{
		printf("func Teacher_Decode() err:%d \n", ret);
		return ret;
	}

	if (t1.age != outPstruct->age ||
		(memcmp(t1.p, outPstruct->p, t1.plen) != 0))
	{

		printf("编码和解码的结果不一致\n");
		return -2;
	}
	printf("编码和解码的结果一致 ok\n");

	Teacher_Free2(&outPstruct);
	Teacher_Free2(&outPstruct);
	Teacher_Free2(&outPstruct);
	printf("hello...\n");
	system("pause");
	return 0;
}
