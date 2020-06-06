


#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "keymng_msg.h"
#include "itcast_asn1_der.h"
#include "itcastderlog.h"

//报文编码
int Teacher_Encode_(Teacher *pstruct, ITCAST_ANYBUF **tmpNode)
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

	/* 
	//分配内存 
	tmpOut = (unsigned char *)malloc(pOutData->dataLen);
	memcpy(tmpOut, pOutData->pData, pOutData->dataLen);

	//间接赋值 是指针存在最大意义
	*p = tmpOut;
	*len = pOutData->dataLen;
	*/
	*tmpNode = pOutData;
	//DER_ITCAST_FreeQueue(pOutData);  //释放链表 头节点

	return ret;
}


int Teacher_Decode_(unsigned char *p, int len, Teacher **pstruct)
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
void Teacher_Free_(Teacher *pStruct)
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
void Teacher_Free2_(Teacher **pStruct)
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


// itype tlv
// teacher tlv sequence
// all sequence tlv

int MsgEncode(
	void			*pStruct, /*in*/
	int				type,
	unsigned char	**outData, /*out*/
	int				*outLen)
{
	ITCAST_ANYBUF	*pHeadbuf = NULL, *pTemp = NULL;
	ITCAST_ANYBUF			*pOutData = NULL;
	int				ret = 0;
	unsigned char * tmpOut = NULL;
	int				tmpOutLen = 0;

	if (pStruct == NULL || outData == NULL || outLen == NULL)
	{
		ret = KeyMng_ParamErr;
		printf("func MsgEncode() err；%d check pStruct == NULL || outData == NULL || outLen == NULL\n", ret);
		return ret;
	}

	//编码type 标签
	ret = DER_ItAsn1_WriteInteger(type, &pHeadbuf);
	if (ret != 0)
	{
		printf("func DER_ItAsn1_WriteInteger() err；%d \n", ret);
		return ret;
	}

	//根据type编码各种类型的结构体

	switch (type)
	{
	case ID_MsgType_Teacher:
		ret = Teacher_Encode_(pStruct, &(pHeadbuf->next));
		if (ret != 0)
		{
			DER_ITCAST_FreeQueue(pHeadbuf);
			printf("func DER_ItAsn1_WriteInteger() err；%d \n", ret);
			return ret;
		}
		break;
	case ID_MsgKey_Req:
		//...
		break;
	case ID_MsgKey_Res:
		//...
		break;
	default:
		ret = -2;
		printf("输入的type不支持\n");
		break;
	}

	//all 
	ret = DER_ItAsn1_WriteSequence(pHeadbuf, &pOutData);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadbuf);
		printf("func DER_ItAsn1_WriteSequence() err:%d\n", ret);
		return ret;
	}

	//分配内存
	*outData = (unsigned char *)malloc(pOutData->dataLen);
	if (*outData == NULL)
	{
		DER_ITCAST_FreeQueue(pHeadbuf);
		ret = KeyMng_MallocErr;
		printf("func MsgEncode() func malloc err:%d\n", ret);
		return ret;
	}

	//间接赋值
	memcpy(*outData, pOutData->pData, pOutData->dataLen);
	*outLen = pOutData->dataLen;

	printf("ttttttt\n");
	DER_ITCAST_FreeQueue(pHeadbuf);
	DER_ITCAST_FreeQueue(pOutData);

	return 0;
}

int MsgDecode(
	unsigned char *inData,/*in*/
	int           inLen,
	void          **pStruct /*out*/,
	int           *type /*out*/)
{
	ITCAST_ANYBUF		*pHeadBuf = NULL, *pTmp = NULL;
	int					ret = 0;
	unsigned long		itype = 0;

	if (inData == NULL || pStruct == NULL || type == NULL)
	{
		ret = KeyMng_ParamErr;
		printf("func MsgDecode() err :%d\n", ret);
		return ret;
	}

	//把C 二进制数据  转换成 ITCAST_ANYBUF
	pTmp = (ITCAST_ANYBUF *)malloc(sizeof(ITCAST_ANYBUF));
	if (pTmp == NULL)
	{
		ret = KeyMng_MallocErr;
		printf("func MsgDecode() err :%d\n", ret);
		return ret;
	}
	//pTmp->next = NULL; 注意链表 要有结束标志
	//pTmp->prev = NULL;
	memset(pTmp, 0, sizeof(ITCAST_ANYBUF));
	pTmp->pData = (unsigned char *) malloc(inLen);
	if (pTmp->pData == NULL)
	{
		ret = KeyMng_MallocErr;
		printf("func MsgDecode() err :%d\n", ret);
		return ret;
	}

	memcpy(pTmp->pData, inData, inLen);
	pTmp->dataLen = inLen;

	//解析大结构体
	ret = DER_ItAsn1_ReadSequence(pTmp, &pHeadBuf);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pTmp);
		printf("func DER_ItAsn1_ReadSequence() err :%d\n", ret);
		return ret;
	}
	DER_ITCAST_FreeQueue(pTmp); //内存泄漏 modify by wbm

	//解析tag
	ret = DER_ItAsn1_ReadInteger(pHeadBuf, &itype);
	if (ret != 0)
	{
		DER_ITCAST_FreeQueue(pHeadBuf);
		printf("func DER_ItAsn1_ReadInteger() err :%d\n", ret);
		return ret;
	}

	//根据itype进行各种类型的解析
	switch (itype)
	{
	case ID_MsgType_Teacher:
		ret = Teacher_Decode_(pHeadBuf->next->pData, pHeadBuf->next->dataLen, (Teacher**)pStruct);
		if (ret != 0)
		{
			DER_ITCAST_FreeQueue(pHeadBuf);
			printf("func Teacher_Decode_() err :%d\n", ret);
			return ret;
		}
		break;

	case ID_MsgKey_Req:
		break;
	case ID_MsgKey_Res:
		break;
	default:
		ret = 3;
		printf("itype类型不支持：%d\n",ret);
		break;
	}
	//
	*type = itype;

	DER_ITCAST_FreeQueue(pHeadBuf);

	return 0;
}



int MsgMemFree(void **point, int type)
{
	if (point == NULL)
	{
		return 0;
	}
	if (type == 0)
	{
		if (*point != NULL)
		{
			free(*point);
		}
		*point = NULL;
	}
	else
	{
		switch (type)
		{
		case ID_MsgType_Teacher:
			Teacher_Free_(*point);
			*point = NULL;
			break;
		default:
			break;
		}
	}
	return 0;
}