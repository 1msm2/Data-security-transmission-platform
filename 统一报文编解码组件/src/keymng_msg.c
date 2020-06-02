

#include "keymng_msg.h"


int MsgEncode(
	void			*pStruct, /*in*/
	int				type,
	unsigned char	**outData, /*out*/
	int				*outLen)
{
	return 0;
}



int MsgDecode(
	unsigned char *inData,/*in*/
	int           inLen,
	void          **pStruct /*out*/,
	int           *type /*out*/)
{
	return 0;
}



int MsgMemFree(void **point, int type)
{
	return 0;
}