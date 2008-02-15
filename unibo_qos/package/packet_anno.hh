#ifndef CLICKMODULE_UNIBO_QOS_PACKET_ANNO_HH
#define CLICKMODULE_UNIBO_QOS_PACKET_ANNO_HH

// bytes 8-11
#define SSRC_ANNO(p)			((p)->user_anno_u8(2))
#define SET_SSRC_ANNO(p, v)		((p)->set_user_anno_u8(2, (v)))

#endif /* CLICKMODULE_UNIBO_QOS_PACKET_ANNO_HH */
