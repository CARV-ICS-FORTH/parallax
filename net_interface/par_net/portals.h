#ifdef PARALLAX_PORTALS
#ifndef PORTALS_H
#define PORTALS_H
#define PORTALS

#define SRV_ME_OPTS                                                                                                 \
	PTL_ME_OP_PUT | PTL_ME_EVENT_LINK_DISABLE | PTL_ME_MAY_ALIGN | PTL_ME_IS_ACCESSIBLE | PTL_ME_MANAGE_LOCAL | \
		PTL_ME_NO_TRUNCATE
#define PRSV_COM_BUF_SIZE (10U * KV_MAX_SIZE)
#define PRSV_COM_BUF_MIN_FREE (8 + KV_MAX_SIZE)
#define MATCH 1
#define IGNORE 0xffffffff
#define METADATA_SIZE 4096
#define MATCH_ENTRY_NUM 5
#define SERVER_PID 2060
#define CLIENT_PID 2080

#endif //PORTALS_H
#endif //PARALLAX_PORTALS
