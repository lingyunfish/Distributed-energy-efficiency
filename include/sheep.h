/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SHEEP_H__
#define __SHEEP_H__

#include <stdint.h>
#include "util.h"
#include "list.h"
#include "net.h"
#include "logger.h"

#define SD_SHEEP_PROTO_VER 0x03

#define SD_DEFAULT_REDUNDANCY 3
#define SD_MAX_REDUNDANCY 8

#define SD_MAX_NODES 1024
#define SD_DEFAULT_VNODES 64
#define SD_MAX_VNODES 65536
#define SD_MAX_VMS   4096 /* FIXME: should be removed */

#define SD_OP_SHEEP         0x80
#define SD_OP_DEL_VDI        0x81
#define SD_OP_GET_NODE_LIST  0x82
#define SD_OP_GET_VM_LIST    0x83
#define SD_OP_MAKE_FS        0x84
#define SD_OP_SHUTDOWN       0x85
#define SD_OP_STAT_SHEEP     0x86
#define SD_OP_STAT_CLUSTER   0x87
#define SD_OP_KILL_NODE      0x88
#define SD_OP_GET_VDI_ATTR   0x89
#define SD_OP_RECOVER	     0x8A

/*+++++++++++++++lingyun++++++++++++*/
#define SD_OP_CLOSE 		 0X8B
#define SD_OP_WAKEUP		 0X8C
/*+++++++++++++++end++++++++++++++*/

#define SD_FLAG_CMD_IO_LOCAL   0x0010
#define SD_FLAG_CMD_RECOVERY 0x0020
/*+++++++++++lingyun++++++++++++*/
#define SD_FLAG_CMD_LOG 0X0040

#define SD_NODE_CLOSE 				0X01
#define SD_NODE_LIVE				0X00

/*+++++++++++end++++++++++++++*/


/* set this flag when you want to read a VDI which is opened by
   another client.  Note that the obtained data may not be the latest
   one because Sheepdog cannot ensure strong consistency against
   concurrent accesses to non-snapshot VDIs. */
#define SD_FLAG_CMD_WEAK_CONSISTENCY 0x0040

/* flags for VDI attribute operations */
#define SD_FLAG_CMD_CREAT    0x0100
#define SD_FLAG_CMD_EXCL     0x0200
#define SD_FLAG_CMD_DEL      0x0400

#define SD_RES_OLD_NODE_VER  0x41 /* Remote node has an old epoch */
#define SD_RES_NEW_NODE_VER  0x42 /* Remote node has a new epoch */
#define SD_RES_NOT_FORMATTED 0x43 /* Sheepdog is not formatted yet */
#define SD_RES_INVALID_CTIME 0x44 /* Creation time of sheepdog is different */
#define SD_RES_INVALID_EPOCH 0x45 /* Invalid epoch */

#define SD_FLAG_NOHALT       0x0001 /* Server the IO rquest even lack of nodes */

struct sd_so_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint64_t	oid;
	uint64_t	ctime;
	uint32_t	copies;
	uint32_t	tag;
	uint32_t	opcode_specific[2];
};

struct sd_so_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t	copies;
	uint64_t	ctime;
	uint64_t	oid;
	uint32_t	opcode_specific[2];
};

struct sd_list_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        tgt_epoch;
	uint32_t        pad[7];
};

struct sd_list_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t        pad[7];
};

/*++++++++++++lingyun++++++++++++++*/
struct sd_log_list_req{
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        closed_zone;
	uint32_t        pad[7];
};
struct sd_log_list_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t        pad[7];
};


/*+++++++++++++end+++++++++++++++*/
struct sd_node_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t	request_ver;
	uint32_t	pad[7];
};

struct sd_node_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t	nr_nodes;
	uint32_t	local_idx;
	uint32_t	master_idx;
	uint64_t	store_size;
	uint64_t	store_free;
};

struct sheepdog_node_list_entry {
	uint8_t         addr[16];
	uint16_t        port;
	uint16_t	nr_vnodes;
	uint32_t	zone;
	/*+++++lingyun++++++*/
	uint8_t state;
	/*+++++end++++++++*/
};

struct sheepdog_vnode_list_entry {
	uint64_t        id;
	uint8_t         addr[16];
	uint16_t        port;
	uint16_t	node_idx;
	uint32_t	zone;
	/*+++++lingyun++++++*/
	uint8_t state;
	/*++++++end+++++++*/
};

struct epoch_log {
	uint64_t ctime;
	uint64_t time;
	uint32_t epoch;
	uint32_t nr_nodes;
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
};

static inline int same_node(struct sheepdog_vnode_list_entry *e, int n1, int n2)
{
	if (memcmp(e[n1].addr, e[n2].addr, sizeof(e->addr)) == 0 &&
	    e[n1].port == e[n2].port)
		return 1;

	return 0;
}

static inline int same_zone(struct sheepdog_vnode_list_entry *e, int n1, int n2)
{
	return e[n1].zone != 0 && e[n1].zone == e[n2].zone;
}

/*+++++++++++lingyun++++++++++++++++*/
static inline int is_closed_node(struct sheepdog_vnode_list_entry *e,int n1)
{
	return e[n1].state == SD_NODE_CLOSE;
}

//int nodes_lp[SD_MAX_REDUNDANCY];
//int nr_lp;

static inline int get_nth_node_lp_debug(struct sheepdog_vnode_list_entry *entries,
					int nr_entries, int nr_obj,int base, int n)
{
	int nr = 0;
	int nodes[SD_MAX_REDUNDANCY];
	int idx = base, i, j = n, flag = 0;
	int new_base;
	if(j > nr_obj - 1){
		flag = 1;
		j = nr_obj - 1;
	}

	while(is_closed_node(entries, idx)){
		/*if node is closed then the next living node should not the same zone /node with this node*/
		nodes[nr++] = idx;
next:
		idx = (idx + 1) % nr_entries;
		if (idx == base) {
			panic("bug");
		}
		for (i = 0; i < nr; i++) {
			if (same_node(entries, idx, nodes[i]))
				
				goto next;
			if (same_zone(entries, idx, nodes[i]))
				
				goto next;
		}
	}
	
	new_base = idx;
	
	while (j--) {
		nodes[nr++] = idx;
next1:
		idx = (idx + 1) % nr_entries;
		if (idx == new_base) {
			panic("bug"); /* not found */
		}
		if(is_closed_node(entries,idx))
			goto next1;
		for (i = 0; i < nr; i++) {
			if (same_node(entries, idx, nodes[i]))
				/* this node is already selected, so skip here */
				goto next1;
			if (same_zone(entries, idx, nodes[i]))
				/* this node is in the same zone, so skip here */
				goto next1;
		}
	}
	nodes[nr++] = idx;
	/*log begin with new_base
	* for example , if n = nr_obj ,then the  idex is the first  vnode from new_base
	*/
	if(flag){
		n = n - nr_obj + 1;
		idx = new_base;
		while (n--) {
			nodes[nr++] = idx;
next2:
			idx = (idx + 1) % nr_entries;
			if (idx == new_base) {
				panic("bug"); /* not found */
			}
			if(is_closed_node(entries,idx))
				goto next2;
			for (i = 0; i < nr; i++) {
				if (same_node(entries, idx, nodes[i]))
					
					goto next2;
			}
		}
	}

	return idx;

}


static inline int get_nth_node_lp(struct sheepdog_vnode_list_entry *entries,
					int nr_entries, int base, int n, int flag)
{
	
	int nr = 0;
	int nodes[SD_MAX_REDUNDANCY];
	int idx = base, i;

	while(is_closed_node(entries, idx)){
		/*if node is closed then the next living node should not the same zone /node with this node*/
		nodes[nr++] = idx;
next1:
		idx = (idx + 1) % nr_entries;
		if (idx == base) {
			panic("bug");
		}
		for (i = 0; i < nr; i++) {
			if (same_node(entries, idx, nodes[i]))
				
				goto next1;
			if (same_zone(entries, idx, nodes[i]))
				
				goto next1;
		}
	}
	while (n--) {
		nodes[nr++] = idx;
next:
		idx = (idx + 1) % nr_entries;
		if (idx == base) {
			panic("bug"); /* not found */
		}
		if(is_closed_node(entries,idx))
			goto next;
		for (i = 0; i < nr; i++) {
			if (same_node(entries, idx, nodes[i]))
				/* this node is already selected, so skip here */
				goto next;
			if(flag)
				if (same_zone(entries, idx, nodes[i]))
				/* this node is in the same zone, so skip here */
					goto next;
		}
	}

	return idx;
}

static inline int hval_to_sheep_lp(struct sheepdog_vnode_list_entry *entries,
				int nr_entries, int nr_obj,uint64_t id, int idx)
{
	int i;
	struct sheepdog_vnode_list_entry *e = entries, *n;

	for (i = 0; i < nr_entries - 1; i++, e++) {
		n = e + 1;
		if (id > e->id && id <= n->id){
			break;
		}
	}
	/*
	while(n->state == SD_NODE_CLOSE){
		i = (i + 1) % nr_entries;
		n = entries + (i + 1) % nr_entries;
				
	}*/
	/*if(idx < nr_obj)
		return get_nth_node_lp(entries, nr_entries, (i + 1) % nr_entries, idx, 1);
	else 
		return get_nth_node_lp(entries, nr_entries,(i + 1) % nr_entries, idx, 0);*/
		return get_nth_node_lp_debug(entries, nr_entries, nr_obj, (i + 1) % nr_entries, idx);
}

static inline int obj_to_sheep_lp(struct sheepdog_vnode_list_entry *entries,
			       int nr_entries, int nr_obj, uint64_t oid, int idx)
{
	//nr_obj is acatually number of obj
	uint64_t id = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);

	return hval_to_sheep_lp(entries, nr_entries, nr_obj, id, idx);
}

/*+++++++++++end++++++++++++++++++*/

/* traverse the virtual node list and return the n'th one */
static inline int get_nth_node(struct sheepdog_vnode_list_entry *entries,
			       int nr_entries, int base, int n)
{
	int nodes[SD_MAX_REDUNDANCY];
	int nr = 0, idx = base, i;

	while (n--) {
		nodes[nr++] = idx;
next:
		idx = (idx + 1) % nr_entries;
		if (idx == base) {
			panic("bug"); /* not found */
		}
		for (i = 0; i < nr; i++) {
			if (same_node(entries, idx, nodes[i]))
				/* this node is already selected, so skip here */
				goto next;
			if (same_zone(entries, idx, nodes[i]))
				/* this node is in the same zone, so skip here */
				goto next;
		}
	}

	return idx;
}

static inline int hval_to_sheep(struct sheepdog_vnode_list_entry *entries,
				int nr_entries, uint64_t id, int idx)
{
	int i;
	struct sheepdog_vnode_list_entry *e = entries, *n;

	for (i = 0; i < nr_entries - 1; i++, e++) {
		n = e + 1;
		if (id > e->id && id <= n->id )
			break;
	}
	return get_nth_node(entries, nr_entries, (i + 1) % nr_entries, idx);
}

static inline int obj_to_sheep(struct sheepdog_vnode_list_entry *entries,
			       int nr_entries, uint64_t oid, int idx)
{
	uint64_t id = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);

	return hval_to_sheep(entries, nr_entries, id, idx);
}

static inline int obj_to_sheep_def(struct sheepdog_vnode_list_entry *entries,
			       int nr_entries, int nr_obj, uint64_t oid, int idx)
{
	return obj_to_sheep(entries, nr_entries, oid, idx);
}

static inline int is_sheep_op(uint8_t op)
{
	return op & SD_OP_SHEEP;
}

static inline const char *sd_strerror(int err)
{
	int i;

	static const struct {
		int err;
		const char *desc;
	} errors[] = {
		{SD_RES_SUCCESS, "Success"},
		{SD_RES_UNKNOWN, "Unknown error"},
		{SD_RES_NO_OBJ, "No object found"},
		{SD_RES_EIO, "I/O error"},
		{SD_RES_VDI_EXIST, "VDI exists already"},
		{SD_RES_INVALID_PARMS, "Invalid parameters"},
		{SD_RES_SYSTEM_ERROR, "System error"},
		{SD_RES_VDI_LOCKED, "VDI is already locked"},
		{SD_RES_NO_VDI, "No VDI found"},
		{SD_RES_NO_BASE_VDI, "No base VDI found"},
		{SD_RES_VDI_READ, "Failed to read from requested VDI"},
		{SD_RES_VDI_WRITE, "Failed to write to requested VDI"},
		{SD_RES_BASE_VDI_READ, "Failed to read from base VDI"},
		{SD_RES_BASE_VDI_WRITE, "Failed to write to base VDI"},
		{SD_RES_NO_TAG, "Failed to find requested tag"},
		{SD_RES_STARTUP, "System is still booting"},
		{SD_RES_VDI_NOT_LOCKED, "VDI is not locked"},
		{SD_RES_SHUTDOWN, "System is shutting down"},
		{SD_RES_NO_MEM, "Out of memory on server"},
		{SD_RES_FULL_VDI, "Maximum number of VDIs reached"},
		{SD_RES_VER_MISMATCH, "Protocol version mismatch"},
		{SD_RES_NO_SPACE, "Server has no space for new objects"},
		{SD_RES_WAIT_FOR_FORMAT, "Waiting for cluster to be formatted"},
		{SD_RES_WAIT_FOR_JOIN, "Waiting for other nodes to join cluster"},
		{SD_RES_JOIN_FAILED, "Node has failed to join cluster"},
		{SD_RES_HALT, "IO has halted as there are too few living nodes"},
		{SD_RES_MANUAL_RECOVER, "Cluster is running/halted and cannot be manually recovered"},

		{SD_RES_OLD_NODE_VER, "Remote node has an old epoch"},
		{SD_RES_NEW_NODE_VER, "Remote node has a new epoch"},
		{SD_RES_NOT_FORMATTED, "Cluster has not been formatted"},
		{SD_RES_INVALID_CTIME, "Creation times differ"},
		{SD_RES_INVALID_EPOCH, "Invalid epoch"},
		/*+++++++++++++lingyun+++++++++++++++++++*/
		{SD_RES_SWITCH,"cluster power mode is switching"}, 
		{SD_RES_NO_ZONE,"close/wake a wrong zone"},
		{SD_RES_LOWPOWER,"Cluster is in lowpower mode"},
		{SD_RES_WRITE_LOG_ERR,"write log error!"},
		{SD_RES_DUP_OP,"wakup/close zone have the same state"},
		/*++++++++++++++end++++++++++++++++++++*/
	};

	for (i = 0; i < ARRAY_SIZE(errors); ++i)
		if (errors[i].err == err)
			return errors[i].desc;

	return "Invalid error code";
}

static inline int node_cmp(const void *a, const void *b)
{
	const struct sheepdog_node_list_entry *node1 = a;
	const struct sheepdog_node_list_entry *node2 = b;
	int cmp;

	cmp = memcmp(node1->addr, node2->addr, sizeof(node1->addr));
	if (cmp != 0)
		return cmp;

	if (node1->port < node2->port)
		return -1;
	if (node1->port > node2->port)
		return 1;
	return 0;
}

static inline int vnode_cmp(const void *a, const void *b)
{
	const struct sheepdog_vnode_list_entry *node1 = a;
	const struct sheepdog_vnode_list_entry *node2 = b;

	if (node1->id < node2->id)
		return -1;
	if (node1->id > node2->id)
		return 1;
	return 0;
}

static inline int nodes_to_vnodes(struct sheepdog_node_list_entry *nodes, int nr,
				  struct sheepdog_vnode_list_entry *vnodes)
{
	struct sheepdog_node_list_entry *n = nodes;
	int i, j, nr_vnodes = 0;
	uint64_t hval;

	while (nr--) {
		hval = FNV1A_64_INIT;

		for (i = 0; i < n->nr_vnodes; i++) {
			if (vnodes) {
				hval = fnv_64a_buf(&n->port, sizeof(n->port), hval);
				for (j = ARRAY_SIZE(n->addr) - 1; j >= 0; j--)
					hval = fnv_64a_buf(&n->addr[j], 1, hval);

				vnodes[nr_vnodes].id = hval;
				memcpy(vnodes[nr_vnodes].addr, n->addr, sizeof(n->addr));
				vnodes[nr_vnodes].port = n->port;
				vnodes[nr_vnodes].node_idx = n - nodes;
				vnodes[nr_vnodes].zone = n->zone;
				/*+++++++lingyun+++++++++++*/
				vnodes[nr_vnodes].state = n->state;
				/*+++++++end+++++++++++++*/
			}

			nr_vnodes++;
		}

		n++;
	}

	if (vnodes)
		qsort(vnodes, nr_vnodes, sizeof(*vnodes), vnode_cmp);

	return nr_vnodes;
}

#endif
