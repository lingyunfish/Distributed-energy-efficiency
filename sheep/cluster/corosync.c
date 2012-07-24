/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <unistd.h>
#include <corosync/cpg.h>
#include <corosync/cfg.h>

#include "cluster.h"
#include "work.h"

struct cpg_node {
	uint32_t nodeid;
	uint32_t pid;
	uint32_t gone;
	struct sheepdog_node_list_entry ent;
};

static cpg_handle_t cpg_handle;
static struct cpg_name cpg_group = { 8, "sheepdog" };

static corosync_cfg_handle_t cfg_handle;
static struct cpg_node this_node;

static struct work_queue *corosync_block_wq;

static struct cdrv_handlers corosync_handlers;
static enum cluster_join_result (*corosync_check_join_cb)(
	struct sheepdog_node_list_entry *joining, void *opaque);

static LIST_HEAD(corosync_event_list);
static LIST_HEAD(corosync_block_list);

static struct cpg_node cpg_nodes[SD_MAX_NODES];
static size_t nr_cpg_nodes;

/* event types which are dispatched in corosync_dispatch() */
enum corosync_event_type {
	COROSYNC_EVENT_TYPE_JOIN,
	COROSYNC_EVENT_TYPE_LEAVE,
	COROSYNC_EVENT_TYPE_NOTIFY,
};

/* multicast message type */
enum corosync_message_type {
	COROSYNC_MSG_TYPE_JOIN_REQUEST,
	COROSYNC_MSG_TYPE_JOIN_RESPONSE,
	COROSYNC_MSG_TYPE_LEAVE,
	COROSYNC_MSG_TYPE_NOTIFY,
	COROSYNC_MSG_TYPE_BLOCK,
	COROSYNC_MSG_TYPE_UNBLOCK,
};

struct corosync_event {
	enum corosync_event_type type;

	struct cpg_node sender;
	void *msg;
	size_t msg_len;

	enum cluster_join_result result;
	uint32_t nr_nodes;
	struct cpg_node nodes[SD_MAX_NODES];

	int blocked;
	int callbacked;
	int first_node;

	struct list_head list;
};

struct corosync_message {
	struct cpg_node sender;
	enum corosync_message_type type : 4;
	enum cluster_join_result result : 4;
	uint32_t msg_len;
	uint32_t nr_nodes;
	struct cpg_node nodes[SD_MAX_NODES];
	uint8_t msg[0];
};

struct corosync_block_msg {
	void *msg;
	size_t msg_len;
	void (*cb)(void *arg);

	struct work work;
	struct list_head list;
};

static int cpg_node_equal(struct cpg_node *a, struct cpg_node *b)
{
	return (a->nodeid == b->nodeid && a->pid == b->pid);
}

static inline int find_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
				struct cpg_node *key)
{
	int i;

	for (i = 0; i < nr_nodes; i++)
		if (cpg_node_equal(nodes + i, key))
			return i;

	return -1;
}

static inline void add_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
				struct cpg_node *added)
{
	nodes[nr_nodes++] = *added;
}

static inline void del_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
				struct cpg_node *deled)
{
	int idx;

	idx = find_cpg_node(nodes, nr_nodes, deled);
	if (idx < 0) {
		dprintf("cannot find node\n");
		return;
	}

	nr_nodes--;
	memmove(nodes + idx, nodes + idx + 1, sizeof(*nodes) * nr_nodes - idx);
}

static int nodeid_to_addr(uint32_t nodeid, uint8_t *addr)
{
	int ret, nr;
	corosync_cfg_node_address_t caddr;
	struct sockaddr_storage *ss = (struct sockaddr_storage *)caddr.address;
	struct sockaddr_in *sin = (struct sockaddr_in *)caddr.address;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)caddr.address;
	void *saddr;

	ret = corosync_cfg_get_node_addrs(cfg_handle, nodeid, 1, &nr, &caddr);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR, "failed to get node addresses (%d)\n", ret);
		return -1;
	}

	if (!nr) {
		vprintf(SDOG_ERR, "no node addresses found\n");
		return -1;
	}

	if (ss->ss_family == AF_INET6) {
		saddr = &sin6->sin6_addr;
		memcpy(addr, saddr, 16);
	} else if (ss->ss_family == AF_INET) {
		saddr = &sin->sin_addr;
		memset(addr, 0, 16);
		memcpy(addr + 12, saddr, 4);
	} else {
		vprintf(SDOG_ERR, "unknown protocol %d\n", ss->ss_family);
		return -1;
	}

	return 0;
}

static int send_message(enum corosync_message_type type,
			enum cluster_join_result result,
			struct cpg_node *sender, struct cpg_node *nodes,
			size_t nr_nodes, void *msg, size_t msg_len)
{
	struct iovec iov[2];
	int ret, iov_cnt = 1;
	struct corosync_message cmsg = {
		.type = type,
		.msg_len = msg_len,
		.result = result,
		.sender = *sender,
		.nr_nodes = nr_nodes,
	};

	if (nodes)
		memcpy(cmsg.nodes, nodes, sizeof(*nodes) * nr_nodes);

	iov[0].iov_base = &cmsg;
	iov[0].iov_len = sizeof(cmsg);
	if (msg) {
		iov[1].iov_base = msg;
		iov[1].iov_len = msg_len;
		iov_cnt++;
	}
retry:
	ret = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, iov_cnt);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("failed to send message: retrying\n");
		sleep(1);
		goto retry;
	default:
		eprintf("failed to send message (%d)\n", ret);
		return -1;
	}
	return 0;
}

static void corosync_block(struct work *work)
{
	struct corosync_block_msg *bm = container_of(work, typeof(*bm), work);

	bm->cb(bm->msg);
}

static void corosync_block_done(struct work *work)
{
	struct corosync_block_msg *bm = container_of(work, typeof(*bm), work);

	send_message(COROSYNC_MSG_TYPE_UNBLOCK, 0, &this_node, NULL, 0,
		     bm->msg, bm->msg_len);

	free(bm->msg);
	free(bm);
}

static struct corosync_event *find_block_event(enum corosync_event_type type,
					       struct cpg_node *sender)
{
	struct corosync_event *cevent;

	list_for_each_entry(cevent, &corosync_event_list, list) {
		if (!cevent->blocked)
			continue;

		if (cevent->type == type &&
		    cpg_node_equal(&cevent->sender, sender))
			return cevent;
	}

	return NULL;
}

static int is_master(struct cpg_node *node)
{
	int i;
	struct cpg_node *n = node;
	if (!n)
		n = &this_node;
	if (nr_cpg_nodes == 0)
		/* this node should be the first cpg node */
		return 0;

	for (i = 0; i < SD_MAX_NODES; i++) {
		if (!cpg_nodes[i].gone)
			break;
	}

	if (cpg_node_equal(&cpg_nodes[i], n))
		return i;
	return -1;
}

static void build_node_list(struct cpg_node *nodes, size_t nr_nodes,
			    struct sheepdog_node_list_entry *entries)
{
	int i;

	for (i = 0; i < nr_nodes; i++)
		entries[i] = nodes[i].ent;
}

/*
 * Process one dispatch event
 *
 * Returns 1 if the event is processed
 */
static int __corosync_dispatch_one(struct corosync_event *cevent)
{
	struct corosync_block_msg *bm;
	enum cluster_join_result res;
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int idx;

	switch (cevent->type) {
	case COROSYNC_EVENT_TYPE_JOIN:
		if (cevent->blocked) {
			if (is_master(&this_node) < 0)
				return 0;

			if (!cevent->msg)
				/* we haven't receive JOIN_REQUEST yet */
				return 0;

			if (cevent->callbacked)
				/* check_join() must be called only once */
				return 0;

			res = corosync_check_join_cb(&cevent->sender.ent,
						     cevent->msg);
			if (res == CJ_RES_MASTER_TRANSFER)
				nr_cpg_nodes = 0;

			send_message(COROSYNC_MSG_TYPE_JOIN_RESPONSE, res,
				     &cevent->sender, cpg_nodes, nr_cpg_nodes,
				     cevent->msg, cevent->msg_len);

			if (res == CJ_RES_MASTER_TRANSFER) {
				eprintf("failed to join sheepdog cluster: please retry when master is up\n");
				exit(1);
			}

			cevent->callbacked = 1;
			return 0;
		}

		switch (cevent->result) {
		case CJ_RES_SUCCESS:
		case CJ_RES_MASTER_TRANSFER:
			add_cpg_node(cpg_nodes, nr_cpg_nodes, &cevent->sender);
			nr_cpg_nodes++;
			/* fall through */
		case CJ_RES_FAIL:
		case CJ_RES_JOIN_LATER:
			build_node_list(cpg_nodes, nr_cpg_nodes, entries);
			corosync_handlers.join_handler(&cevent->sender.ent, entries,
						       nr_cpg_nodes, cevent->result,
						       cevent->msg);
			break;
		}
		break;
	case COROSYNC_EVENT_TYPE_LEAVE:
		idx = find_cpg_node(cpg_nodes, nr_cpg_nodes, &cevent->sender);
		if (idx < 0)
			break;
		cevent->sender.ent = cpg_nodes[idx].ent;

		del_cpg_node(cpg_nodes, nr_cpg_nodes, &cevent->sender);
		nr_cpg_nodes--;
		build_node_list(cpg_nodes, nr_cpg_nodes, entries);
		corosync_handlers.leave_handler(&cevent->sender.ent,
						entries, nr_cpg_nodes);
		break;
	case COROSYNC_EVENT_TYPE_NOTIFY:
		if (cevent->blocked) {
			if (cpg_node_equal(&cevent->sender, &this_node) &&
			    !cevent->callbacked) {
				/* call a block callback function from a worker thread */
				if (list_empty(&corosync_block_list))
					panic("cannot call block callback\n");

				bm = list_first_entry(&corosync_block_list,
						      typeof(*bm), list);
				list_del(&bm->list);

				bm->work.fn = corosync_block;
				bm->work.done = corosync_block_done;
				queue_work(corosync_block_wq, &bm->work);

				cevent->callbacked = 1;
			}

			/* block the rest messages until unblock message comes */
			return 0;
		}

		corosync_handlers.notify_handler(&cevent->sender.ent, cevent->msg,
						 cevent->msg_len);
		break;
	}

	return 1;
}

static void __corosync_dispatch(void)
{
	struct corosync_event *cevent;
	static int join_finished;
	int done;

	while (!list_empty(&corosync_event_list)) {
		cevent = list_first_entry(&corosync_event_list, typeof(*cevent), list);

		/* update join status */
		if (!join_finished && cevent->type == COROSYNC_EVENT_TYPE_JOIN) {
			if (cevent->first_node) {
				join_finished = 1;
				nr_cpg_nodes = 0;
			}
			if (!cevent->blocked && cpg_node_equal(&cevent->sender, &this_node)) {
				join_finished = 1;
				nr_cpg_nodes = cevent->nr_nodes;
				memcpy(cpg_nodes, cevent->nodes,
				       sizeof(*cevent->nodes) * cevent->nr_nodes);
			}
		}

		if (join_finished)
			done = __corosync_dispatch_one(cevent);
		else
			done = !cevent->blocked;

		if (!done)
			break;

		list_del(&cevent->list);
		free(cevent->msg);
		free(cevent);
	}
}

static struct corosync_event *update_block_event(enum corosync_event_type type,
						 struct cpg_node *sender,
						 void *msg, size_t msg_len)
{
	struct corosync_event *cevent;

	cevent = find_block_event(type, sender);
	if (!cevent)
		/* block message was casted before this node joins */
		return NULL;

	cevent->msg_len = msg_len;
	if (msg_len) {
		cevent->msg = realloc(cevent->msg, msg_len);
		if (!cevent->msg)
			panic("failed to allocate memory\n");
		memcpy(cevent->msg, msg, msg_len);
	} else {
		free(cevent->msg);
		cevent->msg = NULL;
	}

	return cevent;
}

static void cdrv_cpg_deliver(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     uint32_t nodeid, uint32_t pid,
			     void *msg, size_t msg_len)
{
	struct corosync_event *cevent;
	struct corosync_message *cmsg = msg;
	int master;

	dprintf("%d\n", cmsg->type);

	cevent = zalloc(sizeof(*cevent));
	if (!cevent)
		panic("failed to allocate memory\n");

	switch (cmsg->type) {
	case COROSYNC_MSG_TYPE_JOIN_REQUEST:
		free(cevent); /* we don't add a new cluster event in this case */

		cevent = update_block_event(COROSYNC_EVENT_TYPE_JOIN, &cmsg->sender,
					    cmsg->msg, cmsg->msg_len);
		if (!cevent)
			break;

		cevent->sender = cmsg->sender;
		cevent->msg_len = cmsg->msg_len;
		break;
	case COROSYNC_MSG_TYPE_BLOCK:
		cevent->blocked = 1;
		/* fall through */
	case COROSYNC_MSG_TYPE_NOTIFY:
		cevent->type = COROSYNC_EVENT_TYPE_NOTIFY;

		cevent->sender = cmsg->sender;
		cevent->msg_len = cmsg->msg_len;
		if (cmsg->msg_len) {
			cevent->msg = zalloc(cmsg->msg_len);
			if (!cevent->msg)
				panic("failed to allocate memory\n");
			memcpy(cevent->msg, cmsg->msg, cmsg->msg_len);
		} else
			cevent->msg = NULL;

		list_add_tail(&cevent->list, &corosync_event_list);
		break;
	case COROSYNC_MSG_TYPE_LEAVE:
		cevent->type = COROSYNC_EVENT_TYPE_LEAVE;

		master = is_master(&cmsg->sender);
		if (master >= 0)
		/* Master is down before new nodes finish joining.
		 * We have to revoke its mastership to avoid cluster hanging
		 */
			cpg_nodes[master].gone = 1;

		cevent->sender = cmsg->sender;
		cevent->msg_len = cmsg->msg_len;
		if (cmsg->msg_len) {
			cevent->msg = xzalloc(cmsg->msg_len);
			memcpy(cevent->msg, cmsg->msg, cmsg->msg_len);
		} else
			cevent->msg = NULL;

		list_add_tail(&cevent->list, &corosync_event_list);
		break;
	case COROSYNC_MSG_TYPE_JOIN_RESPONSE:
		free(cevent); /* we don't add a new cluster event in this case */

		cevent = update_block_event(COROSYNC_EVENT_TYPE_JOIN, &cmsg->sender,
					    cmsg->msg, cmsg->msg_len);
		if (!cevent)
			break;

		cevent->blocked = 0;

		cevent->result = cmsg->result;
		cevent->nr_nodes = cmsg->nr_nodes;
		memcpy(cevent->nodes, cmsg->nodes,
		       sizeof(*cmsg->nodes) * cmsg->nr_nodes);

		break;
	case COROSYNC_MSG_TYPE_UNBLOCK:
		free(cevent); /* we don't add a new cluster event in this case */

		cevent = update_block_event(COROSYNC_EVENT_TYPE_NOTIFY,
					    &cmsg->sender, cmsg->msg, cmsg->msg_len);
		if (!cevent)
			break;

		cevent->blocked = 0;
		break;
	}

	__corosync_dispatch();
}

static void cdrv_cpg_confchg(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     const struct cpg_address *member_list,
			     size_t member_list_entries,
			     const struct cpg_address *left_list,
			     size_t left_list_entries,
			     const struct cpg_address *joined_list,
			     size_t joined_list_entries)
{
	struct corosync_event *cevent;
	int i;
	struct cpg_node joined_sheep[SD_MAX_NODES];
	struct cpg_node left_sheep[SD_MAX_NODES];

	dprintf("mem:%zu, joined:%zu, left:%zu\n",
		member_list_entries, joined_list_entries,
		left_list_entries);

	/* convert cpg_address to cpg_node */
	for (i = 0; i < left_list_entries; i++) {
		left_sheep[i].nodeid = left_list[i].nodeid;
		left_sheep[i].pid = left_list[i].pid;
	}
	for (i = 0; i < joined_list_entries; i++) {
		joined_sheep[i].nodeid = joined_list[i].nodeid;
		joined_sheep[i].pid = joined_list[i].pid;
	}

	/* dispatch leave_handler */
	for (i = 0; i < left_list_entries; i++) {
		int master;
		cevent = find_block_event(COROSYNC_EVENT_TYPE_JOIN,
					  left_sheep + i);
		if (cevent) {
			/* the node left before joining */
			list_del(&cevent->list);
			free(cevent->msg);
			free(cevent);
			continue;
		}

		cevent = find_block_event(COROSYNC_EVENT_TYPE_NOTIFY,
					  left_sheep + i);
		if (cevent) {
			/* the node left before sending UNBLOCK */
			list_del(&cevent->list);
			free(cevent->msg);
			free(cevent);
		}

		cevent = zalloc(sizeof(*cevent));
		if (!cevent)
			panic("failed to allocate memory\n");

		master = is_master(&left_sheep[i]);
		if (master >= 0)
		/* Master is down before new nodes finish joining.
		 * We have to revoke its mastership to avoid cluster hanging
		 */
			cpg_nodes[master].gone = 1;

		cevent->type = COROSYNC_EVENT_TYPE_LEAVE;
		cevent->sender = left_sheep[i];

		list_add_tail(&cevent->list, &corosync_event_list);
	}

	/* dispatch join_handler */
	for (i = 0; i < joined_list_entries; i++) {
		cevent = zalloc(sizeof(*cevent));
		if (!cevent)
			panic("failed to allocate memory\n");

		cevent->type = COROSYNC_EVENT_TYPE_JOIN;
		cevent->sender = joined_sheep[i];
		cevent->blocked = 1; /* FIXME: add explanation */
		if (member_list_entries == joined_list_entries - left_list_entries &&
		    cpg_node_equal(&joined_sheep[0], &this_node))
			cevent->first_node = 1;

		list_add_tail(&cevent->list, &corosync_event_list);
	}

	__corosync_dispatch();
}

static int corosync_init(struct cdrv_handlers *handlers, const char *option,
			 uint8_t *myaddr)
{
	int ret, fd;
	uint32_t nodeid;
	cpg_callbacks_t cb = {
		.cpg_deliver_fn = cdrv_cpg_deliver,
		.cpg_confchg_fn = cdrv_cpg_confchg
	};

	corosync_handlers = *handlers;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CPG_OK) {
		eprintf("failed to initialize cpg (%d) - is corosync running?\n", ret);
		return -1;
	}

	ret = corosync_cfg_initialize(&cfg_handle, NULL);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR, "failed to initialize cfg (%d)\n", ret);
		return -1;
	}

	ret = corosync_cfg_local_get(cfg_handle, &nodeid);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR, "failed to get node id (%d)\n", ret);
		return -1;
	}

	ret = nodeid_to_addr(nodeid, myaddr);
	if (ret < 0) {
		eprintf("failed to get local address\n");
		return -1;
	}

	this_node.nodeid = nodeid;
	this_node.pid = getpid();

	ret = cpg_fd_get(cpg_handle, &fd);
	if (ret != CPG_OK) {
		eprintf("failed to get cpg file descriptor (%d)\n", ret);
		return -1;
	}

	corosync_block_wq = init_work_queue(1);

	return fd;
}

static int corosync_join(struct sheepdog_node_list_entry *myself,
			 enum cluster_join_result (*check_join_cb)(
				 struct sheepdog_node_list_entry *joining,
				 void *opaque),
			 void *opaque, size_t opaque_len)
{
	int ret;

	corosync_check_join_cb = check_join_cb;
retry:
	ret = cpg_join(cpg_handle, &cpg_group);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("failed to join the sheepdog group: retrying\n");
		sleep(1);
		goto retry;
	case CPG_ERR_SECURITY:
		eprintf("permission denied to join the sheepdog group\n");
		return -1;
	default:
		eprintf("failed to join the sheepdog group (%d)\n", ret);
		return -1;
	}

	this_node.ent = *myself;

	ret = send_message(COROSYNC_MSG_TYPE_JOIN_REQUEST, 0, &this_node,
			   NULL, 0, opaque, opaque_len);

	return ret;
}

static int corosync_leave(void)
{
	return send_message(COROSYNC_MSG_TYPE_LEAVE, 0, &this_node, NULL, 0,
			    NULL, 0);
}

static int corosync_notify(void *msg, size_t msg_len, void (*block_cb)(void *))
{
	int ret;
	struct corosync_block_msg *bm;

	if (block_cb) {
		bm = zalloc(sizeof(*bm));
		if (!bm)
			panic("failed to allocate memory\n");
		bm->msg = zalloc(msg_len);
		if (!bm->msg)
			panic("failed to allocate memory\n");

		memcpy(bm->msg, msg, msg_len);
		bm->msg_len = msg_len;
		bm->cb = block_cb;
		list_add_tail(&bm->list, &corosync_block_list);

		ret = send_message(COROSYNC_MSG_TYPE_BLOCK, 0, &this_node,
				   NULL, 0, NULL, 0);
	} else
		ret = send_message(COROSYNC_MSG_TYPE_NOTIFY, 0, &this_node,
				   NULL, 0, msg, msg_len);

	return ret;
}

static int corosync_dispatch(void)
{
	int ret;

	ret = cpg_dispatch(cpg_handle, CPG_DISPATCH_ALL);
	if (ret != CPG_OK)
		return -1;

	return 0;
}

struct cluster_driver cdrv_corosync = {
	.name       = "corosync",

	.init       = corosync_init,
	.join       = corosync_join,
	.leave      = corosync_leave,
	.notify     = corosync_notify,
	.dispatch   = corosync_dispatch,
};

cdrv_register(cdrv_corosync);
