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

#include "../include/config.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/syslog.h>

#include "sheep_priv.h"

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"
#define LOG_FILE_NAME "sheep.log"

LIST_HEAD(cluster_drivers);
static char program_name[] = "sheep";

static struct option const long_options[] = {
	{"port", required_argument, NULL, 'p'},
	{"foreground", no_argument, NULL, 'f'},
	{"loglevel", required_argument, NULL, 'l'},
	{"debug", no_argument, NULL, 'd'},
	{"directio", no_argument, NULL, 'D'},
	{"zone", required_argument, NULL, 'z'},
	{"cluster", required_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static const char *short_options = "p:fl:dDz:c:h";

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else
		printf("\
Sheepdog daemon (version %s)\n\
Usage: %s [OPTION]... [PATH]\n\
Options:\n\
  -p, --port              specify the TCP port on which to listen\n\
  -f, --foreground        make the program run in the foreground\n\
  -l, --loglevel          specify the level of logging detail\n\
  -d, --debug             include debug messages in the log\n\
  -D, --directio          use direct IO when accessing the object store\n\
  -z, --zone              specify the zone id\n\
  -c, --cluster           specify the cluster driver\n\
  -h, --help              display this help and exit\n\
", PACKAGE_VERSION, program_name);
	exit(status);
}

static void sdlog_help(void)
{
	printf("\
Available log levels:\n\
  #    Level           Description\n\
  0    SDOG_EMERG      system has failed and is unusable\n\
  1    SDOG_ALERT      action must be taken immediately\n\
  2    SDOG_CRIT       critical conditions\n\
  3    SDOG_ERR        error conditions\n\
  4    SDOG_WARNING    warning conditions\n\
  5    SDOG_NOTICE     normal but significant conditions\n\
  6    SDOG_INFO       informational notices\n\
  7    SDOG_DEBUG      debugging messages\n");
}

static struct cluster_info __sys;
struct cluster_info *sys = &__sys;

int main(int argc, char **argv)
{
	int ch, longindex;
	int ret, port = SD_LISTEN_PORT;
	const char *dir = DEFAULT_OBJECT_DIR;
	int is_daemon = 1;
	int log_level = SDOG_INFO;
	char path[PATH_MAX];
	int64_t zone = -1;
	char *p;
	struct cluster_driver *cdrv;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			port = strtol(optarg, &p, 10);
			if (optarg == p || port < 1 || port > UINT16_MAX) {
				fprintf(stderr, "Invalid port number '%s'\n",
					optarg);
				exit(1);
			}
			break;
		case 'f':
			is_daemon = 0;
			break;
		case 'l':
			log_level = strtol(optarg, &p, 10);
			if (optarg == p || log_level < SDOG_EMERG ||
			    log_level > SDOG_DEBUG) {
				fprintf(stderr, "Invalid log level '%s'\n",
					optarg);
				sdlog_help();
				exit(1);
			}
			break;
		case 'd':
			/* removed soon. use loglevel instead */
			log_level = SDOG_DEBUG;
			break;
		case 'D':
			dprintf("direct IO mode\n");
			sys->use_directio = 1;
			break;
		case 'z':
			zone = strtol(optarg, &p, 10);
			if (optarg == p || zone < 0 || UINT32_MAX < zone) {
				fprintf(stderr, "Invalid zone id '%s': "
					"must be an integer between 0 and %u\n",
					optarg, UINT32_MAX);
				exit(1);
			}
			sys->this_node.zone = zone;
			break;
		case 'c':
			sys->cdrv = find_cdrv(optarg);
			if (!sys->cdrv) {
				fprintf(stderr, "Invalid cluster driver '%s'\n", optarg);
				fprintf(stderr, "Supported drivers:");
				FOR_EACH_CLUSTER_DRIVER(cdrv) {
					fprintf(stderr, " %s", cdrv->name);
				}
				fprintf(stderr, "\n");
				exit(1);
			}

			sys->cdrv_option = get_cdrv_option(sys->cdrv, optarg);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (optind != argc)
		dir = argv[optind];

	snprintf(path, sizeof(path), "%s/" LOG_FILE_NAME, dir);

	srandom(port);

	if (is_daemon && daemon(0, 0))
		exit(1);

	ret = init_base_path(dir);
	if (ret)
		exit(1);

	ret = log_init(program_name, LOG_SPACE_SIZE, is_daemon, log_level, path);
	if (ret)
		exit(1);

	ret = init_store(dir);
	if (ret)
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = create_listen_port(port, sys);
	if (ret)
		exit(1);

	ret = create_cluster(port, zone);
	if (ret) {
		eprintf("failed to create sheepdog cluster\n");
		exit(1);
	}

	sys->cpg_wqueue = init_work_queue(1);
	sys->gateway_wqueue = init_work_queue(NR_GW_WORKER_THREAD);
	sys->io_wqueue = init_work_queue(NR_IO_WORKER_THREAD);
	sys->recovery_wqueue = init_work_queue(1);
	sys->deletion_wqueue = init_work_queue(1);
	if (!sys->cpg_wqueue || !sys->gateway_wqueue || !sys->io_wqueue ||
	    !sys->recovery_wqueue || !sys->deletion_wqueue)
		exit(1);

	vprintf(SDOG_NOTICE, "sheepdog daemon (version %s) started\n", PACKAGE_VERSION);

	while (!sys_stat_shutdown() || sys->nr_outstanding_reqs != 0)
		event_loop(-1);

	vprintf(SDOG_INFO, "shutdown\n");

	log_close();

	return 0;
}
