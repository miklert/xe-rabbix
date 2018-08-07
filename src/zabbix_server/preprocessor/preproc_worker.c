/*
** Zabbix
** Copyright (C) 2001-2018 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

#include "common.h"
#include "daemon.h"
#include "zbxself.h"
#include "log.h"
#include "zbxipcservice.h"
#include "zbxserialize.h"
#include "preprocessing.h"

#include "sysinfo.h"
#include "preproc_worker.h"
#include "item_preproc.h"

#define	STAT_INTERVAL	5	/* if a process is busy and does not sleep then update status not faster than */

//#define IDX process_num % ZBX_PREPROCESSING_FORKS

extern unsigned char	process_type, program_type;
extern int		server_num, process_num;

/******************************************************************************
 *                                                                            *
 * Function: worker_preprocess_value                                          *
 *                                                                            *
 * Purpose: handle item value preprocessing task                              *
 *                                                                            *
 * Parameters: socket  - [IN] IPC socket                                      *
 *             message - [IN] packed preprocessing task                       *
 *                                                                            *
 ******************************************************************************/
static void worker_preprocess_value(zbx_ipc_socket_t *socket, zbx_ipc_message_t *message)
{
	zbx_uint32_t			size = 0;
	unsigned char			*data = NULL, value_type;
	zbx_uint64_t			itemid;
	zbx_variant_t			value, value_num;
	int				i, steps_num;
	char				*error = NULL;
	zbx_timespec_t			*ts;
	zbx_item_history_value_t	*history_value, history_value_local;
	zbx_preproc_op_t		*steps;

	zbx_preprocessor_unpack_task(&itemid, &value_type, &ts, &value, &history_value, &steps, &steps_num,
			message->data);

	for (i = 0; i < steps_num; i++)
	{
		zbx_preproc_op_t	*op = &steps[i];

		if ((ZBX_PREPROC_DELTA_VALUE == op->type || ZBX_PREPROC_DELTA_SPEED == op->type) &&
				NULL == history_value)
		{
			if (FAIL != zbx_item_preproc_convert_value_to_numeric(&value_num, &value, value_type, &error))
			{
				history_value_local.timestamp = *ts;
				zbx_variant_set_variant(&history_value_local.value, &value_num);
				history_value = &history_value_local;
			}

			zbx_variant_clear(&value);
			break;
		}

		if (SUCCEED != zbx_item_preproc(value_type, &value, ts, op, history_value, &error))
		{
			char	*errmsg_full;

			errmsg_full = zbx_dsprintf(NULL, "Item preprocessing step #%d failed: %s", i + 1, error);
			zbx_free(error);
			error = errmsg_full;

			break;
		}

		if (ZBX_VARIANT_NONE == value.type)
			break;
	}

	size = zbx_preprocessor_pack_result(&data, &value, history_value, error);
	zbx_variant_clear(&value);
	zbx_free(error);
	zbx_free(ts);
	zbx_free(steps);

	if (history_value != &history_value_local)
		zbx_free(history_value);
	

	if (FAIL == zbx_ipc_socket_write(socket, ZBX_IPC_PREPROCESSOR_RESULT, data, size))
	{
		zabbix_log(LOG_LEVEL_CRIT, "cannot send preprocessing result");
		exit(EXIT_FAILURE);
	}

	zbx_free(data);
}

ZBX_THREAD_ENTRY(preprocessing_worker_thread, args)
{
	pid_t			ppid;
	char			*error = NULL;
	zbx_ipc_socket_t	socket;
	zbx_ipc_message_t	message;
	char 			socket_name[MAX_STRING_LEN];
	unsigned long processed_messages=0;
	double			time_stat, time_now;


	process_type = ((zbx_thread_args_t *)args)->process_type;
	server_num = ((zbx_thread_args_t *)args)->server_num;
	process_num = ((zbx_thread_args_t *)args)->process_num;

	zbx_setproctitle("%s #%d starting", get_process_type_string(process_type), process_num);

	zbx_ipc_message_init(&message);

	zbx_snprintf(socket_name,MAX_STRING_LEN,"%s%d",ZBX_IPC_SERVICE_PREPROCESSING_WORKER,IDX);

	if (FAIL == zbx_ipc_socket_open(&socket, socket_name, 10, &error))
	{
		zabbix_log(LOG_LEVEL_CRIT, "cannot connect to preprocessing service: %s, socket:  %s", error,socket_name);
		zbx_free(error);
		exit(EXIT_FAILURE);
	}

	ppid = getppid();
	zbx_ipc_socket_write(&socket, ZBX_IPC_PREPROCESSOR_WORKER, (unsigned char *)&ppid, sizeof(ppid));

	zabbix_log(LOG_LEVEL_INFORMATION, "%s #%d started [%s #%d]", get_program_type_string(program_type),
			server_num, get_process_type_string(process_type), process_num);

	zbx_setproctitle("%s #%d started", get_process_type_string(process_type), process_num);

	update_selfmon_counter(ZBX_PROCESS_STATE_BUSY);

	time_stat = zbx_time();
	time_now = time_stat;


	for (;;)
	{
		//WTF???? Aren't there any better place to handle log rotation with locking ?
		//zbx_handle_log();
		time_now = zbx_time();

		update_selfmon_counter(ZBX_PROCESS_STATE_IDLE);

		if (SUCCEED != zbx_ipc_socket_read(&socket, &message))
		{
			zabbix_log(LOG_LEVEL_CRIT, "cannot read preprocessing service request");
			exit(EXIT_FAILURE);
		}

		update_selfmon_counter(ZBX_PROCESS_STATE_BUSY);

		switch (message.code)
		{
			case ZBX_IPC_PREPROCESSOR_REQUEST:
				worker_preprocess_value(&socket, &message);
				processed_messages++;

				break;
		}

		zbx_ipc_message_clean(&message);

		if (STAT_INTERVAL < time_now - time_stat)
		{

			zbx_setproctitle("%s #%d processed %u messages last %d sec", get_process_type_string(process_type), process_num,processed_messages,STAT_INTERVAL);

			time_stat = time_now;
			processed_messages = 0;
		}



	}

	return 0;
}
