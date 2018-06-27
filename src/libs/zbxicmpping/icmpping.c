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

#include "zbxicmpping.h"
#include "threads.h"
#include "comms.h"
#include "log.h"

#define MAX_ICMP_NMAP_FIELDS		10

extern char	*CONFIG_SOURCE_IP;
extern char	*CONFIG_FPING_LOCATION;
#ifdef HAVE_IPV6
extern char	*CONFIG_FPING6_LOCATION;
#endif
extern char	*CONFIG_TMPDIR;

/* old official fping (2.4b2_to_ipv6) did not support source IP address */
/* old patched versions (2.4b2_to_ipv6) provided either -I or -S options */
/* current official fping (3.x) provides -I option for binding to an interface and -S option for source IP address */

static unsigned char	source_ip_checked = 0;
static const char	*source_ip_option = NULL;
#ifdef HAVE_IPV6
static unsigned char	source_ip6_checked = 0;
static const char	*source_ip6_option = NULL;
#endif

static void	get_source_ip_option(const char *fping, const char **option, unsigned char *checked)
{
	FILE	*f;
	char	*p, tmp[MAX_STRING_LEN];

	zbx_snprintf(tmp, sizeof(tmp), "%s -h 2>&1", fping);

	if (NULL == (f = popen(tmp, "r")))
		return;

	while (NULL != fgets(tmp, sizeof(tmp), f))
	{
		for (p = tmp; isspace(*p); p++)
			;

		if ('-' == p[0] && 'I' == p[1] && isspace(p[2]))
		{
			*option = "-I";
			continue;
		}

		if ('-' == p[0] && 'S' == p[1] && isspace(p[2]))
		{
			*option = "-S";
			break;
		}
	}

	pclose(f);

	*checked = 1;
}

static int	process_ping(ZBX_FPING_HOST *hosts, int hosts_count, int count, int interval, int size, int timeout,
		char *error, int max_error_len)
{


	const char	*__function_name = "process_ping";


	FILE		*f;
	char		*c, params[64];
	char		filename[MAX_STRING_LEN], tmp[MAX_STRING_LEN], nmap_tmp[MAX_STRING_LEN];
	size_t		offset;
	ZBX_FPING_HOST	*host;
	double		sec;
	int 		i, ret = NOTSUPPORTED, index;

#ifdef HAVE_IPV6
	int		family;
	char		params6[64];
	char		fping_existence = 0;
#define	FPING_EXISTS	0x1
#define	FPING6_EXISTS	0x2

#endif	/* HAVE_IPV6 */

	assert(hosts);

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hosts_count:%d", __function_name, hosts_count);

	if (-1 == access(CONFIG_FPING_LOCATION, X_OK))
	{
#if !defined(HAVE_IPV6)
		zbx_snprintf(error, max_error_len, "%s: %s", CONFIG_FPING_LOCATION, zbx_strerror(errno));
		return ret;
#endif
	}
	else
	{
#ifdef HAVE_IPV6
		fping_existence |= FPING_EXISTS;
#else
		if (NULL != CONFIG_SOURCE_IP)
		{
			if (FAIL == is_ip4(CONFIG_SOURCE_IP)) /* we do not have IPv4 family address in CONFIG_SOURCE_IP */
			{
				zbx_snprintf(error, max_error_len,
					"You should enable IPv6 support to use IPv6 family address for SourceIP '%s'.", CONFIG_SOURCE_IP);
				return ret;
			}
		}
#endif
	}

#ifdef HAVE_IPV6
	if (-1 == access(CONFIG_FPING6_LOCATION, X_OK))
	{
		if (0 == (fping_existence & FPING_EXISTS))
		{
			zbx_snprintf(error, max_error_len, "At least one of '%s', '%s' must exist. Both are missing in the system.",
					CONFIG_FPING_LOCATION,
					CONFIG_FPING6_LOCATION);
			return ret;
		}
	}
	else
		fping_existence |= FPING6_EXISTS;
#endif	/* HAVE_IPV6 */

	offset = zbx_snprintf(params, sizeof(params), "-C%d", count);
	if (0 != interval)
		offset += zbx_snprintf(params + offset, sizeof(params) - offset, " -p%d", interval);
	if (0 != size)
		offset += zbx_snprintf(params + offset, sizeof(params) - offset, " -b%d", size);
	if (0 != timeout)
		offset += zbx_snprintf(params + offset, sizeof(params) - offset, " -t%d", timeout);

#ifdef HAVE_IPV6
	strscpy(params6, params);
#endif	/* HAVE_IPV6 */

	if (NULL != CONFIG_SOURCE_IP)
	{
#ifdef HAVE_IPV6
		if (0 != (fping_existence & FPING_EXISTS))
		{
			if (0 == source_ip_checked)
				get_source_ip_option(CONFIG_FPING_LOCATION, &source_ip_option, &source_ip_checked);
			if (NULL != source_ip_option)
				zbx_snprintf(params + offset, sizeof(params) - offset,
						" %s%s", source_ip_option, CONFIG_SOURCE_IP);
		}

		if (0 != (fping_existence & FPING6_EXISTS))
		{
			if (0 == source_ip6_checked)
				get_source_ip_option(CONFIG_FPING6_LOCATION, &source_ip6_option, &source_ip6_checked);
			if (NULL != source_ip6_option)
				zbx_snprintf(params6 + offset, sizeof(params6) - offset,
						" %s%s", source_ip6_option, CONFIG_SOURCE_IP);
		}
#else
		if (0 == source_ip_checked)
			get_source_ip_option(CONFIG_FPING_LOCATION, &source_ip_option, &source_ip_checked);
		if (NULL != source_ip_option)
			zbx_snprintf(params + offset, sizeof(params) - offset,
					" %s%s", source_ip_option, CONFIG_SOURCE_IP);
#endif	/* HAVE_IPV6 */
	}

	zbx_snprintf(filename, sizeof(filename), "%s/%s_%li.pinger", CONFIG_TMPDIR, progname, zbx_get_thread_id());

#ifdef HAVE_IPV6
	if (NULL != CONFIG_SOURCE_IP)
	{
		if (SUCCEED != get_address_family(CONFIG_SOURCE_IP, &family, error, max_error_len))
			return ret;

		if (family == PF_INET)
		{
			if (0 == (fping_existence & FPING_EXISTS))
			{
				zbx_snprintf(error, max_error_len, "File '%s' cannot be found in the system.",
						CONFIG_FPING_LOCATION);
				return ret;
			}

			zbx_snprintf(tmp, sizeof(tmp), "%s %s 2>&1 <%s", CONFIG_FPING_LOCATION, params, filename);
		}
		else
		{
			if (0 == (fping_existence & FPING6_EXISTS))
			{
				zbx_snprintf(error, max_error_len, "File '%s' cannot be found in the system.",
						CONFIG_FPING6_LOCATION);
				return ret;
			}

			zbx_snprintf(tmp, sizeof(tmp), "%s %s 2>&1 <%s", CONFIG_FPING6_LOCATION, params6, filename);
		}
	}
	else
	{
		offset = 0;

		if (0 != (fping_existence & FPING_EXISTS))
			offset += zbx_snprintf(tmp + offset, sizeof(tmp) - offset,
					"%s %s 2>&1 <%s;", CONFIG_FPING_LOCATION, params, filename);

		if (0 != (fping_existence & FPING6_EXISTS))
			zbx_snprintf(tmp + offset, sizeof(tmp) - offset,
					"%s %s 2>&1 <%s;", CONFIG_FPING6_LOCATION, params6, filename);
	}
#elsel
	zbx_snprintf(tmp, sizeof(tmp), "%s %s 2>&1 <%s", CONFIG_FPING_LOCATION, params, filename);
#endif	/* HAVE_IPV6 */

	if (NULL == (f = fopen(filename, "w")))
	{
		zbx_snprintf(error, max_error_len, "%s: %s", filename, zbx_strerror(errno));
		return ret;
	}

	zabbix_log(LOG_LEVEL_DEBUG, "%s", filename);

	for (i = 0; i < hosts_count; i++)
	{
		zabbix_log(LOG_LEVEL_DEBUG, "    %s", hosts[i].addr);
		fprintf(f, "%s\n", hosts[i].addr);
	}

	fclose(f);

//	zabbix_log(LOG_LEVEL_DEBUG, "Launch command line is:  %s", tmp);

	if (1) {
		//todo: fix to support config file options +
		//warning message in ipv6 or just delete the code for ipv6    
		zbx_snprintf(nmap_tmp, sizeof(nmap_tmp), "%s %s  %s 2>&1", "/usr/bin/nmap", "-sP -T5 -iL", filename);
		zabbix_log(LOG_LEVEL_DEBUG, "will do %s", nmap_tmp);

		for (i = 0; i < hosts_count; i++)
		{
			hosts[i]->rcv=0;
			hosts[i]->cnt=0;
			hosts[i]->min=0;
			hosts[i]->max=0;
			hosts[i]->sum=0;
		}


		//if count set to one, then we'll use nmap as the utility
		//its way faster
		//but it ouputs in diffent format, so we need kind an adaptation 
		//example of nmap output 
		//Nmap scan report for bs89594.is74.ru (10.102.159.245)
		//Host is up (0.0012s latency).
		//rDNS record for 10.102.159.245: bs86447.is74.ru
		//Nmap scan report for bs14419.is74.ru (10.102.151.189)
		//Host is up (0.0012s latency).
		//Nmap scan report for bs11954.is74.ru (10.102.178.1)
		//Host is up (0.0030s latency).
		//Nmap scan report for bs85530.is74.ru (10.102.207.56)
		//Host is up (0.0010s latency).

		//fping output for :

		//bs15558.is74.ru : 1.14 1.16 1.17 1.20 1.16
		//bs20623.is74.ru : 5.62 5.35 5.50 5.43 5.56
		//bs54917.is74.ru : 4.33 3.92 3.94 3.91 3.97
		//bs05184.is74.ru : 1.44 1.51 1.46 1.34 1.31
		//bs67420.is74.ru : 2.32 2.33 2.32 2.51 2.34
		//bs20513.is74.ru : 4.25 4.24 4.29 5.40 4.39

		if (NULL == (f = popen(nmap_tmp, "r")))
		{
			zbx_snprintf(error, max_error_len, "%s: %s", tmp, zbx_strerror(errno));

			unlink(filename);

			return ret;
		}


	//	memset(tmp,0,sizeof(char)*
		if (NULL == fgets(tmp, sizeof(tmp), f))
			return ret;
		
		do
		{
			zbx_rtrim(tmp, "\n");
			zabbix_log(LOG_LEVEL_DEBUG, "read line [%s]", tmp);

			if (25> strnlen(tmp,MAX_STRING_LEN) ) {
				zabbix_log(LOG_LEVEL_DEBUG, "skipping too short line");
				continue;
			} 
			

			char *fields[MAX_ICMP_NMAP_FIELDS];
			char *end_field;


			//splitting line into fields
		 
			char *field_ptr = strtok_r(tmp, " ", &end_field);
			int field_count=0;

			for (i=0; i++; i<field_count) 
			fields[i]=NULL; 

			while (field_ptr != NULL && MAX_ICMP_NMAP_FIELDS>field_count) 
			{	
				zabbix_log(LOG_LEVEL_DEBUG, "read field %d [%s]",field_count, field_ptr);
			    fields[field_count++]=field_ptr;
			    field_ptr = strtok_r(NULL, " ", &end_field);
			}

			if (NULL == fields[4]) {
				zabbix_log(LOG_LEVEL_DEBUG, "String 1 not enough fields ");
				 continue;
			 
			}
			//we've got at least 5 fields, checking if this line starts from Nmap ..
			if ( 	strcmp("Nmap",fields[0]) != 0 ||
				strcmp("scan",fields[1]) !=0  ||
				strcmp("report", fields[2]) !=0 )  
			{  
				zabbix_log(LOG_LEVEL_DEBUG, "String doesn't match 'Nmap scan for', skipping");
				continue;
			}

			host = NULL;
			//looking for the first space
			for (i = 0; i < hosts_count; i++)
			{
				if (0 == strcmp(fields[4], hosts[i].addr))
				{
					host = &hosts[i];
					zabbix_log(LOG_LEVEL_DEBUG, " Host has been found %s", fields[4]);
					break;
				}
			}

			if (NULL == host) {
				zabbix_log(LOG_LEVEL_DEBUG, " Host hasn't been found in the request");
				continue;
			} else {
				zabbix_log(LOG_LEVEL_DEBUG, " Host has been found %s", fields[4]);
			}

			if (NULL == fgets(tmp, sizeof(tmp), f)) {
				zabbix_log(LOG_LEVEL_DEBUG, "Couldn't read second line");
				continue;
			}

			zabbix_log(LOG_LEVEL_DEBUG, "read line [%s]", tmp);
			zbx_rtrim(tmp, "\n");

			//got the host, reading and splitting the next line 
			char *latency;
		
			field_ptr = strtok_r(tmp, " ", &end_field);
				
			for (i = 0; i++; i<field_count)
				fields[i]=NULL;

			field_count=0;

			while (field_ptr != NULL && MAX_ICMP_NMAP_FIELDS>field_count) 
			{	
				zabbix_log(LOG_LEVEL_DEBUG, "String 2 doesn't parced field %s",field_ptr);
				fields[field_count++]=field_ptr;
				field_ptr = strtok_r(NULL, " ", &end_field);
			}

			if (NULL == fields[3]) {
				zabbix_log(LOG_LEVEL_DEBUG, "String too short");
				continue;
			}

			//we've got at least 5 fields, checking if this line starts from Nmap ..
			if ( 	strcmp("Host",	fields[0]) != 0 ||
				strcmp("is",	fields[1]) !=0  ||
				strcmp("up",	fields[2]) !=0 ) 
			{
								zabbix_log(LOG_LEVEL_DEBUG, "String 2 doesn't match 'Nmap scan for', skipping");  
				continue;
			}

			latency=fields[3]+1;
			zbx_rtrim(latency,"s");
				
			sec=atof(latency);
			host->rcv=1;
			host->cnt=1;
			host->min=sec;
			host->max=sec;
			host->sum=sec;

			zabbix_log(LOG_LEVEL_DEBUG, "Final parced info is host=%s , latency=%f",host->addr,sec);

			ret = SUCCEED;
		}
		while (NULL != fgets(tmp, sizeof(tmp), f));

		
	} else 
	{
		if (NULL == (f = popen(tmp, "r")))
		{
			zbx_snprintf(error, max_error_len, "%s: %s", tmp, zbx_strerror(errno));

			unlink(filename);

			return ret;
		}

		if (NULL == fgets(tmp, sizeof(tmp), f))
		{
			strscpy(tmp, "no output");
		}
		else
		{
			for (i = 0; i < hosts_count; i++)
			{
				hosts[i].status = zbx_malloc(NULL, count);
				memset(hosts[i].status, 0, count);
			}

			do
			{
				zbx_rtrim(tmp, "\n");
				zabbix_log(LOG_LEVEL_DEBUG, "read line [%s]", tmp);

				host = NULL;

				if (NULL != (c = strchr(tmp, ' ')))
				{
					*c = '\0';
					for (i = 0; i < hosts_count; i++)
						if (0 == strcmp(tmp, hosts[i].addr))
						{
							host = &hosts[i];
							break;
						}
					*c = ' ';
				}

				if (NULL == host)
					continue;

				if (NULL == (c = strstr(tmp, " : ")))
					continue;

				/* when NIC bonding is used, there are also lines like */
				/* 192.168.1.2 : duplicate for [0], 96 bytes, 0.19 ms */

				if (NULL != strstr(tmp, "duplicate for"))
					continue;

				c += 3;

				/* The were two issues with processing only the fping's final status line:  */
				/*   1) pinging broadcast addresses could have resulted in responses from   */
				/*      different hosts, which were counted as the target host responses;   */
				/*   2) there is a bug in fping (v3.8 at least) where pinging broadcast     */
				/*      address will result in no individual responses, but the final       */
				/*      status line might contain a bogus value.                            */
				/* Because of the above issues we must monitor the individual responses     */
				/* and mark the valid ones.                                                 */
				if ('[' == *c)
				{
					/* Fping appends response source address in format '[<- 10.3.0.10]' */
					/* if it does not match the target address. Ignore such responses.  */
					if (NULL != strstr(c + 1, "[<-"))
						continue;

					/* get the index of individual ping response */
					index = atoi(c + 1);

					if (0 > index || index >= count)
						continue;

					host->status[index] = 1;

					continue;
				}

				/* process status line for a host */
				index = 0;
				do
				{
					if (1 == host->status[index])
					{
						sec = atof(c) / 1000; /* convert ms to seconds */

						if (0 == host->rcv || host->min > sec)
							host->min = sec;
						if (0 == host->rcv || host->max < sec)
							host->max = sec;
						host->sum += sec;
						host	->rcv++;
					}
				}
				while (++index < count && NULL != (c = strchr(c + 1, ' ')));
					host->cnt += count;
#ifdef HAVE_IPV6
				if (host->cnt == count && NULL == CONFIG_SOURCE_IP &&
						0 != (fping_existence & FPING_EXISTS) &&
						0 != (fping_existence & FPING6_EXISTS))
				{
					memset(host->status, 0, count);	/* reset response statuses for IPv6 */
				}
#endif
				ret = SUCCEED;
			}
			while (NULL != fgets(tmp, sizeof(tmp), f));

			for (i = 0; i < hosts_count; i++)
				zbx_free(hosts[i].status);
		}
	}
	pclose(f);

	unlink(filename);

	if (NOTSUPPORTED == ret)
		zbx_snprintf(error, max_error_len, "fping failed: %s", tmp);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);

	return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: do_ping                                                          *
 *                                                                            *
 * Purpose: ping hosts listed in the host files                               *
 *                                                                            *
 * Parameters:                                                                *
 *                                                                            *
 * Return value: SUCCEED - successfully processed hosts                       *
 *               NOTSUPPORTED - otherwise                                     *
 *                                                                            *
 * Author: Alexei Vladishev                                                   *
 *                                                                            *
 * Comments: use external binary 'fping' to avoid superuser privileges        *
 *                                                                            *
 ******************************************************************************/
int	do_ping(ZBX_FPING_HOST *hosts, int hosts_count, int count, int interval, int size, int timeout, char *error, int max_error_len)
{
	const char	*__function_name = "do_ping";

	int	res;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hosts_count:%d", __function_name, hosts_count);

	if (NOTSUPPORTED == (res = process_ping(hosts, hosts_count, count, interval, size, timeout, error, max_error_len)))
		zabbix_log(LOG_LEVEL_ERR, "%s", error);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, zbx_result_string(res));

	return res;
}
