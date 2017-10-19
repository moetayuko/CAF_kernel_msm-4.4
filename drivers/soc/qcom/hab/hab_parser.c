/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
//define USE_FILESYS
//#define USE_DEVICETREE

#if defined(USE_FILESYS) && !defined(__QNXNTO__)
#include <errno.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#ifndef WIN32
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <pthread.h>
#endif
#include <stdarg.h>

#include "../linux/habmm.h"

#else
/* in-driver compilation */
#include "hab.h"

#if defined(__linux__) && defined(USE_DEVICETREE)
#include <linux/of.h>
#endif

#endif



#if defined(USE_FILESYS) && !defined(__QNXNTO__)
// ++ To be removed
#define HAB_LOG_ERR printf
#define HAB_LOG_INFO printf
// --
#else
#ifdef __linux__
#define strtol simple_strtol
/* kernel only definition */
#endif

#endif

/*
 * set valid mmid value in tbl to show this is valid entry. All inputs here are
 * normalized to 1 based integer
 */
static int fill_vmid_mmid_tbl (struct vmid_mmid_desc *tbl, int32_t vm_start,
								   int32_t vm_range, int32_t mmid_start,
								   int32_t mmid_range, int32_t be)
{
	int ret = 0;
	int i, j;

	for (i = vm_start; i < vm_start+vm_range; i++) {
		tbl[i].vmid = i; /* set valid vmid value to make it usable */
		for (j = mmid_start; j < mmid_start+mmid_range; j++) {
			/* sanity check */
			if (tbl[i].mmid[j] != HABCFG_VMID_INVALID) {
				HAB_LOG_ERR("overwrite previous setting in vmid %d, mmid %d, be %d\n",
					i, j, tbl[i].is_listener[j]);
			}
			tbl[i].mmid[j] = j;
			tbl[i].is_listener[j] = be; /* BE IS listen */
		}
	}

	return ret;
}

void dump_settings(struct local_vmid *settings)
{
	int i, j;

	HAB_LOG_INFO("self vmid is %d\n", settings->self);
	for (i=0; i<HABCFG_VMID_MAX; i++) {
		HAB_LOG_INFO("remote vmid %d\n", settings->vmid_mmid_list[i].vmid);
		for(j=0; j<=HABCFG_MMID_AREA_MAX; j++) {
			HAB_LOG_INFO("mmid %d, is_be %d\n", settings->vmid_mmid_list[i].mmid[j],
						 settings->vmid_mmid_list[i].is_listener[j]);
		}
	}
}


#if !defined(USE_DEVICETREE)
/* return parsed str in total bytes and the extracted values by -
   0 and negative: parsing failed, no value extracted
   positive: succeeded, exact bytes processed is returned
*/
int find_range(char *str_in, int *start, int *end)
{
	char *strval, *word1, *word2;
	int byte_cnt;

	strval = strsep(&str_in, " \t");
	if (strval) {
		byte_cnt = strlen(strval);/* this range is processed */
		/* further separet the star and end */
		word1 = strsep(&strval, "-");
		word2 = strsep(&strval, "-");

		if(word1 && word2) {
			HAB_LOG_INFO("found range %s %s\n", word1, word2);
			*start = strtol(word1, NULL, 10);
			*end = strtol(word2, NULL, 10);
			return byte_cnt; /* count the whitespace? */
		} else {
			HAB_LOG_INFO("found BE remote is %s\n", strval);
			return 0;
		}
		//ToDo: fill the table? Not yet
	} else {
		HAB_LOG_ERR("failed to find the range in %s\n", str_in);
		return 0;
	}
	return 0; /* we should not come here */
}

/*
	0 or negative: failed to find any meaningful mmids
	positive: total mmid ranges found
*/
int parse_mmid(char* str_in, int32_t vmid_start, int32_t range,
			   int32_t be, struct vmid_mmid_desc *tbl )
{
	char *strval, *str_start = str_in;
	int start, stop, range_cnt, bc, ret = -1;

	start = stop = -1;
	strval = strstr(str_start, HABCFG_ID_MMID); /* move to the start of this id */
	range_cnt = 0;
	while (strval) {
		str_start = strval + strlen(HABCFG_ID_MMID); /* skip the id */
		bc = find_range(str_start, &start, &stop);

		if (bc > 0) {
			if ( (stop-start) < 0 || stop/100 > HABCFG_MMID_AREA_MAX
				|| start/100 <=0 ) {
				HAB_LOG_ERR("find invalid FE MMID range %d - %d\n",
					start, stop);
					/* continue the search */
			} else {
				HAB_LOG_INFO("find MMID range %d - %d\n", start, stop);
				ret = fill_vmid_mmid_tbl (tbl, vmid_start, range,
					start/100, (stop-start)/100 + 1, be);
				if (ret) {
					HAB_LOG_ERR("Failed to fill in vmid mmid tbl vm(%d %d) "
						"mmid(%d %d) be(%d)\n", vmid_start, range, start,
						stop, be);
				}
			}
			/* skip the range & the string minator */
			str_start += (bc+1);
			range_cnt++;
		} else {
			break;
		}

		/* if there is only one separator between mmid and next line, return */
		if(str_start[0] == 'B' || str_start[0] == 'F' || str_start[0] == '\n'){
			/* check HABCFG_ID_BE & HABCFG_ID_FE to make sure it is the same */
			break;
		}
		strval = strstr(str_start, HABCFG_ID_MMID); /* find the next id */
	} /* loop for all the mmid to extract the assocated ranges */

	/* no more range to be found */
	if (!range_cnt) {
		HAB_LOG_ERR("this MMID range is corrupted %s\n", strval);
		return -1;
	} else {
		HAB_LOG_INFO("total %d MMID ranges are found\n", range_cnt);
		return range_cnt;
	}
}


/* parse the input string and fill up the table
	negative: failure
	0 and positive: successful
*/
int parse_line(char *line_in, int32_t self, struct vmid_mmid_desc *tbl)
{
	char *str_start = line_in;
	int ret =  HABCFG_FOUND_NOTHING;
	char * strval, * word;
	int val;
	int start, stop;
	int32_t vmid_start, vmid_range;

	/* check local vmid for FE style from the beginning of the line*/
	strval = strstr(line_in, HABCFG_ID_FE);
	if (strval) {
		strval += strlen(HABCFG_ID_FE);
		word = strsep(&strval, " \t"); /* extract the value */
		if (word) {
			if (!strcmp(word, HABCFG_ID_DONTCARE)) {
				HAB_LOG_INFO("found FE local is %s\n", strval);
				/* default to itself */
				vmid_start = self;
				vmid_range = 1;
			} else {
				val = strtol(word, NULL, 10);
				if (val >= HABCFG_VMID_MAX || val < 0) {
					HAB_LOG_ERR("found invalid remote vmid %d\n", val);
					return ret;
				} else {
					HAB_LOG_INFO("found FE local is %d\n", val);
					vmid_start = val;
					vmid_range = 1;
				}
			}
			str_start = strval; /* skip id & terminiator */

			 /* Remote is BE, local is opener/FE */
			ret = parse_mmid(str_start, vmid_start, vmid_range,
				HABCFG_BE_FALSE, tbl);
			/* FE and BE are not cascaded. skip the return, process new line */
			if (ret > 0) return 0; /* found mmids, return OK */
			else return ret; /* didn't find anything, return faiures */
		} else {
			HAB_LOG_ERR("found no BE remote value %s\n", strval);
			return ret;
		}
	} else {
		HAB_LOG_INFO("No BE found. Continue parsing %s for FE\n", line_in);
	}

	/* check local vmid role is BE style from the beginning of the line,
	   then find out the remote FE ranges */
	strval = strstr(line_in, HABCFG_ID_BE);
	if (strval) {
		strval += strlen(HABCFG_ID_BE);
        word = strsep(&strval, " \t"); /* skip ID BE */
		if (word) {
			/* extract the remote range */
			val = find_range(word, &start, &stop);
			if (val > 0) {
				vmid_start = start;
				vmid_range = stop - start + 1;

				/* continue parsing mmids */
				str_start = strval; /* skip range & terminiator */
				ret = parse_mmid(str_start, vmid_start, vmid_range,
					HABCFG_BE_TRUE, tbl); /* remote is FE, so local is listener */

			} else {
				HAB_LOG_ERR("failed to parse line %s\n", strval);
				// bail out or continue?
			}
		} else {
			HAB_LOG_ERR("found no FE remote value %s\n", strval);
			return ret;
		}
	} else {
		HAB_LOG_INFO("No FE found. Continue parsing %s\n", line_in);
		return ret;
	}
	return ret;
}

/* 0: successful
 * negative: various failure core
 */
int hab_parse_no_dt(struct local_vmid *settings)
{
	char file_path[128] = {0};
#if !defined(USE_FILESYS) && defined(__linux__)
/* for  __linux__ kernel only */
	struct file *fp;
#else
	FILE *fp;
#endif
	long fsize;

	/* please make sure the hab cfg file size is smaller than 256 characters
		including the whitespaces */
	char file_buf[HABCFG_FILE_SIZE_MAX] = {0};
	int val;
	int ret = 0;
	char *fcur, *str_line, *strval, *word;
	int line_cnt;

#if !defined(USE_FILESYS) && defined(__linux__)
	mm_segment_t oldfs;
	loff_t fstart, fend, pos;
#endif

	strcpy(file_path, HABCFG_FILE_PATH);
	strcat(file_path, HABCFG_FILE_NAME);

#if !defined(USE_FILESYS) && defined(__linux__)
	oldfs = get_fs();
	set_fs(get_ds());
	fp = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		//err = PTR_ERR(filp);
#else
	fp = fopen(file_path, "rb");
	if (!fp) {
#endif
		HAB_LOG_ERR("failed to open %s\n", file_path);
		return -ENOENT;
	} else {
		HAB_LOG_INFO("find HAB config file at %s\n", file_path);
	}

#if !defined(USE_FILESYS) && defined(__linux__)
	fstart = vfs_llseek(fp, 0, SEEK_SET);
	fend = vfs_llseek(fp, 0, SEEK_END);
	fsize = fend - fstart;
#else
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
#endif
	if (fsize > sizeof(file_buf)) {
		HAB_LOG_ERR("cfg file size %ld is bigger than allowed %ld size\n", fsize, sizeof(file_buf));
	}
#if !defined(USE_FILESYS) && defined(__linux__)
	vfs_llseek(fp, 0, SEEK_SET);
	pos = 0;
	val = vfs_read(fp, file_buf, fsize, &pos);
#else
	fseek(fp, 0, SEEK_SET);
	val = fread(file_buf, 1, fsize, fp); /* read the whole file in once */
#endif
	if (val != fsize) {
		HAB_LOG_ERR("failed to read cfg into buffer ret %d bytes\n", val);
	}
#if !defined(USE_FILESYS) && defined(__linux__)
	set_fs(oldfs);
	filp_close(fp, NULL);
#else
	fclose(fp);
#endif

	/* pick up the configuration */

	/* 1. check local vmid. this must be the first in cfg file */
	line_cnt = 0;
	fcur = file_buf;
	fcur = strstr(fcur, HABCFG_ID_VMID);
	if (fcur) {
        strval = fcur+strlen(HABCFG_ID_VMID);
		/* extract the number and prepare for the next line */
		word = strsep(&strval, " ,\t\r\n");
		if (word) {
			val = strtol(word, NULL, 10);
			if (val > HABCFG_VMID_MAX || val < 0) {
				/* vmid sanity check */
				HAB_LOG_ERR("detect invalid vmid %d, expecting 0 to %d\n",
							val, HABCFG_VMID_MAX);
				return -ENFILE;
			} else {
				HAB_LOG_INFO("found local VMID is %d\n", val);
				settings->self = val;
				fcur = strval;
				line_cnt++;
			}
		} else {
			HAB_LOG_ERR("failed to find value after detect vmid string at offset %ld\n",
						fcur - file_buf);
			return -ENFILE;
		}
	} else {
		HAB_LOG_ERR("local vmid is not detected in %ld bytes file\n",
					fsize);
		return -ENFILE;
	}

	/* continue parsing after complete local vmid from a new line */
	str_line = strsep(&fcur, ",\r\n");
	while(str_line && fcur) {
		line_cnt++;
		ret = parse_line(str_line, settings->self, settings->vmid_mmid_list);
		/* if one line is corrupted, do we still continue? */
		if (ret < 0) {
			HAB_LOG_ERR("detect corrupted line %s at line cnt %d\n",
				str_line, line_cnt);
			break;
		}
		str_line = strsep(&fcur, ",\r\n"); /* go after next line */
	}
	HAB_LOG_INFO("completed hab cfg file parsing %d lines\n", line_cnt);

	/* only successfully parsed cfg file can be used for hab to boot */
	if (line_cnt > 0) {
		dump_settings(settings);
		HAB_LOG_INFO("hab cfg file successfully parsed for %ld bytes and %d lines!\n", fsize, line_cnt);
		return 0;
	} else {
		HAB_LOG_ERR("hab cfg parsing failed!\n");
		return -ENOEXEC;
	}

	return ret;
}

#else
/* device tree based parser */
int hab_parse_dt(struct local_vmid *settings)
{
	int result, i;
	struct device_node *hab_node = NULL;
	struct device_node *mmid_grp_node = NULL;
	const char *role = NULL;
	int tmp = -1, vmids_num;
    u32 vmids[16];
	int32_t grp_start_id, be;

	/* parse device tree*/
	HAB_LOG_INFO("parsing hab node in device tree...\n");
	hab_node = of_find_compatible_node(NULL, NULL, "qcom,hab");
	if (!hab_node) {
		HAB_LOG_ERR("no hab device tree node\n");
		return -1;
	}

	/* read the local vmid of this VM, like 0 for host, 1 for AGL GVM */
	result = of_property_read_u32(hab_node, "vmid",
									&tmp);
	if (result) {
		HAB_LOG_ERR("failed to read local vmid, result = %d\n", result);
		return result;
	} else {
		HAB_LOG_INFO("local vmid = %d\n", tmp);
		settings->self = tmp;
	}

	for_each_child_of_node(hab_node, mmid_grp_node) {
		/* read the group starting id */
		result = of_property_read_u32(mmid_grp_node,
				"grp-start-id", &tmp);
		if (result) {
			HAB_LOG_ERR("failed to read grp-start-id, result = %d\n", result);
			return result;
		} else {
			HAB_LOG_INFO("grp-start-id = %d\n", tmp);
			grp_start_id = tmp;
		}

		/* read the role(fe/be) of these pchans in this mmid group */
		result = of_property_read_string(mmid_grp_node, "role", &role);
		if (result) {
			HAB_LOG_ERR("failed to get role, result = %d\n", result);
			return result;
		} else {
			HAB_LOG_INFO("local role of this mmid group is %s\n", role);

			if (!strcmp(role, "be")) {
				be = 1;
			} else {
				be = 0;
			}
		}

		/* read the remote vmids for these pchans in this mmid group */
		vmids_num = of_property_count_elems_of_size(mmid_grp_node,
					"remote-vmids", sizeof(u32));

		result = of_property_read_u32_array(mmid_grp_node,
					"remote-vmids", vmids, vmids_num);
		if (result) {
			HAB_LOG_ERR("failed to read remote-vmids, result = %d\n", result);
			return result;
		} else {
			for (i = 0; i < vmids_num; i++) {
				HAB_LOG_INFO("vmids_num = %d, vmids[%d] = %d\n", vmids_num, i, vmids[i]);

				result = fill_vmid_mmid_tbl(settings->vmid_mmid_list, vmids[i], 1,
					grp_start_id/100, 1, be);
				if (result) {
					HAB_LOG_ERR("Failed to fill in vmid mmid tbl\n");
					return result;
				}
			}
		}
	}

	HAB_LOG_INFO("hab device tree node has been successfully pased, and here's the result.\n");
	dump_settings(settings);
	return 0;
}
#endif

/* 0: successful
 * negative: various failure core
 */
int hab_parse(struct local_vmid *settings)
{
	int ret;
#ifdef USE_DEVICETREE
	ret = hab_parse_dt(settings);
#else
	ret = hab_parse_no_dt(settings);
#endif
	return ret;
}

int fill_default_gvm_settings(struct local_vmid *settings, int vmid_local,
							  int mmid_start, int mmid_end) {

	settings->self = vmid_local;
	// default gvm always talks to host as vm0
	return fill_vmid_mmid_tbl(settings->vmid_mmid_list, 0, 1, mmid_start/100, (mmid_end-mmid_start)/100+1, HABCFG_BE_FALSE);
}

#ifdef USE_FILESYS
void main () {
	hab_parse_no_dt();
}
#endif
