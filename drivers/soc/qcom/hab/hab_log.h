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
#ifndef __HAB_LOG_H
#define __HAB_LOG_H

#if defined(__linux__)
#ifdef _DEBUG
#define HAB_LOG_INFO(fmt, args...) \
	pr_info("|%s %d| " fmt, __func__, __LINE__, ##args)
#else
#define HAB_LOG_INFO(fmt, args...)
#endif

#define HAB_LOG_WARN(fmt, args...) \
	pr_warn("|%s %d| " fmt, __func__, __LINE__, ##args)

#define HAB_LOG_ERR(fmt, args...) \
	pr_err("|%s %d| " fmt, __func__, __LINE__, ##args)

#define HAB_LOG_ERR_ONCE(fmt, args...) \
	pr_err_once("|%s %d| " fmt, __func__, __LINE__, ##args)

#elif defined(__QNXNTO__)

#include <stdio.h>
#include "logger_utils.h"
#ifdef _DEBUG
#define HAB_LOG_INFO(_fmt_, ...) \
	do { \
		printf("HAB_INFO  %s %d " _fmt_  "\n", \
		__func__, __LINE__, ##__VA_ARGS__); \
		logger_log(QCLOG_AMSS_MM, 0, _SLOG_INFO, "%s: " \
		_fmt_, __func__, ##__VA_ARGS__); \
	} while (0)
#else
#define HAB_LOG_INFO(fmt, args...)
#endif
#define HAB_LOG_WARN(_fmt_, ...) \
	do { \
		printf("HAB_WARN  %s %d " _fmt_  "\n", \
		__func__, __LINE__, ##__VA_ARGS__); \
		logger_log(QCLOG_AMSS_MM, 0, _SLOG_WARNING, "%s: " \
		_fmt_, __func__, ##__VA_ARGS__); \
	} while (0)
#define HAB_LOG_ERR(_fmt_, ...) \
	do { \
		printf("HAB_ERROR %s %d " _fmt_ "\n", \
		__func__, __LINE__, ##__VA_ARGS__); \
		logger_log(QCLOG_AMSS_MM, 0, _SLOG_ERROR, "%s: " \
		_fmt_, __func__, ##__VA_ARGS__); \
	} while (0)

#define HAB_LOG_ERR_ONCE(_fmt_, ...) \
	do { \
		static bool hab_log_err_once;			\
		if (!hab_log_err_once) {			\
			hab_log_err_once = true;		\
			printf("HAB_ERROR %s %d " _fmt_ "\n",	\
			__func__, __LINE__, ##__VA_ARGS__);	\
		}						\
	} while (0)

#define pr_err(fmt, args...) \
	do { \
		printf(fmt, ##args); \
		logger_log(QCLOG_AMSS_MM, 0, _SLOG_ERROR, fmt, ##args); \
	} while (0)

#define pr_info(fmt, args...) \
	do { \
		printf(fmt, ##args); \
		logger_log(QCLOG_AMSS_MM, 0, _SLOG_INFO, fmt, ##args); \
	} while (0)

#endif

#endif /* __HAB_LOG_H */
