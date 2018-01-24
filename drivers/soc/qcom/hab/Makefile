msm_hab-objs = \
	khab.o \
	hab.o \
	hab_msg.o \
	hab_vchan.o \
	hab_pchan.o \
	hab_open.o \
	hab_mimex.o \
	hab_mem_linux.o \
	hab_pipe.o \
	hab_parser.o


ifdef CONFIG_GHS_VMM
msm_hab_hyp-objs = \
	ghs_comm.o \
	hab_ghs.o
endif

ifdef CONFIG_MSM_QUIN_VIRT
msm_hab_hyp-objs = \
	qvm_comm.o \
	hab_qvm.o
endif

obj-$(CONFIG_MSM_HAB) += msm_hab.o msm_hab_hyp.o
