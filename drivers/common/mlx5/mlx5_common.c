/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_class.h>
#include <rte_malloc.h>

#include "mlx5_common.h"
#include "mlx5_common_os.h"
#include "mlx5_common_log.h"
#include "mlx5_malloc.h"
#include "mlx5_common_defs.h"
#include "mlx5_common_private.h"

uint8_t haswell_broadwell_cpu;

/* In case this is an x86_64 intel processor to check if
 * we should use relaxed ordering.
 */
#ifdef RTE_ARCH_X86_64
/**
 * This function returns processor identification and feature information
 * into the registers.
 *
 * @param eax, ebx, ecx, edx
 *		Pointers to the registers that will hold cpu information.
 * @param level
 *		The main category of information returned.
 */
static inline void mlx5_cpu_id(unsigned int level,
				unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	__asm__("cpuid\n\t"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "0" (level));
}
#endif

RTE_LOG_REGISTER(mlx5_common_logtype, pmd.common.mlx5, NOTICE)

/* Head of list of drivers. */
static TAILQ_HEAD(mlx5_drivers, mlx5_class_driver) drivers_list =
				TAILQ_HEAD_INITIALIZER(drivers_list);

/* Head of devices. */
static TAILQ_HEAD(mlx5_devices, mlx5_common_device) devices_list =
				TAILQ_HEAD_INITIALIZER(devices_list);
static pthread_mutex_t devices_list_lock;

static const struct {
	const char *name;
	unsigned int drv_class;
} mlx5_classes[] = {
	{ .name = "vdpa", .drv_class = MLX5_CLASS_VDPA },
	{ .name = "eth", .drv_class = MLX5_CLASS_ETH },
	/* Keep class "net" for backward compatibility. */
	{ .name = "net", .drv_class = MLX5_CLASS_ETH },
	{ .name = "regex", .drv_class = MLX5_CLASS_REGEX },
	{ .name = "compress", .drv_class = MLX5_CLASS_COMPRESS },
	{ .name = "crypto", .drv_class = MLX5_CLASS_CRYPTO },
};

static int
class_name_to_value(const char *class_name)
{
	unsigned int i;

	for (i = 0; i < RTE_DIM(mlx5_classes); i++) {
		if (strcmp(class_name, mlx5_classes[i].name) == 0)
			return mlx5_classes[i].drv_class;
	}
	return -EINVAL;
}

static struct mlx5_class_driver *
driver_get(uint32_t class)
{
	struct mlx5_class_driver *driver;

	TAILQ_FOREACH(driver, &drivers_list, next) {
		if ((uint32_t)driver->drv_class == class)
			return driver;
	}
	return NULL;
}

/**
 * Verify and store value for devargs.
 *
 * @param[in] key
 *   Key argument to verify.
 * @param[in] val
 *   Value associated with key.
 * @param opaque
 *   User data.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_common_args_check_handler(const char *key, const char *val, void *opaque)
{
	struct mlx5_common_dev_config *config = opaque;
	signed long tmp;

	errno = 0;
	tmp = strtol(val, NULL, 0);
	if (errno) {
		rte_errno = errno;
		DRV_LOG(WARNING, "%s: \"%s\" is an invalid integer.", key, val);
		return -rte_errno;
	}
	if (strcmp(key, "tx_db_nc") == 0) {
		if (tmp != MLX5_TXDB_CACHED &&
		    tmp != MLX5_TXDB_NCACHED &&
		    tmp != MLX5_TXDB_HEURISTIC) {
			DRV_LOG(ERR, "Invalid Tx doorbell mapping parameter.");
			rte_errno = EINVAL;
			return -rte_errno;
		}
		config->dbnc = tmp;
	} else if (strcmp(key, "mr_ext_memseg_en") == 0) {
		config->mr_ext_memseg_en = !!tmp;
	} else if (strcmp(key, "mr_mempool_reg_en") == 0) {
		config->mr_mempool_reg_en = !!tmp;
	} else if (strcmp(key, "sys_mem_en") == 0) {
		config->sys_mem_en = !!tmp;
	}
	return 0;
}

/**
 * Parse common device parameters.
 *
 * @param devargs
 *   Device arguments structure.
 * @param config
 *   Pointer to device configuration structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_common_config_get(struct rte_devargs *devargs,
		       struct mlx5_common_dev_config *config)
{
	struct rte_kvargs *kvlist;
	int ret = 0;

	/* Set defaults. */
	config->mr_ext_memseg_en = 1;
	config->mr_mempool_reg_en = 1;
	config->sys_mem_en = 0;
	config->dbnc = MLX5_ARG_UNSET;
	if (devargs == NULL)
		return 0;
	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	ret = rte_kvargs_process(kvlist, NULL, mlx5_common_args_check_handler,
				 config);
	if (ret)
		ret = -rte_errno;
	rte_kvargs_free(kvlist);
	DRV_LOG(DEBUG, "mr_ext_memseg_en is %u.", config->mr_ext_memseg_en);
	DRV_LOG(DEBUG, "mr_mempool_reg_en is %u.", config->mr_mempool_reg_en);
	DRV_LOG(DEBUG, "sys_mem_en is %u.", config->sys_mem_en);
	DRV_LOG(DEBUG, "Tx doorbell mapping parameter is %d.", config->dbnc);
	return ret;
}

static int
devargs_class_handler(__rte_unused const char *key,
		      const char *class_names, void *opaque)
{
	int *ret = opaque;
	int class_val;
	char *scratch;
	char *found;
	char *refstr = NULL;

	*ret = 0;
	scratch = strdup(class_names);
	if (scratch == NULL) {
		*ret = -ENOMEM;
		return *ret;
	}
	found = strtok_r(scratch, ":", &refstr);
	if (found == NULL)
		/* Empty string. */
		goto err;
	do {
		/* Extract each individual class name. Multiple
		 * classes can be supplied as class=net:regex:foo:bar.
		 */
		class_val = class_name_to_value(found);
		/* Check if its a valid class. */
		if (class_val < 0) {
			*ret = -EINVAL;
			goto err;
		}
		*ret |= class_val;
		found = strtok_r(NULL, ":", &refstr);
	} while (found != NULL);
err:
	free(scratch);
	if (*ret < 0)
		DRV_LOG(ERR, "Invalid mlx5 class options: %s.\n", class_names);
	return *ret;
}

static int
parse_class_options(const struct rte_devargs *devargs)
{
	struct rte_kvargs *kvlist;
	int ret = 0;

	if (devargs == NULL)
		return 0;
	if (devargs->cls != NULL && devargs->cls->name != NULL)
		/* Global syntax, only one class type. */
		return class_name_to_value(devargs->cls->name);
	/* Legacy devargs support multiple classes. */
	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		return 0;
	rte_kvargs_process(kvlist, RTE_DEVARGS_KEY_CLASS,
			   devargs_class_handler, &ret);
	rte_kvargs_free(kvlist);
	return ret;
}

static const unsigned int mlx5_class_invalid_combinations[] = {
	MLX5_CLASS_ETH | MLX5_CLASS_VDPA,
	/* New class combination should be added here. */
};

static int
is_valid_class_combination(uint32_t user_classes)
{
	unsigned int i;

	/* Verify if user specified unsupported combination. */
	for (i = 0; i < RTE_DIM(mlx5_class_invalid_combinations); i++) {
		if ((mlx5_class_invalid_combinations[i] & user_classes) ==
		    mlx5_class_invalid_combinations[i])
			return -EINVAL;
	}
	/* Not found any invalid class combination. */
	return 0;
}

static bool
device_class_enabled(const struct mlx5_common_device *device, uint32_t class)
{
	return (device->classes_loaded & class) > 0;
}

static bool
mlx5_bus_match(const struct mlx5_class_driver *drv,
	       const struct rte_device *dev)
{
	if (mlx5_dev_is_pci(dev))
		return mlx5_dev_pci_match(drv, dev);
	return true;
}

static struct mlx5_common_device *
to_mlx5_device(const struct rte_device *rte_dev)
{
	struct mlx5_common_device *cdev;

	TAILQ_FOREACH(cdev, &devices_list, next) {
		if (rte_dev == cdev->dev)
			return cdev;
	}
	return NULL;
}

int
mlx5_dev_to_pci_str(const struct rte_device *dev, char *addr, size_t size)
{
	struct rte_pci_addr pci_addr = { 0 };
	int ret;

	if (mlx5_dev_is_pci(dev)) {
		/* Input might be <BDF>, format PCI address to <DBDF>. */
		ret = rte_pci_addr_parse(dev->name, &pci_addr);
		if (ret != 0)
			return -ENODEV;
		rte_pci_device_name(&pci_addr, addr, size);
		return 0;
	}
#ifdef RTE_EXEC_ENV_LINUX
	return mlx5_auxiliary_get_pci_str(RTE_DEV_TO_AUXILIARY_CONST(dev),
			addr, size);
#else
	rte_errno = ENODEV;
	return -rte_errno;
#endif
}

/**
 * Uninitialize all HW global of device context.
 *
 * @param cdev
 *   Pointer to mlx5 device structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static void
mlx5_dev_hw_global_release(struct mlx5_common_device *cdev)
{
	if (cdev->pd != NULL) {
		claim_zero(mlx5_glue->dealloc_pd(cdev->pd));
		cdev->pd = NULL;
	}
	if (cdev->ctx != NULL) {
		claim_zero(mlx5_glue->close_device(cdev->ctx));
		cdev->ctx = NULL;
	}
}

/**
 * Initialize all HW global of device context.
 *
 * @param cdev
 *   Pointer to mlx5 device structure.
 * @param classes
 *   Chosen classes come from user device arguments.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_dev_hw_global_prepare(struct mlx5_common_device *cdev, uint32_t classes)
{
	int ret;

	/* Create context device */
	ret = mlx5_os_open_device(cdev, classes);
	if (ret < 0)
		return ret;
	/* Allocate Protection Domain object and extract its pdn. */
	ret = mlx5_os_pd_create(cdev);
	if (ret)
		goto error;
	/* All actions taken below are relevant only when DevX is supported */
	if (cdev->config.devx == 0)
		return 0;
	/* Query HCA attributes. */
	ret = mlx5_devx_cmd_query_hca_attr(cdev->ctx, &cdev->config.hca_attr);
	if (ret) {
		DRV_LOG(ERR, "Unable to read HCA capabilities.");
		rte_errno = ENOTSUP;
		goto error;
	}
	return 0;
error:
	mlx5_dev_hw_global_release(cdev);
	return ret;
}

static void
mlx5_common_dev_release(struct mlx5_common_device *cdev)
{
	pthread_mutex_lock(&devices_list_lock);
	TAILQ_REMOVE(&devices_list, cdev, next);
	pthread_mutex_unlock(&devices_list_lock);
	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		mlx5_dev_hw_global_release(cdev);
	rte_free(cdev);
}

static struct mlx5_common_device *
mlx5_common_dev_create(struct rte_device *eal_dev, uint32_t classes)
{
	struct mlx5_common_device *cdev;
	int ret;

	cdev = rte_zmalloc("mlx5_common_device", sizeof(*cdev), 0);
	if (!cdev) {
		DRV_LOG(ERR, "Device allocation failure.");
		rte_errno = ENOMEM;
		return NULL;
	}
	cdev->dev = eal_dev;
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		goto exit;
	/* Parse device parameters. */
	ret = mlx5_common_config_get(eal_dev->devargs, &cdev->config);
	if (ret < 0) {
		DRV_LOG(ERR, "Failed to process device arguments: %s",
			strerror(rte_errno));
		rte_free(cdev);
		return NULL;
	}
	mlx5_malloc_mem_select(cdev->config.sys_mem_en);
	/* Initialize all HW global of device context. */
	ret = mlx5_dev_hw_global_prepare(cdev, classes);
	if (ret) {
		DRV_LOG(ERR, "Failed to initialize device context.");
		rte_free(cdev);
		return NULL;
	}
exit:
	pthread_mutex_lock(&devices_list_lock);
	TAILQ_INSERT_HEAD(&devices_list, cdev, next);
	pthread_mutex_unlock(&devices_list_lock);
	return cdev;
}

static int
drivers_remove(struct mlx5_common_device *cdev, uint32_t enabled_classes)
{
	struct mlx5_class_driver *driver;
	int local_ret = -ENODEV;
	unsigned int i = 0;
	int ret = 0;

	enabled_classes &= cdev->classes_loaded;
	while (enabled_classes) {
		driver = driver_get(RTE_BIT64(i));
		if (driver != NULL) {
			local_ret = driver->remove(cdev);
			if (local_ret == 0)
				cdev->classes_loaded &= ~RTE_BIT64(i);
			else if (ret == 0)
				ret = local_ret;
		}
		enabled_classes &= ~RTE_BIT64(i);
		i++;
	}
	if (local_ret != 0 && ret == 0)
		ret = local_ret;
	return ret;
}

static int
drivers_probe(struct mlx5_common_device *cdev, uint32_t user_classes)
{
	struct mlx5_class_driver *driver;
	uint32_t enabled_classes = 0;
	bool already_loaded;
	int ret;

	TAILQ_FOREACH(driver, &drivers_list, next) {
		if ((driver->drv_class & user_classes) == 0)
			continue;
		if (!mlx5_bus_match(driver, cdev->dev))
			continue;
		already_loaded = cdev->classes_loaded & driver->drv_class;
		if (already_loaded && driver->probe_again == 0) {
			DRV_LOG(ERR, "Device %s is already probed",
				cdev->dev->name);
			ret = -EEXIST;
			goto probe_err;
		}
		ret = driver->probe(cdev);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to load driver %s",
				driver->name);
			goto probe_err;
		}
		enabled_classes |= driver->drv_class;
	}
	cdev->classes_loaded |= enabled_classes;
	return 0;
probe_err:
	/* Only unload drivers which are enabled which were enabled
	 * in this probe instance.
	 */
	drivers_remove(cdev, enabled_classes);
	return ret;
}

int
mlx5_common_dev_probe(struct rte_device *eal_dev)
{
	struct mlx5_common_device *cdev;
	uint32_t classes = 0;
	bool new_device = false;
	int ret;

	DRV_LOG(INFO, "probe device \"%s\".", eal_dev->name);
	ret = parse_class_options(eal_dev->devargs);
	if (ret < 0) {
		DRV_LOG(ERR, "Unsupported mlx5 class type: %s",
			eal_dev->devargs->args);
		return ret;
	}
	classes = ret;
	if (classes == 0)
		/* Default to net class. */
		classes = MLX5_CLASS_ETH;
	cdev = to_mlx5_device(eal_dev);
	if (!cdev) {
		cdev = mlx5_common_dev_create(eal_dev, classes);
		if (!cdev)
			return -ENOMEM;
		new_device = true;
	}
	/*
	 * Validate combination here.
	 * For new device, the classes_loaded field is 0 and it check only
	 * the classes given as user device arguments.
	 */
	ret = is_valid_class_combination(classes | cdev->classes_loaded);
	if (ret != 0) {
		DRV_LOG(ERR, "Unsupported mlx5 classes combination.");
		goto class_err;
	}
	ret = drivers_probe(cdev, classes);
	if (ret)
		goto class_err;
	return 0;
class_err:
	if (new_device)
		mlx5_common_dev_release(cdev);
	return ret;
}

int
mlx5_common_dev_remove(struct rte_device *eal_dev)
{
	struct mlx5_common_device *cdev;
	int ret;

	cdev = to_mlx5_device(eal_dev);
	if (!cdev)
		return -ENODEV;
	/* Matching device found, cleanup and unload drivers. */
	ret = drivers_remove(cdev, cdev->classes_loaded);
	if (ret == 0)
		mlx5_common_dev_release(cdev);
	return ret;
}

int
mlx5_common_dev_dma_map(struct rte_device *dev, void *addr, uint64_t iova,
			size_t len)
{
	struct mlx5_class_driver *driver = NULL;
	struct mlx5_class_driver *temp;
	struct mlx5_common_device *mdev;
	int ret = -EINVAL;

	mdev = to_mlx5_device(dev);
	if (!mdev)
		return -ENODEV;
	TAILQ_FOREACH(driver, &drivers_list, next) {
		if (!device_class_enabled(mdev, driver->drv_class) ||
		    driver->dma_map == NULL)
			continue;
		ret = driver->dma_map(dev, addr, iova, len);
		if (ret)
			goto map_err;
	}
	return ret;
map_err:
	TAILQ_FOREACH(temp, &drivers_list, next) {
		if (temp == driver)
			break;
		if (device_class_enabled(mdev, temp->drv_class) &&
		    temp->dma_map && temp->dma_unmap)
			temp->dma_unmap(dev, addr, iova, len);
	}
	return ret;
}

int
mlx5_common_dev_dma_unmap(struct rte_device *dev, void *addr, uint64_t iova,
			  size_t len)
{
	struct mlx5_class_driver *driver;
	struct mlx5_common_device *mdev;
	int local_ret = -EINVAL;
	int ret = 0;

	mdev = to_mlx5_device(dev);
	if (!mdev)
		return -ENODEV;
	/* There is no unmap error recovery in current implementation. */
	TAILQ_FOREACH_REVERSE(driver, &drivers_list, mlx5_drivers, next) {
		if (!device_class_enabled(mdev, driver->drv_class) ||
		    driver->dma_unmap == NULL)
			continue;
		local_ret = driver->dma_unmap(dev, addr, iova, len);
		if (local_ret && (ret == 0))
			ret = local_ret;
	}
	if (local_ret)
		ret = local_ret;
	return ret;
}

void
mlx5_class_driver_register(struct mlx5_class_driver *driver)
{
	mlx5_common_driver_on_register_pci(driver);
	TAILQ_INSERT_TAIL(&drivers_list, driver, next);
}

static void mlx5_common_driver_init(void)
{
	mlx5_common_pci_init();
#ifdef RTE_EXEC_ENV_LINUX
	mlx5_common_auxiliary_init();
#endif
}

static bool mlx5_common_initialized;

/**
 * One time innitialization routine for run-time dependency on glue library
 * for multiple PMDs. Each mlx5 PMD that depends on mlx5_common module,
 * must invoke in its constructor.
 */
void
mlx5_common_init(void)
{
	if (mlx5_common_initialized)
		return;

	pthread_mutex_init(&devices_list_lock, NULL);
	mlx5_glue_constructor();
	mlx5_common_driver_init();
	mlx5_common_initialized = true;
}

/**
 * This function is responsible of initializing the variable
 *  haswell_broadwell_cpu by checking if the cpu is intel
 *  and reading the data returned from mlx5_cpu_id().
 *  since haswell and broadwell cpus don't have improved performance
 *  when using relaxed ordering we want to check the cpu type before
 *  before deciding whether to enable RO or not.
 *  if the cpu is haswell or broadwell the variable will be set to 1
 *  otherwise it will be 0.
 */
RTE_INIT_PRIO(mlx5_is_haswell_broadwell_cpu, LOG)
{
#ifdef RTE_ARCH_X86_64
	unsigned int broadwell_models[4] = {0x3d, 0x47, 0x4F, 0x56};
	unsigned int haswell_models[4] = {0x3c, 0x3f, 0x45, 0x46};
	unsigned int i, model, family, brand_id, vendor;
	unsigned int signature_intel_ebx = 0x756e6547;
	unsigned int extended_model;
	unsigned int eax = 0;
	unsigned int ebx = 0;
	unsigned int ecx = 0;
	unsigned int edx = 0;
	int max_level;

	mlx5_cpu_id(0, &eax, &ebx, &ecx, &edx);
	vendor = ebx;
	max_level = eax;
	if (max_level < 1) {
		haswell_broadwell_cpu = 0;
		return;
	}
	mlx5_cpu_id(1, &eax, &ebx, &ecx, &edx);
	model = (eax >> 4) & 0x0f;
	family = (eax >> 8) & 0x0f;
	brand_id = ebx & 0xff;
	extended_model = (eax >> 12) & 0xf0;
	/* Check if the processor is Haswell or Broadwell */
	if (vendor == signature_intel_ebx) {
		if (family == 0x06)
			model += extended_model;
		if (brand_id == 0 && family == 0x6) {
			for (i = 0; i < RTE_DIM(broadwell_models); i++)
				if (model == broadwell_models[i]) {
					haswell_broadwell_cpu = 1;
					return;
				}
			for (i = 0; i < RTE_DIM(haswell_models); i++)
				if (model == haswell_models[i]) {
					haswell_broadwell_cpu = 1;
					return;
				}
		}
	}
#endif
	haswell_broadwell_cpu = 0;
}

/**
 * Allocate page of door-bells and register it using DevX API.
 *
 * @param [in] ctx
 *   Pointer to the device context.
 *
 * @return
 *   Pointer to new page on success, NULL otherwise.
 */
static struct mlx5_devx_dbr_page *
mlx5_alloc_dbr_page(void *ctx)
{
	struct mlx5_devx_dbr_page *page;

	/* Allocate space for door-bell page and management data. */
	page = mlx5_malloc(MLX5_MEM_RTE | MLX5_MEM_ZERO,
			   sizeof(struct mlx5_devx_dbr_page),
			   RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
	if (!page) {
		DRV_LOG(ERR, "cannot allocate dbr page");
		rte_errno = ENOMEM;
		return NULL;
	}
	/* Register allocated memory. */
	page->umem = mlx5_glue->devx_umem_reg(ctx, page->dbrs,
					      MLX5_DBR_PAGE_SIZE, 0);
	if (!page->umem) {
		DRV_LOG(ERR, "cannot umem reg dbr page");
		rte_errno = errno;
		mlx5_free(page);
		return NULL;
	}
	return page;
}

/**
 * Find the next available door-bell, allocate new page if needed.
 *
 * @param [in] ctx
 *   Pointer to device context.
 * @param [in] head
 *   Pointer to the head of dbr pages list.
 * @param [out] dbr_page
 *   Door-bell page containing the page data.
 *
 * @return
 *   Door-bell address offset on success, a negative error value otherwise.
 */
int64_t
mlx5_get_dbr(void *ctx,  struct mlx5_dbr_page_list *head,
	     struct mlx5_devx_dbr_page **dbr_page)
{
	struct mlx5_devx_dbr_page *page = NULL;
	uint32_t i, j;

	LIST_FOREACH(page, head, next)
		if (page->dbr_count < MLX5_DBR_PER_PAGE)
			break;
	if (!page) { /* No page with free door-bell exists. */
		page = mlx5_alloc_dbr_page(ctx);
		if (!page) /* Failed to allocate new page. */
			return (-1);
		LIST_INSERT_HEAD(head, page, next);
	}
	/* Loop to find bitmap part with clear bit. */
	for (i = 0;
	     i < MLX5_DBR_BITMAP_SIZE && page->dbr_bitmap[i] == UINT64_MAX;
	     i++)
		; /* Empty. */
	/* Find the first clear bit. */
	MLX5_ASSERT(i < MLX5_DBR_BITMAP_SIZE);
	j = rte_bsf64(~page->dbr_bitmap[i]);
	page->dbr_bitmap[i] |= (UINT64_C(1) << j);
	page->dbr_count++;
	*dbr_page = page;
	return (i * CHAR_BIT * sizeof(uint64_t) + j) * MLX5_DBR_SIZE;
}

/**
 * Release a door-bell record.
 *
 * @param [in] head
 *   Pointer to the head of dbr pages list.
 * @param [in] umem_id
 *   UMEM ID of page containing the door-bell record to release.
 * @param [in] offset
 *   Offset of door-bell record in page.
 *
 * @return
 *   0 on success, a negative error value otherwise.
 */
int32_t
mlx5_release_dbr(struct mlx5_dbr_page_list *head, uint32_t umem_id,
		 uint64_t offset)
{
	struct mlx5_devx_dbr_page *page = NULL;
	int ret = 0;

	LIST_FOREACH(page, head, next)
		/* Find the page this address belongs to. */
		if (mlx5_os_get_umem_id(page->umem) == umem_id)
			break;
	if (!page)
		return -EINVAL;
	page->dbr_count--;
	if (!page->dbr_count) {
		/* Page not used, free it and remove from list. */
		LIST_REMOVE(page, next);
		if (page->umem)
			ret = -mlx5_glue->devx_umem_dereg(page->umem);
		mlx5_free(page);
	} else {
		/* Mark in bitmap that this door-bell is not in use. */
		offset /= MLX5_DBR_SIZE;
		int i = offset / 64;
		int j = offset % 64;

		page->dbr_bitmap[i] &= ~(UINT64_C(1) << j);
	}
	return ret;
}

/**
 * Allocate the User Access Region with DevX on specified device.
 *
 * @param [in] ctx
 *   Infiniband device context to perform allocation on.
 * @param [in] mapping
 *   MLX5DV_UAR_ALLOC_TYPE_BF - allocate as cached memory with write-combining
 *				attributes (if supported by the host), the
 *				writes to the UAR registers must be followed
 *				by write memory barrier.
 *   MLX5DV_UAR_ALLOC_TYPE_NC - allocate as non-cached memory, all writes are
 *				promoted to the registers immediately, no
 *				memory barriers needed.
 *   mapping < 0 - the first attempt is performed with MLX5DV_UAR_ALLOC_TYPE_NC,
 *		   if this fails the next attempt with MLX5DV_UAR_ALLOC_TYPE_BF
 *		   is performed. The drivers specifying negative values should
 *		   always provide the write memory barrier operation after UAR
 *		   register writings.
 * If there is no definitions for the MLX5DV_UAR_ALLOC_TYPE_xx (older rdma
 * library headers), the caller can specify 0.
 *
 * @return
 *   UAR object pointer on success, NULL otherwise and rte_errno is set.
 */
void *
mlx5_devx_alloc_uar(void *ctx, int mapping)
{
	void *uar;
	uint32_t retry, uar_mapping;
	void *base_addr;

	for (retry = 0; retry < MLX5_ALLOC_UAR_RETRY; ++retry) {
#ifdef MLX5DV_UAR_ALLOC_TYPE_NC
		/* Control the mapping type according to the settings. */
		uar_mapping = (mapping < 0) ?
			      MLX5DV_UAR_ALLOC_TYPE_NC : mapping;
#else
		/*
		 * It seems we have no way to control the memory mapping type
		 * for the UAR, the default "Write-Combining" type is supposed.
		 */
		uar_mapping = 0;
		RTE_SET_USED(mapping);
#endif
		uar = mlx5_glue->devx_alloc_uar(ctx, uar_mapping);
#ifdef MLX5DV_UAR_ALLOC_TYPE_NC
		if (!uar && mapping < 0) {
			/*
			 * If Verbs/kernel does not support "Non-Cached"
			 * try the "Write-Combining".
			 */
			DRV_LOG(DEBUG, "Failed to allocate DevX UAR (NC)");
			uar_mapping = MLX5DV_UAR_ALLOC_TYPE_BF;
			uar = mlx5_glue->devx_alloc_uar(ctx, uar_mapping);
		}
#endif
		if (!uar) {
			DRV_LOG(ERR, "Failed to allocate DevX UAR (BF/NC)");
			rte_errno = ENOMEM;
			goto exit;
		}
		base_addr = mlx5_os_get_devx_uar_base_addr(uar);
		if (base_addr)
			break;
		/*
		 * The UARs are allocated by rdma_core within the
		 * IB device context, on context closure all UARs
		 * will be freed, should be no memory/object leakage.
		 */
		DRV_LOG(DEBUG, "Retrying to allocate DevX UAR");
		uar = NULL;
	}
	/* Check whether we finally succeeded with valid UAR allocation. */
	if (!uar) {
		DRV_LOG(ERR, "Failed to allocate DevX UAR (NULL base)");
		rte_errno = ENOMEM;
	}
	/*
	 * Return void * instead of struct mlx5dv_devx_uar *
	 * is for compatibility with older rdma-core library headers.
	 */
exit:
	return uar;
}

RTE_PMD_EXPORT_NAME(mlx5_common_driver, __COUNTER__);
