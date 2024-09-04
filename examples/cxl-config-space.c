/*code to test the cxl config space */

#include <libcxlmi.h>
#include <stdio.h>
#include <stdlib.h>

static int show_memdev_info(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_memdev_identify id;

	rc = cxlmi_cmd_memdev_identify(ep, NULL, &id);
	if (rc)
		return rc;

	printf("FW revision: %s\n", id.fw_revision);
	printf("total capacity: %ld Mb\n", 256 * id.total_capacity);
	printf("\tvolatile: %ld Mb\n", 256 * id.volatile_capacity);
	printf("\tpersistent: %ld Mb\n", 256 * id.persistent_capacity);
	printf("lsa size: %d bytes\n", id.lsa_size);
	printf("poison injection limit: %d\n", id.inject_poison_limit);
	printf("poison caps 0x%x\n", id.poison_caps);
	printf("DC event log size %d\n", id.dc_event_log_size);

       return 0;
}

static int show_some_info_from_all_devices(struct cxlmi_ctx *ctx)
{
	int rc = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep) {
		struct cxlmi_cmd_identify id;

		rc = cxlmi_cmd_identify(ep, NULL, &id);
		if (rc)
			break;

		printf("serial number: 0x%lx\n", (uint64_t)id.serial_num);

		switch (id.component_type) {
		case 0x00:
			printf("device type: CXL Switch\n");
			printf("VID:%04x DID:%04x\n", id.vendor_id, id.device_id);
			break;
		case 0x03:
			printf("device type: CXL Type3 Device\n");
			printf("VID:%04x DID:%04x SubsysVID:%04x SubsysID:%04x\n",
			       id.vendor_id, id.device_id,
			       id.subsys_vendor_id, id.subsys_id);

			show_memdev_info(ep);
			break;
		case 0x04:
			printf("GFD not supported\n");
			/* fallthrough */
		default:
			break;
		}
	}

	return rc;
}

int main(int argc, char **argv)
{
    struct cxlmi_ctx *ctx;
    struct cxlmi_endpoint *ep;
    int rc = EXIT_FAILURE;

    if (argc != 2)
    {
        fprintf(stderr, "Must provide a pcie device address (0d:00.0)\n");
        fprintf(stderr, "Usage: cxl-config-space <device>\n");
        goto exit;
    }

    ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
    if (!ctx)
    {
        fprintf(stderr, "cannot create new context object\n");
        goto exit;
    }
    ep = (struct cxlmi_endpoint *)cxlmi_config_space_access(ctx, argv[1]);
    if (ep == NULL)
    {
        fprintf(stderr, "cannot open '%s' endpoint\n", argv[1]);
        goto exit_free_ctx;
    }

    printf("ep '%s'\n", argv[1]);

    /* yes, only 1 endpoint, but might add more */
	rc = show_some_info_from_all_devices(ctx);

    cxlmi_close(ep);
    cxlmi_free_ctx(ctx);
    return rc;
exit_free_ctx:
    cxlmi_free_ctx(ctx);
exit:
    return rc;
}