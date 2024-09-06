#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <libcxlmi.h>

static int show_device_info(struct cxlmi_endpoint *ep)
{
    int rc;
    struct cxlmi_cmd_identify id;

    rc = cxlmi_cmd_identify(ep, NULL, &id);
    if (rc) {
        fprintf(stderr, "Failed to identify device: %s\n", cxlmi_cmd_retcode_tostr(rc));
        return rc;
    }

    printf("Serial number: 0x%lx\n", (uint64_t)id.serial_num);
    printf("Vendor ID: %04x\n", id.vendor_id);
    printf("Device ID: %04x\n", id.device_id);

    return 0;
}

static int test_timestamp(struct cxlmi_endpoint *ep)
{
    int rc;
    struct cxlmi_cmd_get_timestamp get_ts;
    struct cxlmi_cmd_set_timestamp set_ts = {
        .timestamp = 1609459200, /* Jan 1, 2021 */
    };

    rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
    if (rc)
        return rc;
    printf("Original timestamp: %lu\n", get_ts.timestamp);

    rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
    if (rc)
        return rc;

    rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
    if (rc)
        return rc;
    printf("New timestamp: %lu\n", get_ts.timestamp);

    return 0;
}

static const uint8_t cel_uuid[0x10] = { 0x0d, 0xa9, 0xc0, 0xb5,
					0xbf, 0x41,
					0x4b, 0x78,
					0x8f, 0x79,
					0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17 };

static const uint8_t ven_dbg[0x10] = { 0x5e, 0x18, 0x19, 0xd9,
				       0x11, 0xa9,
				       0x40, 0x0c,
				       0x81, 0x1f,
				       0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86 };

static const uint8_t c_s_dump[0x10] = { 0xb3, 0xfa, 0xb4, 0xcf,
					0x01, 0xb6,
					0x43, 0x32,
					0x94, 0x3e,
					0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67 };

static int parse_supported_logs(struct cxlmi_cmd_get_supported_logs *pl,
				size_t *cel_size)
{
	int i, j;

	*cel_size = 0;
	printf("Get Supported Logs Response %d\n",
	       pl->num_supported_log_entries);

	for (i = 0; i < pl->num_supported_log_entries; i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			printf("\tCommand Effects Log (CEL) available\n");
		}
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != ven_dbg[j])
				break;
		}
		if (j == 0x10)
			printf("\tVendor Debug Log available\n");
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != c_s_dump[j])
				break;
		}
		if (j == 0x10)
			printf("\tComponent State Dump Log available\n");
	}
	if (cel_size == 0) {
		return -1;
	}
	return 0;
}

static int show_cel(struct cxlmi_endpoint *ep, int cel_size)
{
	struct cxlmi_cmd_get_log_req in = {
		.offset = 0,
		.length = cel_size,
	};
	struct cxlmi_cmd_get_log_cel_rsp *ret;
	int i, rc;

	ret = calloc(1, sizeof(*ret) + cel_size);
	if (!ret)
		return -1;

	memcpy(in.uuid, cel_uuid, sizeof(in.uuid));
	rc = cxlmi_cmd_get_log_cel(ep, NULL, &in, ret);
	if (rc)
		goto done;

	for (i = 0; i < cel_size / sizeof(*ret); i++) {
		printf("\t[%04x] %s%s%s%s%s%s%s%s\n",
		       ret[i].opcode,
		       ret[i].command_effect & 0x1 ? "ColdReset " : "",
		       ret[i].command_effect & 0x2 ? "ImConf " : "",
		       ret[i].command_effect & 0x4 ? "ImData " : "",
		       ret[i].command_effect & 0x8 ? "ImPol " : "",
		       ret[i].command_effect & 0x10 ? "ImLog " : "",
		       ret[i].command_effect & 0x20 ? "ImSec" : "",
		       ret[i].command_effect & 0x40 ? "BgOp" : "",
		       ret[i].command_effect & 0x80 ? "SecSup" : "");
	}
done:
	free(ret);
	return rc;
}

static int get_device_logs(struct cxlmi_endpoint *ep)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs *gsl;

	gsl = calloc(1, sizeof(*gsl) +
		     CXLMI_MAX_SUPPORTED_LOGS * sizeof(*gsl->entries));
	if (!gsl)
		return -1;

	rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
	if (rc)
		return rc;

	rc = parse_supported_logs(gsl, &cel_size);
	if (rc)
		return rc;
	else {
		/* we know there is a CEL */
		rc = show_cel(ep, cel_size);
	}

	free(gsl);
	return rc;
}

void parse_and_show_log_capabilities(struct cxlmi_cmd_get_log_capabilities_rsp *ret)
{ 
    printf("Parameter flags: %u\n", ret->parameter_flags);
    if (ret->parameter_flags & 0x1) {
        printf("  Clear Log Supported\n");
    }
    if (ret->parameter_flags & 0x2) {
        printf("  Populate Log Supported\n");
    }
    if (ret->parameter_flags & 0x4) {
        printf("  Auto Populate Supported\n");
    }
    if (ret->parameter_flags & 0x8) {
        printf("  Persistent across Cold Reset\n");
    }
    if (ret->parameter_flags & 0xFFFFFFF0) {
        printf("  Reserved bits set: 0x%08x\n", ret->parameter_flags & 0xFFFFFFF0);
    }
}

static int get_device_logs_capabilities(struct cxlmi_endpoint *ep)
{
    int rc;
    struct cxlmi_cmd_get_log_capabilities_req get_log_capabilities = {0};
    struct cxlmi_cmd_get_log_capabilities_rsp *ret;

    ret = calloc(1, sizeof(*ret));
    if (!ret)
        return -1;

    memcpy(get_log_capabilities.uuid, cel_uuid, sizeof(get_log_capabilities.uuid));

    rc = cxlmi_cmd_get_log_capabilities(ep, NULL, &get_log_capabilities, ret);
    if (rc)
        return rc;

    parse_and_show_log_capabilities(ret);


    free(ret);
    return 0;
}

static int clear_and_populate_device_log(struct cxlmi_endpoint *ep)
{
    int rc;
    struct cxlmi_cmd_clear_log clear_log = {0};
    struct cxlmi_cmd_populate_log populate_log = {0};
    // Get the log size first
    struct cxlmi_cmd_get_supported_logs *gsl;
    size_t cel_size = 0;

    gsl = calloc(1, sizeof(*gsl) +
                 CXLMI_MAX_SUPPORTED_LOGS * sizeof(*gsl->entries));
    if (!gsl)
        return -1;

    rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
    if (rc) {
        free(gsl);
        return rc;
    }

    for (int i = 0; i < gsl->num_supported_log_entries; i++) {
        if (memcmp(gsl->entries[i].uuid, cel_uuid, sizeof(cel_uuid)) == 0) {
            cel_size = gsl->entries[i].log_size;
            break;
        }
    }
    free(gsl);

    if (cel_size == 0) {
        printf("CEL log not found\n");
        return -1;
    }

    // Get and show the log
    struct cxlmi_cmd_get_log_req get_log_req = {0};
    struct cxlmi_cmd_get_log_cel_rsp *log_data;

    memcpy(get_log_req.uuid, cel_uuid, sizeof(cel_uuid));
    get_log_req.offset = 0;
    get_log_req.length = cel_size;

    log_data = calloc(1, cel_size);
    if (!log_data)
        return -1;

    rc = cxlmi_cmd_get_log_cel(ep, NULL, &get_log_req, log_data);
    if (rc) {
        free(log_data);
        return rc;
    }

    printf("Current log contents:\n");
    for (size_t i = 0; i < cel_size / sizeof(*log_data); i++) {
        printf("  [%04x] %s%s%s%s%s%s%s%s\n",
               log_data[i].opcode,
               log_data[i].command_effect & 0x1 ? "ColdReset " : "",
               log_data[i].command_effect & 0x2 ? "ImConf " : "",
               log_data[i].command_effect & 0x4 ? "ImData " : "",
               log_data[i].command_effect & 0x8 ? "ImPol " : "",
               log_data[i].command_effect & 0x10 ? "ImLog " : "",
               log_data[i].command_effect & 0x20 ? "ImSec " : "",
               log_data[i].command_effect & 0x40 ? "BgOp " : "",
               log_data[i].command_effect & 0x80 ? "SecSup " : "");
    }

    free(log_data);

    memcpy(clear_log.uuid, cel_uuid, sizeof(clear_log.uuid));
    rc = cxlmi_cmd_clear_log(ep, NULL, &clear_log);
    if (rc) {
        printf("Failed to clear log: %s\n", cxlmi_cmd_retcode_tostr(rc));
        return rc;
    }

    printf("Log cleared successfully.\n");

    // Get and show the log again
    log_data = calloc(1, cel_size);
    if (!log_data)
        return -1;

    rc = cxlmi_cmd_get_log_cel(ep, NULL, &get_log_req, log_data);
    if (rc) {
        free(log_data);
        return rc;  
    }

    printf("Log contents after clearing:\n");
    for (size_t i = 0; i < cel_size / sizeof(*log_data); i++) {
        printf("  [%04x] %s%s%s%s%s%s%s%s\n",
               log_data[i].opcode,
               log_data[i].command_effect & 0x1 ? "ColdReset " : "",
               log_data[i].command_effect & 0x2 ? "ImConf " : "",   
               log_data[i].command_effect & 0x4 ? "ImData " : "",
               log_data[i].command_effect & 0x8 ? "ImPol " : "",
               log_data[i].command_effect & 0x10 ? "ImLog " : "",
               log_data[i].command_effect & 0x20 ? "ImSec " : "",
               log_data[i].command_effect & 0x40 ? "BgOp " : "",
               log_data[i].command_effect & 0x80 ? "SecSup " : "");
    }
    free(log_data); 

    memcpy(populate_log.uuid, cel_uuid, sizeof(populate_log.uuid));
    rc = cxlmi_cmd_populate_log(ep, NULL, &populate_log);
    if (rc) {
        printf("Failed to populate log: %s\n", cxlmi_cmd_retcode_tostr(rc));
        return rc;
    }

    printf("Log populated successfully.\n");

    // Get and show the log again
    log_data = calloc(1, cel_size);
    if (!log_data)
        return -1;

    rc = cxlmi_cmd_get_log_cel(ep, NULL, &get_log_req, log_data);
    if (rc) {
        free(log_data);
        return rc;
    }
    
    printf("Log contents after populating:\n");
    for (size_t i = 0; i < cel_size / sizeof(*log_data); i++) {
        printf("  [%04x] %s%s%s%s%s%s%s%s\n",
               log_data[i].opcode,
               log_data[i].command_effect & 0x1 ? "ColdReset " : "",
               log_data[i].command_effect & 0x2 ? "ImConf " : "",
               log_data[i].command_effect & 0x4 ? "ImData " : "",
               log_data[i].command_effect & 0x8 ? "ImPol " : "",
               log_data[i].command_effect & 0x10 ? "ImLog " : "",   
               log_data[i].command_effect & 0x20 ? "ImSec " : "",
               log_data[i].command_effect & 0x40 ? "BgOp " : "",
               log_data[i].command_effect & 0x80 ? "SecSup " : "");
    }
    free(log_data);

    return 0;
}

int get_supported_logs_sublist(struct cxlmi_endpoint *ep)
{
    int rc;
    struct cxlmi_cmd_get_supported_logs_sublist_req get_supported_logs_sublist = {0};
    struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret;

    ret = calloc(1, sizeof(*ret));
    if (!ret)
        return -1;  

    get_supported_logs_sublist.max_supported_log_entries = 1; // this is the minimum allowed by the spec
    get_supported_logs_sublist.start_log_entry_index = 0;

    rc = cxlmi_cmd_get_supported_logs_sublist(ep, NULL, &get_supported_logs_sublist, ret);
    if (rc)
        return rc;

    printf("Number of supported log entries: %d\n", ret->num_supported_log_entries);
    printf("Total number of supported log entries: %d\n", ret->total_num_supported_log_entries);
    printf("Start log entry index: %d\n", ret->start_log_entry_index);
    
    printf("Supported Logs Sublist:\n");
    for (int i = 0; i < ret->num_supported_log_entries; i++) {
        printf("  Log %d: %s\n", i + 1, ret->entries[i].uuid);
    }

    free(ret);
    return 0;
}

int main(int argc, char **argv)
{
    struct cxlmi_ctx *ctx;
    struct cxlmi_endpoint *ep;
    int rc = EXIT_FAILURE;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <device>\n", argv[0]);
        goto exit;
    }

    ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        goto exit;
    }

    ep = cxlmi_open(ctx, argv[1]);
    if (!ep) {
        fprintf(stderr, "Failed to open endpoint '%s'\n", argv[1]);
        goto exit_free_ctx;
    }

    printf("Testing endpoint '%s'\n", argv[1]);

    char choice;
    do {
        printf("\nChoose an operation:\n");
        printf("1. Show device info\n");
        printf("2. Test timestamp\n");
        printf("3. Get device logs\n");
        printf("4. Get device logs capabilities\n");
        printf("5. Clear and populate device log\n");
        printf("6. Get supported logs sublist\n");
        printf("q. Quit\n");
        printf("Enter your choice: ");
        int ret = scanf(" %c", &choice);
        if (ret != 1) {
            fprintf(stderr, "Failed to read choice\n");
            goto exit_close_ep;
        }

        switch (choice) {
            case '1':
                rc = show_device_info(ep);
                if (rc) {
                    fprintf(stderr, "Failed to show device info\n");
                    goto exit_close_ep;
                }
                break;
            case '2':
                rc = test_timestamp(ep);
                if (rc) {
                    fprintf(stderr, "Failed to test timestamp\n");
                    goto exit_close_ep;
                }
                break;
            case '3':
                rc = get_device_logs(ep);
                if (rc) {
                    fprintf(stderr, "Failed to get device logs\n");
                    goto exit_close_ep;
                }
                break;
            case '4':
                rc = get_device_logs_capabilities(ep);
                if (rc) {
                    fprintf(stderr, "Failed to get device logs capabilities\n");
                    goto exit_close_ep;
                }
                break;
            case '5':
                rc = clear_and_populate_device_log(ep);
                if (rc) {
                    fprintf(stderr, "Failed to clear and populate device log\n");
                    goto exit_close_ep;
                }
                break;
            case '6':
                rc = get_supported_logs_sublist(ep);
                if (rc) {
                    fprintf(stderr, "Failed to get supported logs sublist\n");
                    goto exit_close_ep;
                }
                break;
            case 'q':
            case 'Q':
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 'q' && choice != 'Q');

    rc = EXIT_SUCCESS;

exit_close_ep:
    cxlmi_close(ep);
exit_free_ctx:
    cxlmi_free_ctx(ctx);
exit:
    return rc;
}
