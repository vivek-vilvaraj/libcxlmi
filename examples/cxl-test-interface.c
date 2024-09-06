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
    if (rc)
        return rc;

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
