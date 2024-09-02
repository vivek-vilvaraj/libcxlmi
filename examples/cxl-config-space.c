/*code to test the cxl config space */

#include <libcxlmi.h>
#include <stdio.h>
#include <stdlib.h>

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
    ep = cxlmi_config_space_access(ctx, argv[1]);
    if (ep == NULL)
    {
        fprintf(stderr, "cannot open '%s' endpoint\n", argv[1]);
        goto exit_free_ctx;
    }

    printf("ep '%s'\n", argv[1]);

    cxlmi_close(ep);
    cxlmi_free_ctx(ctx);
    return rc;
exit_free_ctx:
    cxlmi_free_ctx(ctx);
exit:
    return rc;
}