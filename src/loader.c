#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
// #include <signal.h>
#include <inttypes.h>
// #include <time.h>
#include <getopt.h>
#include <sys/resource.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"

// #include "include/xdpfw.h"
// #include "include/config.h"

// Command line variables.
// static char *configFile;
static int help = 0;
static int load = 0;
static int offload = 0;
static int smap = 0;
static char *filename;
static char *drivename;

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_rule_map";
// const char *map_name2    =  "xdp_gateway_map";

const struct option opts[] =
{
    {"filename", required_argument, NULL, 'f'},
    {"drivename", required_argument, NULL, 'd'},
    {"offload", no_argument, &offload, 'o'},
    {"load", no_argument, &load, 'l'},
    {"help", no_argument, &help, 'h'},
    // {"map", no_argument, &smap, 'm'},
    {NULL, 0, NULL, 0}
};

// Other variables.
static uint8_t cont = 1;
static int blacklist_map_fd = -1;
// static int stats_map_fd = -1;

// void signalHndl(int tmp)
// {
//     cont = 0;
// }

void parse_command_line(int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "f:d:loh", opts, NULL)) != -1)
    {
        switch (c)
        {


            case 'f':
                filename = optarg;

                break;

            case 'd':
                drivename = optarg;

                break;
            
            case 'o':
                offload = 1;

                break;

            case 'l':
                load = 1;
               

                break;

            case 'h':
                help = 1;

                break;
            
            // case 'm':
            //     smap = 1;

            //     break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}

// int open_bpf_map(const char *subdir)
// {
// 	int fd;
//     char map_filename[PATH_MAX];
// 	char pin_dir[PATH_MAX];
// 	int err, len;

// 	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
// 		       pin_basedir, subdir, map_name);
// 	if (len < 0) {
// 		fprintf(stderr, "ERR: creating map_name\n");
// 		return EXIT_FAILURE;
// 	}

// 	fd = bpf_obj_get(map_filename);
// 	if (fd < 0) {
// 		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n", map_filename, errno, strerror(errno));
// 		return EXIT_FAILURE;
// 	}
// 	return fd;
// }

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir)
{
	char map_filename[PATH_MAX];
    char map_filename2[PATH_MAX];
	char pin_dir[PATH_MAX];
	int err, len;

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAILURE;
	}

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, subdir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAILURE;
	}

    // len = snprintf(map_filename2, PATH_MAX, "%s/%s/%s",
	// 	       pin_basedir, subdir, map_name2);
	// if (len < 0) {
	// 	fprintf(stderr, "ERR: creating map_name\n");
	// 	return EXIT_FAILURE;
	// }

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		printf(" - Unpinning (remove) prev maps in %s/\n", pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAILURE;
		}
	}

    // if (access(map_filename2, F_OK ) != -1 ) {
	// 	printf(" - Unpinning (remove) prev maps in %s/\n", pin_dir);

	// 	/* Basically calls unlink(3) on map_filename */
	// 	err = bpf_object__unpin_maps(bpf_obj, pin_dir);
	// 	if (err) {
	// 		fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
	// 		return EXIT_FAILURE;
	// 	}
	// }
	
	printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAILURE;

	return 0;
}


int load_bpf_object_file__simple(const char *filename)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;
    printf("i am here 4\n");
    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);
    printf("i am here 5\n");
    if (err)
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Num => %d\n", filename, strerror(-err), err);

        return -1;
    }

    err = pin_maps_in_bpf_object(obj, drivename);
    if (err) {
		 fprintf(stderr, "ERR: pinning maps\n");
		return -1;
	}

    // stats_map_fd = find_map_fd(obj, "stats_map");

    return first_prog_fd;
}

static int xdp_detach(int ifindex, uint32_t xdp_flags)
{
    int err;

    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    if (err < 0)
    {
        fprintf(stderr, "Error detaching XDP program. Error => %s. Error Num => %.d\n", strerror(-err), err);

        return -1;
    }

    return EXIT_SUCCESS;
}

static int xdp_attach(int ifindex, uint32_t *xdp_flags, int prog_fd)
{
    int err;

    printf("i am here 8\n");
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, *xdp_flags);
    printf("i am here 9\n");
    if (err < 0)
    {
        fprintf(stderr, "Error attaching XDP program. Error => %s. Error Num => %d. IfIndex => %d.\n", strerror(-err), -err, ifindex);

        return -1;
    }

    printf("i am here 11\n");

    return EXIT_SUCCESS;
}



int main(int argc, char *argv[])
{
    // Parse the command line.
    printf("i am here 1\n");
    parse_command_line(argc, argv);
    printf("f %s\n", filename);
    printf("d %s\n", drivename);

    printf("i am here a\n");


    // Check for help menu.
    if (help)
    {
        fprintf(stdout, "Usage:\n" \
            "--config -c => Config file location (default is /etc/xdpfw/xdpfw.conf).\n" \
            "--offload -o => Tries to load the XDP program in hardware/offload mode." \
            "--list -l => Print config details including filters (this will exit program after done).\n" \
            "--help -h => Print help menu.\n");

        return EXIT_SUCCESS;
    }

    // Raise RLimit.
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "Error setting rlimit.\n");

        return EXIT_FAILURE;
    }

    // Get device.
    int dev;

    if ((dev = if_nametoindex(drivename)) < 0)
    {
        fprintf(stderr, "Error finding device %s.\n", drivename);

        return EXIT_FAILURE;
    }

    printf("dev %d\n", dev);

    // XDP variables.
    int prog_fd;
    uint32_t xdpflags;
    
    printf("i am here 2\n");
    xdpflags = XDP_FLAGS_SKB_MODE;
    // xdpflags = XDP_FLAGS_DRV_MODE;

    if (load) {
        printf("i am here 3\n");
        // Get XDP's ID.
        prog_fd = load_bpf_object_file__simple(filename);
        printf("prog %d\n", prog_fd);

        if (prog_fd <= 0)
        {
            fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", filename);

            return EXIT_FAILURE;
        }

        
        // Attach XDP program to device.
        if (xdp_attach(dev, &xdpflags, prog_fd) != 0)
        {
            return EXIT_FAILURE;
        }


    }
    // Check for valid maps.
    // if (filter_map_fd < 0)
    // {
    //     fprintf(stderr, "Error finding 'filters_map' BPF map.\n");

    //     return EXIT_FAILURE;
    // }

    // if (stats_map_fd < 0)
    // {
    //     fprintf(stderr, "Error finding 'stats_map' BPF map.\n");

    //     return EXIT_FAILURE;
    // }

    // if (smap) {
    //     int fd;
    //     int res;
    //     __u64 value = 2;
	//     __u32 key = 1;
    //     fd = open_bpf_map(drivename);
    //     printf("map %d", fd);
    //     res = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);

    //     if (res != 0) { /* 0 == success */
    //         fprintf(stderr,
    //             "%s()  key:0x%X errno(%d/%s)",
    //             __func__, key, errno, strerror(errno));

    //         if (errno == 17) {
    //             fprintf(stderr, ": Already in blacklist\n");
    //             return EXIT_SUCCESS;
    //         }
    //         fprintf(stderr, "\n");
    //         return EXIT_FAILURE;
    //     }
    // }

    

    if (offload) {
        printf("i am here 13\n");
        // Detach XDP program.
        if (xdp_detach(dev, xdpflags) != 0)
        {
            printf("i am here 12\n");
            fprintf(stderr, "Error removing XDP program from device %s\n", drivename);

            return EXIT_FAILURE;
        }

    }


    // Exit program successfully.
    return EXIT_SUCCESS;
}