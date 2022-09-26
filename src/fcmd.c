#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
// #include <signal.h>
#include <inttypes.h>
// #include <time.h>
#include <getopt.h>
#include <linux/swab.h>
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
// static int load = 0;
// static int offload = 0;
static int smap = 0;
static int slistfw = 0;
static int slistdist = 0;
static int sgateway = 0;
static int sdistsource = 0;
// static int sdistdest = 0;
// static char *filename;
static char *drivename;
static char *sourceipstring;
static char *destinationipstring;
static char *destinationmacstring;
static char *mapvaluestring;
static char *tmpfileloc;
static char *action;
// static char *destinationportstring;

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_rule_map";
const char *map_name2    =  "xdp_gateway_map";
const char *map_name_distsource    =  "xdp_distsource_map";
const char *map_name_distdest    =  "xdp_distdest_map";

const struct option opts[] =
{
    {"drivename", required_argument, NULL, 'd'},
    {"sourceip", required_argument, NULL, 's'},
    {"destinationip", required_argument, NULL, 'n'},
    {"destinationmac", required_argument, NULL, 'a'},
    // {"destinationport", required_argument, NULL, 'p'},
    {"help", no_argument, &help, 'h'},
    {"map", no_argument, &smap, 'm'},
    {"gateway", no_argument, &smap, 'g'},
    // {"distdest", no_argument, &sdistdest, 'e'},
    {"distsource", no_argument, &sdistsource, 'o'},
    {"listfw", no_argument, &slistfw, 'l'},
    {"listdist", no_argument, &slistdist, 'i'},
    {"tmpf", required_argument, NULL, 'f'},
    {"action", required_argument, NULL, 'c'},
    {"mapvalue", required_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
};

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

struct bublr {
    uint32_t sip0;
    uint32_t sip1;
    uint32_t sip2;
    uint32_t sip3;
    uint32_t dip0;
    uint32_t dip1;
    uint32_t dip2;
    uint32_t dip3;
    uint8_t dmac0;
    uint8_t dmac1;
    uint8_t dmac2;
    uint8_t dmac3;
    uint8_t dmac4;
    uint8_t dmac5;
    uint16_t pad;
};

struct distdestr {
    uint32_t dip0;
    uint32_t dip1;
    uint32_t dip2;
    uint32_t dip3;
    uint8_t dmac0;
    uint8_t dmac1;
    uint8_t dmac2;
    uint8_t dmac3;
    uint8_t dmac4;
    uint8_t dmac5;
    uint16_t pad;
};

struct distsourcer {
    uint32_t sip0;
    uint32_t sip1;
    uint32_t sip2;
    uint32_t sip3;
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

    while ((c = getopt_long(argc, argv, "mglhuid:s:n:a:v:f:c:", opts, NULL)) != -1)
    {
        switch (c)
        {


            case 'd':
                drivename = optarg;

                break;


            case 's':
                sourceipstring = optarg;

                break;

            case 'n':
                destinationipstring = optarg;

                break;


            case 'a':
                destinationmacstring = optarg;

                break;

             case 'v':
                mapvaluestring = optarg;

                break;
            
            case 'f':
                tmpfileloc = optarg;

                break;

            case 'c':
                action = optarg;

                break;
            
            // case 'p':
            //     destinationportstring = optarg;

            //     break;

            case 'h':
                help = 1;

                break;
            
            case 'm':
                smap = 1;

                break;

            case 'g':
                sgateway = 1;

                break;

            case 'u':
                sdistsource = 1;

                break;

            // case 'e':
            //     sdistdest = 1;

            //     break;


            case 'l':
                slistfw = 1;

                break;

             case 'i':
                slistdist = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}

int str2mac(const char* mac, uint8_t* values){
    if( 6 == sscanf( mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&values[0], &values[1], &values[2],&values[3], &values[4], &values[5] ) ){
        return 1;
    }else{
        return 0;
    }
}

int open_bpf_map(const char *subdir, const char *openmap)
{
	int fd;
    char map_filename[PATH_MAX];
	char pin_dir[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, subdir, openmap);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAILURE;
	}

	fd = bpf_obj_get(map_filename);
	if (fd < 0) {
		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n", map_filename, errno, strerror(errno));
		return EXIT_FAILURE;
	}
	return fd;
}





int main(int argc, char *argv[])
{
    // Parse the command line.
    printf("i am here 1\n");
    parse_command_line(argc, argv);
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


    if (smap) {
       
        struct in6_addr sip;
        struct in6_addr dip;
        int fd;
        int fd2;
        int res;
        int res2;
        // __u32 value = 1;
        __u32 value;
	    struct bublr key;
        struct distdestr destkey;

        inet_pton(AF_INET6, sourceipstring, &sip);
        inet_pton(AF_INET6, destinationipstring, &dip);
        key.sip0 = sip.__in6_u.__u6_addr32[0];
        key.sip1 = sip.__in6_u.__u6_addr32[1];
        key.sip2 = sip.__in6_u.__u6_addr32[2];
        key.sip3 = sip.__in6_u.__u6_addr32[3];
        key.dip0 = dip.__in6_u.__u6_addr32[0];
        key.dip1 = dip.__in6_u.__u6_addr32[1];
        key.dip2 = dip.__in6_u.__u6_addr32[2];
        key.dip3 = dip.__in6_u.__u6_addr32[3];
        destkey.dip0 = dip.__in6_u.__u6_addr32[0];
        destkey.dip1 = dip.__in6_u.__u6_addr32[1];
        destkey.dip2 = dip.__in6_u.__u6_addr32[2];
        destkey.dip3 = dip.__in6_u.__u6_addr32[3];


        // int dpval;
        // dpval = atoi(destinationportstring);
        // key.dport = htons(dpval);

        uint8_t macvalues[6] = { 0 };
        int success = str2mac(destinationmacstring, macvalues);
        if (success != 1) {
            fprintf(stderr,"ERR: converting string to mac\n");
        }

        key.dmac0 = macvalues[0];
        key.dmac1 = macvalues[1];
        key.dmac2 = macvalues[2];
        key.dmac3 = macvalues[3];
        key.dmac4 = macvalues[4];
        key.dmac5 = macvalues[5];
        key.pad = 0;

        destkey.dmac0 = macvalues[0];
        destkey.dmac1 = macvalues[1];
        destkey.dmac2 = macvalues[2];
        destkey.dmac3 = macvalues[3];
        destkey.dmac4 = macvalues[4];
        destkey.dmac5 = macvalues[5];
        destkey.pad = 0;

        int valuelong = atoi(mapvaluestring);
        value = (__u32) valuelong;

        fd = open_bpf_map(drivename, map_name);
        printf("map %d", fd);

        if (strcmp(action,"insert") == 0) {
            res = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
        }

        if (strcmp(action,"delete") == 0) {
            res = bpf_map_delete_elem(fd, &key);
        }

        if (res != 0) { /* 0 == success */
            fprintf(stderr,
                "errno(%d/%s)",  errno, strerror(errno));

            if (errno == 17) {
                fprintf(stderr, ": Already bublfw list\n");
                return EXIT_SUCCESS;
            }
            fprintf(stderr, "\n");
            return EXIT_FAILURE;
        }


        fd2 = open_bpf_map(drivename, map_name_distdest);
        printf("map2 %d", fd2);

        if (strcmp(action,"insert") == 0) {
            res2 = bpf_map_update_elem(fd2, &destkey, &value, BPF_NOEXIST);
        }

        if (strcmp(action,"delete") == 0) {
            res2 = bpf_map_delete_elem(fd2, &destkey);
        }

        if (res2 != 0) { /* 0 == success */
            fprintf(stderr,
                "errno(%d/%s)",  errno, strerror(errno));

            if (errno == 17) {
                fprintf(stderr, ": Already in dist dest list\n");
                return EXIT_SUCCESS;
            }
            fprintf(stderr, "\n");
            return EXIT_FAILURE;
        }

    }


    if (sdistsource) {
       
        struct in6_addr sip;
        struct in6_addr dip;
        int fd;
        int res;
        __u32 value = 1;
	    struct distsourcer key;

        inet_pton(AF_INET6, sourceipstring, &sip);
        key.sip0 = sip.__in6_u.__u6_addr32[0];
        key.sip1 = sip.__in6_u.__u6_addr32[1];
        key.sip2 = sip.__in6_u.__u6_addr32[2];
        key.sip3 = sip.__in6_u.__u6_addr32[3];

        fd = open_bpf_map(drivename, map_name_distsource);
        printf("map %d", fd);

        if (strcmp(action,"insert") == 0) {
            res = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
        }

        if (strcmp(action,"delete") == 0) {
            res = bpf_map_delete_elem(fd, &key);
        }

        if (res != 0) { /* 0 == success */
            fprintf(stderr,
                "errno(%d/%s)",  errno, strerror(errno));

            if (errno == 17) {
                fprintf(stderr, ": Already in dist source\n");
                return EXIT_SUCCESS;
            }
            fprintf(stderr, "\n");
            return EXIT_FAILURE;
        }
    }


    if (sgateway) {
        struct in6_addr sip;
        int fd;
        int res;
        __u32 value = 1;
	    uint32_t key;

        inet_pton(AF_INET6, sourceipstring, &sip);
        // key.sip0 = sip.__in6_u.__u6_addr32[0];
        // key.sip1 = sip.__in6_u.__u6_addr32[1];
        // key.sip2 = sip.__in6_u.__u6_addr32[2];
        // key.sip3 = sip.__in6_u.__u6_addr32[3];

        key = sip.__in6_u.__u6_addr32[0];

        fd = open_bpf_map(drivename, map_name2);
        printf("map %d", fd);
        if (strcmp(action,"insert") == 0) {
            res = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
        }

        if (strcmp(action,"delete") == 0) {
            res = bpf_map_delete_elem(fd, &key);
        }

        if (res != 0) { /* 0 == success */
            fprintf(stderr,
                "errno(%d/%s)",  errno, strerror(errno));

            if (errno == 17) {
                fprintf(stderr, ": Already in gatewalist\n");
                return EXIT_SUCCESS;
            }
            fprintf(stderr, "\n");
            return EXIT_FAILURE;
        }


    }

    if (slistfw) {
        struct bublr key;
        struct bublr prev_key;
        struct distdestr destkey;
        struct distdestr prev_destkey;
        __u32 value;
        int fd;
        int fd2;
        int res;
        int len;
        FILE *fp;
        FILE *fp2;
        char wline[PATH_MAX];
        char output_filename[PATH_MAX];
        char output_filename2[PATH_MAX];

        len = snprintf(output_filename, PATH_MAX, "%s/%s", tmpfileloc , "fwbubl.csv");
        if (len < 0) {
            fprintf(stderr, "ERR: creating outputfilename\n");
            return EXIT_FAILURE;
        }

        fp = fopen(output_filename, "w+");

        fd = open_bpf_map(drivename, map_name);
        
        while(bpf_map_get_next_key(fd, &prev_key, &key) == 0) {
            printf("Got key %u\n", key.sip0);
            struct in6_addr sip;
            struct in6_addr dip;

            sip.__in6_u.__u6_addr32[0] = key.sip0;
            sip.__in6_u.__u6_addr32[1] = key.sip1;
            sip.__in6_u.__u6_addr32[2] = key.sip2;
            sip.__in6_u.__u6_addr32[3] = key.sip3;
            dip.__in6_u.__u6_addr32[0] = key.dip0;
            dip.__in6_u.__u6_addr32[1] = key.dip1;
            dip.__in6_u.__u6_addr32[2] = key.dip2;
            dip.__in6_u.__u6_addr32[3] = key.dip3;
            // printf("%x:%x:%x:%x\n", ntohs(sip.__in6_u.__u6_addr16[0]),ntohs(sip.__in6_u.__u6_addr16[1]),ntohs(sip.__in6_u.__u6_addr16[2]),ntohs(sip.__in6_u.__u6_addr16[3]));

            res = bpf_map_lookup_elem(fd, &key, &value);
            if(res < 0) {
                printf("No value??\n");
            } else {
                printf("%u\n", value);
           
            }

            len = snprintf(wline, PATH_MAX, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%x,%04x:%04x:%04x:%04x:%04x:%04x:%04x:%x,%02x:%02x:%02x:%02x:%02x:%02x,%u\n", 
                ntohs(sip.__in6_u.__u6_addr16[0]),
                ntohs(sip.__in6_u.__u6_addr16[1]),
                ntohs(sip.__in6_u.__u6_addr16[2]),
                ntohs(sip.__in6_u.__u6_addr16[3]),
                ntohs(sip.__in6_u.__u6_addr16[4]),
                ntohs(sip.__in6_u.__u6_addr16[5]),
                ntohs(sip.__in6_u.__u6_addr16[6]),
                ntohs(sip.__in6_u.__u6_addr16[7]),
                ntohs(dip.__in6_u.__u6_addr16[0]),
                ntohs(dip.__in6_u.__u6_addr16[1]),
                ntohs(dip.__in6_u.__u6_addr16[2]),
                ntohs(dip.__in6_u.__u6_addr16[3]),
                ntohs(dip.__in6_u.__u6_addr16[4]),
                ntohs(dip.__in6_u.__u6_addr16[5]),
                ntohs(dip.__in6_u.__u6_addr16[6]),
                ntohs(dip.__in6_u.__u6_addr16[7]),
                key.dmac0,
                key.dmac1,
                key.dmac2,
                key.dmac3,
                key.dmac4,
                key.dmac5,
                value
                );

            if (len < 0) {
                fprintf(stderr, "ERR: creating line\n");
                fclose(fp);
                return EXIT_FAILURE;
            }
            fputs(wline, fp);


            prev_key=key;

        }

        fclose(fp);


        len = snprintf(output_filename2, PATH_MAX, "%s/%s", tmpfileloc , "fwdistdest.csv");
        if (len < 0) {
            fprintf(stderr, "ERR: creating outputfilename\n");
            return EXIT_FAILURE;
        }

        fp2 = fopen(output_filename2, "w+");

        fd2 = open_bpf_map(drivename, map_name_distdest);
        
        while(bpf_map_get_next_key(fd2, &prev_destkey, &destkey) == 0) {
            printf("Got key %u\n", destkey.dip0);
            struct in6_addr sip;
            struct in6_addr dip;

            dip.__in6_u.__u6_addr32[0] = destkey.dip0;
            dip.__in6_u.__u6_addr32[1] = destkey.dip1;
            dip.__in6_u.__u6_addr32[2] = destkey.dip2;
            dip.__in6_u.__u6_addr32[3] = destkey.dip3;
            // printf("%x:%x:%x:%x\n", ntohs(sip.__in6_u.__u6_addr16[0]),ntohs(sip.__in6_u.__u6_addr16[1]),ntohs(sip.__in6_u.__u6_addr16[2]),ntohs(sip.__in6_u.__u6_addr16[3]));

            len = snprintf(wline, PATH_MAX, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x,%02x:%02x:%02x:%02x:%02x:%02x\n", 
                    ntohs(dip.__in6_u.__u6_addr16[0]),
                    ntohs(dip.__in6_u.__u6_addr16[1]),
                    ntohs(dip.__in6_u.__u6_addr16[2]),
                    ntohs(dip.__in6_u.__u6_addr16[3]),
                    ntohs(dip.__in6_u.__u6_addr16[4]),
                    ntohs(dip.__in6_u.__u6_addr16[5]),
                    ntohs(dip.__in6_u.__u6_addr16[6]),
                    ntohs(dip.__in6_u.__u6_addr16[7]),
                    destkey.dmac0,
                    destkey.dmac1,
                    destkey.dmac2,
                    destkey.dmac3,
                    destkey.dmac4,
                    destkey.dmac5
                    );
            if (len < 0) {
                fprintf(stderr, "ERR: creating line\n");
                fclose(fp2);
                return EXIT_FAILURE;
            }
            fputs(wline, fp2);
            res = bpf_map_lookup_elem(fd2, &destkey, &value);
            if(res < 0) {
                printf("No value??\n");
            } else {
                printf("%u\n", value);
            }
            prev_destkey=destkey;
        }

        fclose(fp2);
    }

    if (slistdist) {
        struct distsourcer key;
        struct distsourcer prev_key;

        __u32 value;
        int fd;
        int fd2;
        int res;
        int len;
        FILE *fp;
        char wline[PATH_MAX];
        char output_filename[PATH_MAX];
   

        len = snprintf(output_filename, PATH_MAX, "%s/%s", tmpfileloc , "fwdistsource.csv");
        if (len < 0) {
            fprintf(stderr, "ERR: creating outputfilename\n");
            return EXIT_FAILURE;
        }

        fp = fopen(output_filename, "w+");

        fd = open_bpf_map(drivename, map_name_distsource);
        
        while(bpf_map_get_next_key(fd, &prev_key, &key) == 0) {
            printf("Got key %u\n", key.sip0);
            struct in6_addr sip;

            sip.__in6_u.__u6_addr32[0] = key.sip0;
            sip.__in6_u.__u6_addr32[1] = key.sip1;
            sip.__in6_u.__u6_addr32[2] = key.sip2;
            sip.__in6_u.__u6_addr32[3] = key.sip3;
           
            // printf("%x:%x:%x:%x\n", ntohs(sip.__in6_u.__u6_addr16[0]),ntohs(sip.__in6_u.__u6_addr16[1]),ntohs(sip.__in6_u.__u6_addr16[2]),ntohs(sip.__in6_u.__u6_addr16[3]));

            len = snprintf(wline, PATH_MAX, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%x\n", 
                    ntohs(sip.__in6_u.__u6_addr16[0]),
                    ntohs(sip.__in6_u.__u6_addr16[1]),
                    ntohs(sip.__in6_u.__u6_addr16[2]),
                    ntohs(sip.__in6_u.__u6_addr16[3]),
                    ntohs(sip.__in6_u.__u6_addr16[4]),
                    ntohs(sip.__in6_u.__u6_addr16[5]),
                    ntohs(sip.__in6_u.__u6_addr16[6]),
                    ntohs(sip.__in6_u.__u6_addr16[7])
                    );
            if (len < 0) {
                fprintf(stderr, "ERR: creating line\n");
                fclose(fp);
                return EXIT_FAILURE;
            }
            fputs(wline, fp);
            res = bpf_map_lookup_elem(fd, &key, &value);
            if(res < 0) {
                printf("No value??\n");
            } else {
                printf("%u\n", value);
            }
            prev_key=key;
        }

        fclose(fp);


    }


    // Exit program successfully.
    return EXIT_SUCCESS;
}