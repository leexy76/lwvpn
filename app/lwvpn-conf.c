#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <strings.h>

#include "../driver/lwvpn.h"

char * const short_options = "Virchs:d:a:p:k:v:" ;

struct option long_options[] = {
    { "version", 0, NULL, 'V' },
    { "insert", 0, NULL, 'i' },
    { "remove", 0, NULL, 'r' },
    { "clean", 0, NULL, 'c' },
    { "help", 0, NULL, 'h' },
    { "source", 1, NULL, 's' },
    { "dest", 1, NULL, 'd' },
    { "action", 1, NULL, 'a' },
    { "priority", 1, NULL, 'p' },
    { "key", 1, NULL, 'k' },
    { "iv", 1, NULL, 'v' },
} ;

void usage(char *path)
{
    printf("usage: %s [options]\n", basename(path)) ;
    printf("LW-VPN config\n\n") ;
    printf("Mandatory arguments to long options are mandatory for short options too.\n") ;
    printf("  -V, --version\n");
    printf("        Get LW-VPN version\n") ;
    printf("  -i, --insert\n") ;
    printf("        Insert a policy to LW-VPN rule-list, needs:\n") ;
    printf("        -s, --source    source address: xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx\n");
    printf("        -d, --dest      dest address  : xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx\n");
    printf("        -a, --action    action        : DROP/PASS/ENCRY/DECRY\n");
    printf("        -p, --priority  priority      : 0~255, 0--high priority, 255--low priority\n");
    printf("        -k, --key       key           : input 32 hex number, (key len is 16 bytes)\n");
    printf("        -v, --iv        iv            : input 32 hex number, (iv len is 16 bytes)\n");
    printf("  -r, --remove\n") ;
    printf("        Remove a policy from LW-VPN rule-list, needs:\n") ;
    printf("        -s, --source    source net    : xxx.xxx.xxx.xxx\n");
    printf("        -d, --dest      dest net      : xxx.xxx.xxx.xxx\n");
    printf("  -c, --clean\n") ;
    printf("        Clean all rule-list of LW-VPN\n") ;
    printf("  -h, --help\n") ;
    printf("        Display this help and exit\n") ;
    exit(0) ;
}

#define OP_NULL         0
#define OP_GET_VER      1 
#define OP_ADD_POLICY   2
#define OP_DEL_POLICY   3
#define OP_CLR_POLICY   4
#define OP_MAX_NUM      OP_CLR_POLICY

unsigned int convert_ip(char *s)
{
    unsigned int ip = 0 ;
    unsigned char *ptr = (unsigned char *)&ip ;
    char *p ;
    int i ;

    for(i=0; i<4; ++i,++ptr) {
        p = strchr(s, '.') ;
        if(p)
            *p = 0 ;

        *ptr = atoi(s) ;

        if(!p)
            break ;
        else 
            s = p+1 ;
    }
    return ip ;
}

void convert_net(char *s, unsigned int *net, unsigned int *mask)
{
    char *s2 ;

    *net = 0 ;
    *mask = 0 ;

    s2 = strchr(s, '/') ;
    if(s2) {
        *s2 = 0x0 ;
        ++s2 ;

        if(mask) {
            *mask = convert_ip(s2) ;
        }
    }

    *net = convert_ip(s) ;
}

int to_hex(char ch)
{
    if(ch < '0')
        return 0 ;
    else if(ch <= '9')
        return ch - '0' ;
    else if(ch < 'A')
        return 0 ;
    else if(ch <= 'F')
        return (ch - 'A' + 10) ;
    else if(ch < 'a')
        return 0 ;
    else if(ch <= 'f')
        return (ch - 'a' + 10) ;

    return 0;
}

void convert_hex_str(char *s, unsigned char *buf, int buflen)
{
    int i ;

    if(s==NULL) 
        return ;

    for(i=0; (i<buflen*2) && (*s!=0); ++i,++s) 
    {
        buf[i>>1] |= to_hex(*s) << (i&1?0:4) ;
    } 
}

char *act_str(int val)
{
    switch(val)
    {
    case V_DROP:    return "DROP" ;
    case V_PASS:    return "PASS" ;
    case V_ENCRY:   return "ENCRY" ;
    case V_DECRY:   return "DECRY" ;
    default:        break ;
    }

    return "<Unknown>" ;
}

char *op_str(int val)
{
    switch(val)
    {
    case OP_NULL:       return "NULL" ; 
    case OP_GET_VER:    return "GET_VER" ;
    case OP_ADD_POLICY: return "ADD_POLICY" ;
    case OP_DEL_POLICY: return "DEL_POLICY" ; 
    case OP_CLR_POLICY: return "CLR_POLICY" ;
    default:            break ;
    }

    return "<Unknown>" ;
}

int main(int argc, char *argv[])
{
    int ret, fd, c ;
    unsigned int lwvpn_ver ;
    int op = OP_NULL, snet, smask, dnet, dmask, action, priority ;
    unsigned char key[16], iv[16] ;

    memset(key, 0, 16) ;
    memset(iv, 0, 16) ;

    while((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch(c) {
        case 'V':
            op = OP_GET_VER ;
            break ;

        case 'i':
            op = OP_ADD_POLICY ;
            break ;

        case 'r':
            op = OP_DEL_POLICY ;
            break ;

        case 's':
            convert_net(optarg, &snet, &smask) ;
            break ;

        case 'd':
            convert_net(optarg, &dnet, &dmask) ;
            break ;

        case 'p':
            priority = atoi(optarg) ;
            if(priority < 0)
                priority = 0 ;
            else if(priority > 255)
                priority = 255 ;
            break ;

        case 'a':
            if(strncasecmp(optarg, "DROP", 4) == 0) {
                action = V_DROP ;
            } else if (strncasecmp(optarg, "PASS", 4) == 0) {
                action = V_PASS ;
            } else if (strncasecmp(optarg, "ENCRY", 5) == 0) {
                action = V_ENCRY ;
            } else if (strncasecmp(optarg, "DECRY", 5) == 0) {
                action = V_DECRY ;
            }
            break ;

        case 'k':
            convert_hex_str(optarg, key, 16) ;
            break ;

        case 'v':
            convert_hex_str(optarg, iv, 16) ;
            break ;
        
        case 'c':
            op = OP_CLR_POLICY ;
            break ; 

        case 'h':
            usage(argv[0]);
            break ;

        default:
            printf("?? getopt returned character code %08x ??\n", c) ;
        }
    }

    {
        int i ;

        printf("op %s, source %08x/%08x, dest %08x/%08x, act:%s, pri:%d\n",
                        op_str(op), snet, smask, dnet, dmask, act_str(action), priority) ;

        for(i=0; i<16; ++i) {
            printf("%02x ", key[i]) ;
        }
        printf("\n") ;

        for(i=0; i<16; ++i) {
            printf("%02x ", iv[i]) ;
        }
        printf("\n") ;
    }

    if((op <= OP_NULL) || (op > OP_MAX_NUM))
        usage(argv[0]);

    fd = open("/dev/lwvpn", O_RDWR) ;
    if(fd == -1) {
        perror("open") ;
        return 0 ;
    }

    switch(op) 
    {
    case OP_GET_VER:
        ret = ioctl(fd, LWVPN_GET_VERS, &lwvpn_ver) ;
        if(ret == 0) {
            printf("LW-VPN Version: %06x.%02x\n", lwvpn_ver>>4, lwvpn_ver&0xF) ;
        } else {
            perror("Get version") ;
        }
        break ; 

    case OP_ADD_POLICY:
        {
            IoAddRuleReq req ;

            req.policy.snet = snet ;
            req.policy.smask = smask ;
            req.policy.dnet = dnet ;
            req.policy.dmask = dmask ;
            req.policy.action = action ;
            req.policy.priority = priority ;
            memcpy(&req.policy.key, key, 16) ;
            memcpy(&req.policy.iv, iv, 16) ;
        
            ret = ioctl(fd, LWVPN_ADD_RULE, &req) ;
            if(ret != 0) {
                perror("Add policy") ;
            }
        }
        break ;

    case OP_DEL_POLICY:
        {
            IoDelRuleReq req ;

            req.snet = snet ;
            req.dnet = dnet ;

            ret = ioctl(fd, LWVPN_DEL_RULE, &req) ;
            if(ret != 0) {
                perror("Delete policy") ;
            }
        }
        break ;

    case OP_CLR_POLICY:
        ret = ioctl(fd, LWVPN_CLR_RULE) ;
        if(ret != 0) {
            perror("Clean policy") ;
        } 
        break ;
    }

    close(fd) ;
    return 0 ;
}
