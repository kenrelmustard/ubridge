/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_link.h>

#include "ubridge.h"
#include "hypervisor.h"
#include "hypervisor_vxlan.h"
#include "netlink/nl.h"

struct link_req {
  struct nlmsg nlmsg;
  struct ifinfomsg ifinfomsg;
};

static int netdev_set_flag(hypervisor_conn_t *conn, const char *name, int flag)
{
    struct nl_handler nlh;
    struct nlmsg *nlmsg = NULL, *answer = NULL;
    struct link_req *link_req;
    int ifindex, len;
    int err = -1;

    if (netlink_open(&nlh, NETLINK_ROUTE)) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not open netlink connection");
        return (-1);
    }

    len = strlen(name);
    if (len == 0 || len >= IFNAMSIZ) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "interface name is invalid or too long");
        goto out;
    }

    nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!nlmsg || !answer) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "insufficient memory");
        goto out;
    }

    if (!(ifindex = if_nametoindex(name))) {
       hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not find interface index");
       goto out;
    }

    link_req = (struct link_req *)nlmsg;
    link_req->ifinfomsg.ifi_family = AF_UNSPEC;
    link_req->ifinfomsg.ifi_index = ifindex;
    link_req->ifinfomsg.ifi_change |= IFF_UP;
    link_req->ifinfomsg.ifi_flags |= flag;
    nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
    nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

    if (netlink_transaction(&nlh, nlmsg, answer)) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not complete netlink transaction");
        goto out;
    }
    err = 0;

out:
    netlink_close(&nlh);
    nlmsg_free(nlmsg);
    nlmsg_free(answer);
    return (err);
}

/*
 * Create a VXLAN interface
 * Arguments: <name> <vni> <local_ip> [<remote_ip>]
 */
static int cmd_create_vxlan(hypervisor_conn_t *conn, int argc, char *argv[])
{
    struct nl_handler nlh;
    struct nlmsg *nlmsg = NULL, *answer = NULL;
    struct link_req *link_req;
    struct rtattr *nest1, *nest2;
    char *ifname = argv[0];
    unsigned long vni_val;
    char *endptr;
    struct in_addr local_addr;
    struct in_addr remote_addr;
    int err = -1;
    int has_remote = 0;

    if (netlink_open(&nlh, NETLINK_ROUTE)) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not open netlink connection");
        return (-1);
    }

    if (strlen(ifname) >= IFNAMSIZ) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "interface name is too long");
        goto out;
    }

    errno = 0;
    vni_val = strtoul(argv[1], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || endptr == argv[1] || vni_val > 16777215) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "VNI must be a valid number between 0 and 16777215");
        goto out;
    }

    if (inet_pton(AF_INET, argv[2], &local_addr) != 1) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "invalid local IP address");
        goto out;
    }

    if (argc == 4) {
        if (inet_pton(AF_INET, argv[3], &remote_addr) != 1) {
            hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "invalid remote IP address");
            goto out;
        }
        has_remote = 1;
    }

    nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!nlmsg || !answer) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "insufficient memory");
        goto out;
    }

    link_req = (struct link_req *)nlmsg;
    link_req->ifinfomsg.ifi_family = AF_UNSPEC;
    nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
    nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

    nla_put_string(nlmsg, IFLA_IFNAME, ifname);

    nest1 = nla_begin_nested(nlmsg, IFLA_LINKINFO);
    nla_put_string(nlmsg, IFLA_INFO_KIND, "vxlan");

    nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
    nla_put_u32(nlmsg, IFLA_VXLAN_ID, (unsigned int)vni_val);
    nla_put_buffer(nlmsg, IFLA_VXLAN_LOCAL, &local_addr, sizeof(local_addr));

    if (has_remote) {
        nla_put_buffer(nlmsg, IFLA_VXLAN_GROUP, &remote_addr, sizeof(remote_addr));
    }

    nla_end_nested(nlmsg, nest2);
    nla_end_nested(nlmsg, nest1);

    if (netlink_transaction(&nlh, nlmsg, answer)) {
        hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not create VXLAN interface");
        goto out;
    }

    if (netdev_set_flag(conn, ifname, IFF_UP)) {
        fprintf(stderr, "failed to enable interface '%s'\n", ifname);
        goto out;
    }

    if (has_remote)
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VXLAN interface %s created with VNI %lu (local %s, remote %s)", ifname, vni_val, argv[2], argv[3]);
    else
        hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VXLAN interface %s created with VNI %lu (local %s)", ifname, vni_val, argv[2]);
    err = 0;

out:
    netlink_close(&nlh);
    nlmsg_free(answer);
    nlmsg_free(nlmsg);
    return (err);
}

/*
 * Delete a VXLAN interface
 * Arguments: <name>
 */
static int cmd_delete_vxlan(hypervisor_conn_t *conn, int argc, char *argv[])
{
    struct nl_handler nlh;
    struct nlmsg *nlmsg = NULL, *answer = NULL;
    struct link_req *link_req;
    int ifindex;
    char *ifname = argv[0];
    int err = -1;

    if (netlink_open(&nlh, NETLINK_ROUTE)) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "could not open netlink connection");
        return (-1);
    }

    if (!(ifindex = if_nametoindex(ifname))) {
       hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "could not find interface index for %s", ifname);
       goto out;
    }

    nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
    answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
    if (!nlmsg || !answer) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "insufficient memory");
        goto out;
    }

    link_req = (struct link_req *)nlmsg;
    link_req->ifinfomsg.ifi_family = AF_UNSPEC;
    link_req->ifinfomsg.ifi_index = ifindex;
    nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
    nlmsg->nlmsghdr.nlmsg_type = RTM_DELLINK;

    if (netlink_transaction(&nlh, nlmsg, answer)) {
        hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "could not delete VXLAN interface");
        goto out;
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "VXLAN interface %s has been deleted", ifname);
    err = 0;

out:
    netlink_close(&nlh);
    nlmsg_free(answer);
    nlmsg_free(nlmsg);
    return (err);
}

/* VXLAN commands */
static hypervisor_cmd_t vxlan_cmd_array[] = {
   { "create", 3, 4, cmd_create_vxlan, NULL },
   { "delete", 1, 1, cmd_delete_vxlan, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor VXLAN initialization */
int hypervisor_vxlan_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("vxlan", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, vxlan_cmd_array);
   return(0);
}
