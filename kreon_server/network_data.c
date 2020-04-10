
//  tu_network_data.c
//  Fuctions related to network stuff: get the hostname, get the IP address of all the nics,
//
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez-Ferez <pilar@ics.forth.gr>.
//

#define _GNU_SOURCE /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <sys/types.h>

#include "regions.h"
#include "prototype.h"
#include "network_data.h"
#include "globals.h"
#include <log.h>

void Init_Tu_Network_Data(_tu_network_data *net)
{
	net->hostname = NULL;
	net->IPs = NULL;
	net->num_NICs = 0;
	//net->net_private = NULL;
}

/*
* Set the hostname of the server.
 * It will alloc space if needed (because it has not been allocated before
 * or because there is not enought memory)
 */
/* [mvard] deprecated by Get_My_Hostname. To be removed
void Set_and_Alloc_Hostname( const char *buf, _tu_network_data *net )
{
	if ( net-> hostname == NULL)
		net->hostname = (char *)malloc(sizeof(char) * strlen( buf ) + 1 );
	else if ( ( strlen(buf) + 1 )  > strlen( net->hostname )){
		free( net->hostname);
		net->hostname = (char *)malloc(sizeof(char) * strlen( buf ) + 1 );
	}

	if(net->hostname == NULL){
		printf("ERROR Hostname NULL\n");
		exit(1);
	}
	strncpy( net->hostname , buf, strlen( buf ) + 1 );
}
*/
/*
 * Get the hostname of the server.
 * To create the /servers/hostname node at zookeeper
 */

char *get_my_hostname(void)
{
	char buf[2048];
	char *hostname = NULL;
	char port[6];

	sprintf(port, "%d", globals_get_RDMA_connection_port());
	gethostname(buf, sizeof(buf));
	int hostname_length = sizeof(char) * (strlen(buf) + strlen(port)) + 1;
	hostname = (char *)malloc(hostname_length);
	if (hostname == NULL) {
		printf("ERROR Hostname NULL\n");
		exit(1);
	}
	sprintf(hostname, "%s-%s", buf, port);
	return hostname;
}

/*
 * Get IPs addresses of a server
 * TODO: We should avoid the localhost, but right now, I need it
 */
/* TODO [mvard] append port to ip addresses and change client functions to not
 * do anything about ports
 */
void Get_My_IP_Addresses(_tu_network_data *net)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n, i;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) {
			//n++;
			/*<gesalous>*/
			//added this segment for experiments. It accepts only IPs with
			//the prefix 192.168.2.200
			struct sockaddr_in *sa;
			char *addr;
			sa = (struct sockaddr_in *)ifa->ifa_addr;
			addr = inet_ntoa(sa->sin_addr);
			char *ip_filter = globals_get_RDMA_IP_filter();
			if (strncmp(addr, ip_filter, strlen(ip_filter)) == 0) {
				log_info("RDMA IP prefix accepted %s Interface: %s Full IP Address: %s",
					 globals_get_RDMA_IP_filter(), ifa->ifa_name, addr);
				n++;
			}
			/*</gesalous>*/
		}
	}
	if (n == 0) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	net->num_NICs = n;
	net->IPs = (char **)malloc(sizeof(char *) * n);
	for (i = 0; i < n; i++) {
		net->IPs[i] = (char *)malloc(sizeof(char) * 32);
	}

	for (ifa = ifaddr, i = 0; ifa != NULL; ifa = ifa->ifa_next) {
		char IPS[32];
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;
		/* For an AF_INET* interface address, display the address */

		if (family == AF_INET) {
			/*<gesalous>*/
			//added this segment for experiments. It accepts only IPs with
			//the prefix 192.168.2.200
			struct sockaddr_in *sa;
			char *addr;
			sa = (struct sockaddr_in *)ifa->ifa_addr;
			addr = inet_ntoa(sa->sin_addr);
			char *ip_filter = globals_get_RDMA_IP_filter();
			if (strncmp(addr, ip_filter, strlen(ip_filter)) != 0) {
				log_info("Interface: %s Address: %s", ifa->ifa_name, addr);
				continue;
			}
			/*</gesalous>*/
			s = getnameinfo(ifa->ifa_addr,
					(family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					IPS, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}
			sprintf(net->IPs[i], "%s:%d", IPS, globals_get_RDMA_connection_port());
			/*strcpy(net->IPs[i],IPS);*/
			//printf("DIP %d %s %s\n", i,net->IPs[i], IPS);fflush(stdout);
			i++;
		}
	}
#if 0
	for ( i = 0; i < n ; i++)
	{
		printf("DIP2 %d %s\n", i,net->IPs[i]);fflush(stdout);
	}
#endif
	freeifaddrs(ifaddr);
}

void Get_Tu_Network_Data(_tu_network_data *net)
{
	net->hostname = get_my_hostname();
	Get_My_IP_Addresses(net);
}
//..............................................................................
void Set_And_Alloc_IPs(const struct String_vector *zk_ip, _tu_network_data *net)
{
	char **IPs;
	int num_NICs = 0;
	int i;
	int j;

	if (zk_ip->count <= 0)
		return;

	if (net->num_NICs > 0) {
		IPs = net->IPs;
		num_NICs = net->num_NICs;
		net->IPs = NULL;
	} else
		IPs = NULL;

	net->num_NICs = zk_ip->count;
	net->IPs = (char **)malloc(sizeof(char *) * net->num_NICs);

	if (num_NICs == 0) {
		for (i = 0; i < zk_ip->count; i++) {
			net->IPs[i] = strdup(zk_ip->data[i]);
		}
	} else {
		for (i = 0; i < zk_ip->count; i++) {
			int found_IP = 0;
			for (j = 0; j < num_NICs; j++) {
				if (strcmp(zk_ip->data[i], IPs[j]) == 0) {
					net->IPs[i] = IPs[j];
					IPs[j] = NULL;
					found_IP = 1;
					break;
				}
			}
			if (found_IP == 0) {
				net->IPs[i] = strdup(zk_ip->data[i]);
			}
		}
		for (i = 0; i < num_NICs; i++) {
			if (IPs[i] != NULL)
				free(IPs[i]);
		}
		free(IPs);
	}
	PrintfNetData(net);
}

void PrintfNetData(_tu_network_data *net)
{
	int i;
	for (i = 0; i < net->num_NICs; i++) {
		printf("IP %d %s\n", i, net->IPs[i]);
	}
}

void Free_Network_Data(_tu_network_data *net)
{
	int i;

	if (net->hostname != NULL) {
		free(net->hostname);
		net->hostname = NULL;
	}

	if (net->num_NICs == 0)
		return;

	for (i = 0; i < net->num_NICs; i++)
		free(net->IPs[i]);
	free(net->IPs);
	net->num_NICs = 0;
	net->IPs = NULL;
}
//..............................................................................

void Init_Array_Tu_Network_Data(_array_tu_network_data *net_list)
{
	net_list->count = 0;
	net_list->net_data = NULL;
}

//..............................................................................
void Set_And_Alloc_Tu_Network_Data(const struct String_vector *zk_servers, _array_tu_network_data *net_list,
				   void *net_private)
{
	_tu_network_data *old_net_data;
	int old_count = 0;
	int i;
	int j;

	if (zk_servers->count <= 0)
		return;

	if (net_list->count > 0) {
		old_net_data = net_list->net_data;
		old_count = net_list->count;
		net_list->net_data = NULL;
	}

	net_list->count = zk_servers->count;
	net_list->net_data = malloc(net_list->count * sizeof(_tu_network_data));
	if (net_list->net_data == NULL) {
		perror("Set_And_Alloc_Tu_Network_Data: alloc net_data\n");
		exit(1);
	}

	// We copy the list of servers, and for each server we put the list of IPs to NULL
	if (old_count > 0) {
		for (i = 0; i < net_list->count; i++) {
			int found_hostname;
			found_hostname = 0;
			for (j = 0; j < old_count; j++) {
				if (strcmp(zk_servers->data[i], old_net_data[j].hostname) == 0) {
					net_list->net_data[i].hostname = old_net_data[j].hostname;
					net_list->net_data[i].num_NICs = old_net_data[j].num_NICs;
					net_list->net_data[i].IPs = old_net_data[j].IPs;
					old_net_data[j].num_NICs = 0;
					old_net_data[j].IPs = NULL;
					old_net_data[j].hostname = NULL;
					found_hostname = 1;
					printf("Encontrado %s\n", net_list->net_data[i].hostname);
					break;
				}
			}
			if (found_hostname == 0) {
				Init_Tu_Network_Data(&net_list->net_data[i]);
				net_list->net_data[i].hostname = strdup(zk_servers->data[i]);
			}
			//net_list->net_data[i].net_private = net_private;
			//client_get_IP_server( &net_list->net_data[i] ); //We call zookeeper to update the list of IPs for the server
		}
	} else {
		for (i = 0; i < net_list->count; i++) {
			Init_Tu_Network_Data(&net_list->net_data[i]);
			net_list->net_data[i].hostname = strdup(zk_servers->data[i]);
			//net_list->net_data[i].net_private = net_private;
			//client_get_IP_server( &net_list->net_data[i] ); //We call zookeeper to update the list of IPs for the server
		}
	}

	if (old_count == 0) //There was no data previously
	{
		return;
	}

	// Delete the old data
	for (j = 0; j < old_count; j++) {
		Free_Network_Data(&old_net_data[j]);
	}
	free(old_net_data);
}
