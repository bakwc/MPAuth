#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/time.h>

MODULE_AUTHOR("Filipp Kovalev <kovalev@quantion.ru>");
MODULE_DESCRIPTION("MPAuth - module for the ping authorisation");
MODULE_LICENSE("GPL");

struct nf_hook_ops bundle;

static int pingPass=220;
static int timeToConnect;
static int filterPort=22;
static __be32 allowedIp;
static __kernel_time_t allowedTime;

module_param(pingPass, int, S_IRUSR);
module_param(filterPort, int, S_IRUSR);

unsigned int intercept(unsigned hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff *)  )
{
    struct iphdr *ip;
    struct timeval currTime;
    struct tcphdr *tcp;

    do_gettimeofday(&currTime);

    if (skb->protocol == htons(ETH_P_IP))
    {
	ip = (struct iphdr *) skb_network_header(skb);

        if (ip->protocol == IPPROTO_ICMP)
	{
            if (skb->len==pingPass)
            {
                allowedIp=ip->saddr;
                allowedTime=currTime.tv_sec;
                //printk("Access granted..\n");
            }
	}

        if (ip->protocol == IPPROTO_TCP)
        {
            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);

            if (tcp->dest == htons(filterPort))
            {
                if (tcp->syn)
                {
                    if (ip->saddr==allowedIp &&
                        currTime.tv_sec<(allowedTime+timeToConnect))
                    {
                        //printk("Allowed\n");
                        return NF_ACCEPT;
                    }
                    else
                    {
                        //printk("Disallowed!\n");
                        return NF_DROP;
                    }
                }
            }
        }
    }

    return NF_ACCEPT;
}

int Init(void)
{
    timeToConnect=30;
    allowedIp=0;

    pingPass+=28;

    bundle.hook = intercept;
    bundle.owner = THIS_MODULE;
    bundle.pf = PF_INET;
    bundle.hooknum = NF_INET_PRE_ROUTING;
    bundle.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&bundle);

    printk("MPAuth loaded\n");
    return 0;
}

void Exit(void)
{
    nf_unregister_hook(&bundle);
    printk("MPAuth unloaded\n");
}

module_init(Init);
module_exit(Exit);
