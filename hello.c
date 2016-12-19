#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb) {
    struct iphdr    * iph;
    struct tcphdr   * tcph;

    if (skb) {
        iph = ip_hdr(skb);

        if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP)) {
            tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

            if (tcph->source) {
                if ((tcph->urg && tcph->fin && tcph->psh) && (!tcph->ack && !tcph->syn && !tcph->rst)) {
                    printk(KERN_DEBUG "TCP Xmas Scan Detected!\n");
                } else if (!tcph->urg && !tcph->fin && !tcph->psh && !tcph->ack && !tcph->syn && !tcph->rst) {
                    printk(KERN_DEBUG "TCP NULL Scan Detected!\n");
                } else if ((tcph->fin) && (!tcph->urg &&!tcph->ack && !tcph->syn && !tcph->rst && !tcph->psh)) {
                    printk(KERN_DEBUG "TCP FIN Scan Detected!\n");
                } else if ((tcph->syn) && (!tcph->fin && !tcph->psh && !tcph->urg && !tcph->ack && !tcph->rst)) {
                    printk(KERN_DEBUG "TCP SYN Scan Detected!\n");
                }
            }
        }
    }

    return NF_ACCEPT;
}

int init_module() {
    int result;

    nfho.hook   = (nf_hookfn *) hook_func;
    nfho.hooknum    = NF_INET_POST_ROUTING;
    nfho.pf     = PF_INET;
    nfho.priority   = NF_IP_PRI_FIRST;

    result = nf_register_hook(&nfho);

    if(result) {
        printk(KERN_DEBUG "Error!\n");
        return 1;
    }

    printk(KERN_DEBUG "Module inserted!\n");

    return 0;
}

void cleanup_module() {
    nf_unregister_hook(&nfho);
    printk(KERN_DEBUG "Module removed!\n");
}