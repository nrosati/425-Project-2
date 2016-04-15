/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 * IMPLEMENTING ARP 3.2.6 Header table on page 230
    Build a table of mappings between IPs and MACs
    Time to Live ~15 minutes
    If address not in table send out request, add response to table
    If request recieved with a match in table send corresponding MAC
        Query message contains IP and MAC of sender
        So whenever a query sent all hosts can add sender to table
            if already in table reset TTL

 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    
    struct sr_ethernet_hdr* e_hdr = 0;
    e_hdr = (struct sr_ethernet_hdr*)packet;
    struct sr_arphdr* a_hdr = 0;
    //struct sr_if* iface = sr_get_interface(sr, interface);
    
    if(e_hdr-> ether_type == htons(ETHERTYPE_ARP))
    {
        /*CHECK THE TABLE, IF NOT IN TABLE FORWARD REQUEST ADD A RESPONSE 
        * TO THE TABLE.  IF IN THE TABLE SEND CORRESPONDING MAC, RESET TTL
        * OPTIONALLY ADD SENDER TO TABLE
        */

        a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
        printf("%d\n", ntohs(a_hdr->ar_op));
        if(a_hdr->ar_op == htons(ARP_REQUEST))
        {
            struct sr_if* iface = sr_get_interface(sr, interface);
            if(iface)//Found
            {   
                //should verify lengths of numerical values to make sure we use either htonl vs. htons 
                //htons for 2 byte numbers, htonl for 4 bytes numbers, refer to header specs for this
                struct sr_arphdr areply;
                areply.ar_op = htons(ARP_REPLY);
                areply.ar_sip = (iface->ip);//sender ip(us)
                areply.ar_tip = (a_hdr->ar_sip);//target ip(from a_hdr)
                memcpy(areply.ar_tha, a_hdr->ar_sha, 6);//target hardware address(a_hdr)
                memcpy(areply.ar_sha, iface->addr, 6); //sender hardware address(us) 
                areply.ar_hrd = htons(1);//hardware address format Ethernet?
                areply.ar_pro = htons(ETHERTYPE_IP);//protocal address format IP?
                areply.ar_hln = (unsigned char)(06);//length of hardware address Ethernet? Shiv said make it 06
                areply.ar_pln = (unsigned char)(04);//length of protocal address IP? Shiv said make it 04

                //Create Ethernet Header
                struct sr_ethernet_hdr ereply;
                memcpy(ereply.ether_dhost, a_hdr->ar_sha, 6);
                memcpy(ereply.ether_shost, iface->addr, 6);
                ereply.ether_type = htons(ETHERTYPE_ARP);

                //Create packet buffer
                unsigned int length = (sizeof(ereply) + sizeof(areply));
                uint8_t reply[length];
                memcpy(reply, &ereply, sizeof(struct sr_ethernet_hdr));
                memcpy((reply + sizeof(ereply)), &areply, sizeof(struct sr_arphdr));
                
                //Send Arp Reply
                sr_send_packet(sr, reply, length, interface);
            }
            
        }
        
        /********************************************************************
        *When do we want to send to next hop? In this method?
            Yes, check IP packet, if not for us send to next hop
        *Arp Cache, what is it how do we create it, when do we update it
            Linked list, 
        *How do we do the timing, sleep?
            Get time of day or whatever we did in milestone 3
        *Add check of packet = ip then do some stuff
        *If no ethernet address in table(routing table), send an arp request,
        *process the reply, I guess add the reply to the table.
        *
        *********************************************************************/

    }
    

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
