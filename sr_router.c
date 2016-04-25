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
#include <stdlib.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

struct node{
  unsigned char ha[ETHER_ADDR_LEN];
  time_t ttl;
  struct node *next;
  int dead;
};

struct node *root;
//root = malloc(sizeof(struct node));
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
      //Add linked list root and conductor here?
    root = malloc(sizeof(struct node));
    root->dead = 1;
    root->ttl = -1;

} /* -- sr_init -- */

void addList(struct node * toAdd);
void cleanList();
u_short cksum(u_short *buf, int count);
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
    struct ip* ip_packet = 0;
    //struct sr_if* iface = sr_get_interface(sr, interface);

    if(e_hdr-> ether_type == htons(ETHERTYPE_ARP))
    {
        /*CHECK THE TABLE, IF NOT IN TABLE FORWARD REQUEST ADD A RESPONSE
        * TO THE TABLE.  IF IN THE TABLE SEND CORRESPONDING MAC, RESET TTL
        * OPTIONALLY ADD SENDER TO TABLE
        */

        a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
        //printf("%d\n", ntohs(a_hdr->ar_op));
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

        }else if(a_hdr->ar_op == htons(ARP_REPLY)){
          // sent an ARP_REQUEST to resolve nexthop Ethernet address for the IP
          // parse ARP_REPLY for Ethernet address, add to linked list
          // w/ gettimeofday info for TTL in cache (15 sec)

          //I think we want sender hardware address from the packet

           //So our linked list, is it a global?
           struct timeval tv;
           struct node *next;
           next = (struct node *) malloc(sizeof(struct node));
           memcpy(next->ha, a_hdr->ar_sha, 6);
           gettimeofday(&tv, NULL);
           next->ttl = tv.tv_sec;
           next->next = 0;
           next->dead = 0;
           addList(next);
           cleanList();
        }


    }if(e_hdr-> ether_type == htons(ETHERTYPE_IP)){
      //handle IP packet:
          //if dest address is itself
              //discard packet, DONE
          //else
              //Decrement TTL by 1
                  //if TTL is now 0
                      //discard packet, DONE
                  //else
                      //Update checksum w/ IP Checksum algo. (see textbook p95)
              //Look up routing table to find IP of nexthop
              //Check ARP cache for Ethernet of nexthop
                  //if not in cache
                      //send ARP request and receive for Ethernet address
                      //do ARP cache management
              //Make packet and send to next hop, DONE

      //IP CHECKSUM FOUND in ip_sum (uint16_t), TTL in ip_ttl (uint8_t)
      //source + dest addr in (struct in_addr) ip_src, ip_dst

      ip_packet = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
      //process the packet

    }
    /*************************************************************
    * For cache, make a linked list with gettimeofday data included
    * so that everytime this method is called, it goes through and
    * maintains the list to remove nodes that are older than 15s
    * compared to the current time (gettimeofday again).
    *************************************************************/

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


}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
 void addList(struct node * toAdd)
 {
    struct node *temp = root;
    while(temp->next)
    {
      temp = temp->next;
    }
    temp->next = toAdd;
 }

 void cleanList()
 {
    struct node *temp = root;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t life = tv.tv_sec;
    while(temp->next)
    {
      int dif = life - temp->ttl;
      if(dif >= 15)
      {
        temp->dead = 0;
      }
    }
    temp = root;
    int flag = 0;
    while(temp->next)
    {
      if(temp->next->dead == 0)
      {
        temp->next = temp->next->next;
        free(temp->next);
        flag = 1;
      }
    }
    if(flag)
      cleanList();
 }

//IP Internet Checksum algorithm from book, copied here
//takes buffer of all data (in 16 bit words), with count
//of 16 bit words in count, returns u_short of the sum
u_short cksum(u_short *buf, int count)
{
  register u_long sum = 0;
  while(count--)
  {
    sum += *buf++;
    if(sum & 0xFFFF0000)
    {
      /*carry occurred, so wrap around */
      sum &= 0xFFFF;
      sum++;
    }
  }
  return ~(sum&0xFFFF);

}
