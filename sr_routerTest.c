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
  uint32_t ip;
  time_t ttl;
  struct node *next;
  int alive;//1 = valid 0 = ttl expired
};

struct node *root;
uint8_t **queue;
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
    
    root = malloc(sizeof(struct node));
    root->alive = 1;
    root->ttl = 100;
    root->next = 0;
    queue = malloc(10 * sizeof(uint8_t *));//My 2d C arrays are rusty but I think this works?
    int j;
    for(j = 0; j < 10; j++)
    {
      queue[j] = 0;
    }

} /* -- sr_init -- */

void addList(uint8_t *ha, uint32_t ip);
void cleanList();
u_short cksum(u_short *buf, int count);
void refreshList(in_addr_t ip, uint8_t ha[6]);
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
    
    struct sr_if* iface = sr_get_interface(sr, interface);
    if(e_hdr-> ether_type == htons(ETHERTYPE_ARP))
    {
        /*CHECK THE TABLE, IF NOT IN TABLE FORWARD REQUEST ADD A RESPONSE
        * TO THE TABLE.  IF IN THE TABLE SEND CORRESPONDING MAC, RESET TTL
        * OPTIONALLY ADD SENDER TO TABLE
        */

        a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
        //printf("%d\n", ntohs(a_hdr->ar_op));
        printf("Arp recieved\n");
        addList(a_hdr->ar_sha, a_hdr->ar_sip);
        //refreshList(a_hdr->ar_sip, a_hdr->ar_sha);//Should this be src or dst?
        if(a_hdr->ar_op == htons(ARP_REQUEST))
        {
            printf("Arp Request recieved\n");
            if(iface)//Found
            {
              printf("Arp answer found sending response\n");
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
          printf("Arp Reply Recieved\n");
          //I think we want sender hardware address from the packet
           
           //addList(a_hdr->ar_sha, a_hdr->ar_sip);
           cleanList();
           //Loop through our queue of packets see if we can send any
          struct ip * ipq = 0;
          struct sr_ethernet_hdr * qe = 0;
           for(int i = 0; i < 10; i++)
           {
              if(queue[i] != 0)
              {
                 ipq = (struct ip*)(queue[i] + sizeof(struct sr_ethernet_hdr));
                //printf("looking in queue");
                printf("arp ip: %lu\n ip ip: %lu\n", (unsigned long)a_hdr->ar_sip, (unsigned long)ipq->ip_dst.s_addr);
                if(a_hdr->ar_sip == ipq->ip_dst.s_addr)
                {
                  printf("Sending From Queue\n");
                  qe = (struct sr_ethernet_hdr*)queue[i];
                  memcpy(qe->ether_dhost, a_hdr->ar_sha, 6);
                  unsigned int qlen = (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
                  sr_send_packet(sr, queue[i], qlen, interface);
                  queue[i] = 0;
                } 

              }
             
           }
        }


    }if(e_hdr-> ether_type == htons(ETHERTYPE_IP)){
      //handle IP packet:
          //if dest address is itself
              //discard packet, DONE
        //go through cache refresh any ttl if found
        printf("IP Packet recieved\n");
        if(memcmp(e_hdr->ether_dhost, iface->addr, 6))
        {
          //Do nothing?
          printf("Its for us returning\n");
          return;
        }
              
        else
        {
          ip_packet = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
          struct sr_ethernet_hdr eforward;//Ethernet header for forwarding packet
          addList(e_hdr->ether_shost, ip_packet->ip_src.s_addr);
          //refreshList(ip_packet->ip_src.s_addr, e_hdr->ether_shost);//Should this be the source or dest?
          uint8_t ttl = ip_packet->ip_ttl;//ntohs(ip_packet->ip_ttl);
          ttl--;
          if(ttl == 0)//If TTL = 0 
          {
            printf("Packet TTL = 0 returning\n");
            return;
          }
          else
          {
            printf("Checksum running\n");
            //Update checksum w/ IP Checksum algo. (see textbook p95)
            //IP CHECKSUM FOUND in ip_sum (uint16_t), TTL in ip_ttl (uint8_t)
            //source + dest addr in (struct in_addr) ip_src, ip_dst
          }

          //Look up routing table to find IP of nexthop
          struct sr_rt * rTemp = sr->routing_table;
          int compare = 0;
          struct in_addr sendIP;
          struct sr_rt *match1 = 0;
          struct sr_rt *match2 = 0;
          struct sr_if * oface = 0;  //sr_get_interface(sr, interface);
          in_addr_t mask;
          /**********************
            New Gameplan, make two sr_rt structs, if the mask & operation matches
            set one of them equal to the sr_rt node were on.  Then we can get what we
            want out of them later.  We want the interface name so we can get the
            outgoing interface address to send on from oface.  Then if the gateway
            is 0s we set sendIP to the destination.  If its not we set sendIP to the
            gateway.
          ***********************/
          while(rTemp)
          {
            printf("Looking up routing table\n");
            //Find the longest prefix match, get its next hop
      
            mask = rTemp->mask.s_addr;
            if((ip_packet->ip_dst.s_addr & mask) == (rTemp->dest.s_addr & mask))
            {
              if(compare)
              {
                match2 = rTemp;
              }
              else
              {
                match1 = rTemp;
                compare++;
              }
            }
            rTemp = rTemp->next;
            
          }
          /* So we will find at most 2 matches, one match will be the default, the mask is 0.
            so if we found two matches, match2 will be set, if match2 has a mask of 0 thats the default
            route we can ignore it.  If its not 0, thats the route we want so set match 1 to match 2
            */

          if(match2)
          {
            if(match2->mask.s_addr == 0)
            {

            }
            else
            {
              match1 = match2;
            }

          }
          oface = sr_get_interface(sr, match1->interface);
          if(match1->gw.s_addr == 0)
          {
            sendIP.s_addr = match1->dest.s_addr;
          }
          else
          {
            sendIP.s_addr = match1->gw.s_addr;
          }
          //Check ARP cache for Ethernet of nexthop
          struct node *temp = root;
          compare = 0;//repurpose as a flag
          while(temp->next)
          {
            printf("Looking up arp cache\n");
            //sendIP is from a standard system include it is a struct with a typedef of uint32_t
            if(memcmp(&sendIP.s_addr, &temp->ip, sizeof(uint32_t)) == 0)//== didnt want to work
            {
              printf("Found entry in Arp Cache setting ha\n");
              memcpy(eforward.ether_dhost, temp->ha, 6);
              compare = 1;
              break;
            }
            temp = temp->next;
          }
          if(!compare)//Reusing compare as a flag
          {
            printf("Didnt find in Cache, sending arp request\n");
            //send ARP request and receive for Ethernet address
            struct sr_ethernet_hdr erequest;
            struct sr_arphdr arpReq;
            
            memcpy(erequest.ether_shost, oface->addr, 6);//use interface you got from name
            erequest.ether_type = htons(ETHERTYPE_ARP);
            //get interface by name
            memset(erequest.ether_dhost, 0xFFFF, 6 * sizeof(erequest.ether_dhost[0]));//Broadcast all 1s

            arpReq.ar_hrd = htons(1);
            arpReq.ar_pro = htons(ETHERTYPE_IP);
            arpReq.ar_hln = (unsigned char)(06);
            arpReq.ar_pln = (unsigned char)(04);
            arpReq.ar_op = htons(ARP_REQUEST);
            memcpy(arpReq.ar_sha, iface->addr, 6);
            memset(arpReq.ar_tha, 0x0000, 6 * sizeof(arpReq.ar_tha[0]));//Target all 0s from BZhang
            arpReq.ar_sip = iface->ip;

            printf("Send iP = %lu\n", (unsigned long) sendIP.s_addr);
            arpReq.ar_tip = ip_packet->ip_dst.s_addr;
            unsigned int plen = (sizeof(erequest) + sizeof(arpReq));
            uint8_t req[plen];
            memcpy(req, &erequest, sizeof(struct sr_ethernet_hdr));
            memcpy((req + sizeof(erequest)), &arpReq, sizeof(struct sr_arphdr));

            //Send Arp Request
            sr_send_packet(sr, req, plen, oface->name);
          }
          //do ARP cache management
          cleanList();
          
          //temp = root;
       
          memcpy(eforward.ether_shost, iface->addr, 6);
          eforward.ether_type = htons(ETHERTYPE_IP);
          //Build IP packet
          struct ip ipforward;
          printf("Building IP packet\n");
          //Do we need htons for uint8_t?
          ipforward.ip_tos = ip_packet->ip_tos;//type of service uint8_t 0 = best beffort
          ipforward.ip_len = ip_packet->ip_len;//total length uint16_t
          ipforward.ip_id = ip_packet->ip_id;//identification uint16_t
          ipforward.ip_off = ip_packet->ip_id;//fragment offset field uint16_t
          ipforward.ip_ttl = 64;//time to live uint8_t
          ipforward.ip_p = ip_packet->ip_p;//protocol uint8_t 6 = tcp

          /***************Set this to the checksum we did earlier***********/
          ipforward.ip_sum = ip_packet->ip_sum;//checksum uint16_t
          /**********Error possible here with IP struct*****************/
          
          ipforward.ip_dst.s_addr = sendIP.s_addr;//destination address, s_addr is uint32_t inside struct in_addr
          ipforward.ip_src.s_addr = iface->ip;//source address same as parameters as destination

          
          //Create packet buffer
          unsigned int flen = (sizeof(eforward) + sizeof(ipforward));
          uint8_t freply[flen];
          memcpy(freply, &eforward, sizeof(struct sr_ethernet_hdr));
          memcpy((freply + sizeof(eforward)), &ipforward, sizeof(struct ip));

          if(compare)//If we found it in the cache, ha has been set, ok to send
          {
            //Send to next hop and DONE
            printf("HA found in cache, sending packet\n");
            sr_send_packet(sr, freply, flen, oface->name);
          }
          else//If we didnt find ha in cache, add it to queue
          {
            printf("Not in cache, adding to queue\n");
            for(int j = 0; j < 10; j++)
            {
              if(queue[j] == 0)
              {
                queue[j] = freply;
                break;
              }
            }
          }
          
        }

      
      //process the packet
      cleanList();
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
 void addList(uint8_t *ha, uint32_t ip)
 {
  printf("Running add list\n");
    struct node *temp = root;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t life = tv.tv_sec;
    int flag = 1;
    
    //printf("iMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ha[0], ha[1], ha[2], ha[3], ha[4], ha[5]);
    
    while(temp)
    {
      //If its in our list, but marked dead reset ttl, bring back to life
      
      //printf("lMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", temp->ha[0], temp->ha[1], temp->ha[2], temp->ha[3], temp->ha[4], temp->ha[5]);
      if(memcmp(temp->ha, ha, 6) == 0)
      {
        printf("Packet life reset\n");
        temp->ttl = life;
        temp->alive = 1;
        flag = 0;
      }
      temp = temp->next;
    }
    if(flag){//If we didnt find it in our list already add it
      temp = root;
      while(temp->next)
      {
        temp = temp->next;
      }
      struct node *next;
      next = (struct node *) malloc(sizeof(struct node));
      memcpy(next->ha, ha, 6);
      next->ttl = life;
      next->next = 0;
      next->alive = 1;
      next->ip = ip;
      temp->next = next;
      printf("Packet added to cache\n");
    }
 }

 void refreshList(in_addr_t ip, uint8_t ha[6])
 {
  printf("Running refresh list\n");
  struct node *temp = root;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  time_t life = tv.tv_sec;
  while(temp)
  {
    printf("refreshList loop\n");
      if(temp->ip == ip)
      {
        if(memcmp(temp->ha, ha, 6) == 0){
          temp->ttl = life;
          printf("Refreshing packet\n");
        }
      }
      temp = temp->next;
  }
 }

 void cleanList()
 {
  printf("Running clean list\n");
    struct node *temp = root;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t life = tv.tv_sec;
    while(temp)
    {
      //printf("Clean list loop\n");
      int dif = life - temp->ttl;
      if(dif >= 15 && temp->alive == 1 && temp != root)
      {
        temp->alive = 0;
        printf("Marking packet as expired\n");
      }
      temp = temp->next;
    }
    /*temp = root;
    int flag = 0;
    while(temp->next)
    {
      if(temp->next->alive == 0)
      {
        temp->next = temp->next->next;
        free(temp->next);
        flag = 1;
      }
    }
    if(flag)
      cleanList();*/
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
