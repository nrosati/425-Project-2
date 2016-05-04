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
  struct in_addr ip;
  time_t ttl;
  struct node *next;
  char * name;
  int alive;//1 = valid 0 = ttl expired
};

struct fullIP
{
  struct ip header;//Header
  unsigned char data[1600];//Block of memeory for payload data
};
struct node *root;
struct fullIP queue[10];
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
    int i;
    for(i = 0; i < 10; i++)
    {
      queue[i].header.ip_ttl = 0;
    }

} /* -- sr_init -- */

void addList(uint8_t *ha, struct in_addr ip, char * interface);
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
        //printf("Arp recieved\n");
        struct in_addr temp;
        temp.s_addr = a_hdr->ar_sip;
        //printf("ARP sIP: %s\t\t", inet_ntoa(temp));
        addList(a_hdr->ar_sha, temp, interface);
        //refreshList(a_hdr->ar_sip, a_hdr->ar_sha);//Should this be src or dst?
        if(a_hdr->ar_op == htons(ARP_REQUEST))
        {
            //printf("Arp Request recieved\n");
            if(iface)//Found
            {
              //printf("Arp answer found sending response\n");
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
          //printf("Arp Reply Recieved\n");
          //I think we want sender hardware address from the packet
           
           //addList(a_hdr->ar_sha, a_hdr->ar_sip);
           cleanList();
           //Loop through our queue of packets see if we can send any
          //struct ip ipq;
          struct sr_ethernet_hdr qe;
           int i; 
           for(i = 0; i < 10; i++)
           {
              if(queue[i].header.ip_ttl != 0)
              {
                //printf("looking in queue\n");
                //printf("arp ip: %lu\n ip ip: %lu\n", (unsigned long)a_hdr->ar_sip, (unsigned long)ipq->ip_dst.s_addr);
                if(a_hdr->ar_sip == queue[i].header.ip_dst.s_addr);
                {
                  //printf("Building ether packet for queue\n");
                  memcpy(qe.ether_shost, iface->addr, 6);
                  //printf("1\n");
                  memcpy(qe.ether_dhost, a_hdr->ar_sha, 6);
                  //printf("2\n");
                  qe.ether_type = htons(ETHERTYPE_IP);
                 //printf("3\n");
                  unsigned int qlen = (sizeof(struct sr_ethernet_hdr) + ntohs(queue[i].header.ip_len));
                  //printf("Qlen: %d\n", qlen);
                  uint8_t qpack[qlen];
                  //printf("5\n");
                  memcpy(qpack, &qe, sizeof(struct sr_ethernet_hdr));
                  //printf("6\n");
                  memcpy((qpack + sizeof(struct sr_ethernet_hdr)), &queue[i], ntohs(queue[i].header.ip_len));
                  //printf("Sending packet from queue\n");
                  sr_send_packet(sr, qpack, qlen, interface);
                  //printf("7\n");
                  queue[i].header.ip_ttl = 0;
                } 

              }
             
           }
        }


    }if(e_hdr-> ether_type == htons(ETHERTYPE_IP)){
      //handle IP packet:
          //if dest address is itself
              //discard packet, DONE
        //go through cache refresh any ttl if found
        //printf("IP Packet recieved\n");
        if(memcmp(e_hdr->ether_dhost, iface->addr, 6))
        {
          //Do nothing?
          //printf("Its for us returning\n");
          return;
        }
              
        else
        {
          ip_packet = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
          //const unsigned char *data = 
          //printf("Size of packet recieved: %lu\n", sizeof(*ip_packet));
          //printf("Size of ip Struct: %lu\n", sizeof(struct ip));
          struct sr_ethernet_hdr eforward;//Ethernet header for forwarding packet
          addList(e_hdr->ether_shost, ip_packet->ip_src, interface);
          //refreshList(ip_packet->ip_src.s_addr, e_hdr->ether_shost);//Should this be the source or dest?

          /*********Gotta un comment this the TTL**************/
          ip_packet->ip_ttl--;//ntohs(ip_packet->ip_ttl);
          //printf("Memory Check: %x", (char)*(ip_packet+20));
          if(ip_packet->ip_ttl == 0)//If TTL = 0 
          {
            //printf("Packet TTL = 0 returning\n");
            return;
          }
          else
          {
            //printf("Checksum running\n");
            //IP CHECKSUM FOUND in ip_sum (uint16_t), TTL in ip_ttl (uint8_t)
            //source + dest addr in (struct in_addr) ip_src, ip_dst

            //split ip header values into u_short array
            unsigned int hlen = sizeof(struct ip);//Header length is always 4
                                                //4 what im not sure, size of struct ip outputs 20 soooo
            u_short words[sizeof(struct ip)];//hlen is 32-bit words, making this fit
            uint16_t zero= 0x0000;
            //pull out IP header of size given in header
            //why not just memcpy(words, ip_packet, sizeof(struct ip));
            memcpy(words,ip_packet, sizeof(struct ip));
            //set checksum location to 0
            //printf("Checksum from packet: %d\n", ip_packet->ip_sum);
            //printf("In array: %d\n", words[5]);
            words[5] = zero; //overwrite 16bit word at index 5
                            //which is checksum to 0
            //printf("After zero: %d\n", words[5]);
            //Ideally cksum would return a uint16_t since thats what our IP headers take
            u_short cksumres = cksum(words, hlen/2); //give buffer + # 16b words
            //printf("From checksum: %d\n", cksumres);
            ip_packet->ip_sum = cksumres;
            //compare calculated to what is in IP packet
            if(cksumres == (ip_packet->ip_sum)){
              //printf("Wow, IP Checksum works\n");

            }else{
              //printf("IP Checksum calculated doesn't match one included in header...\n");
            }
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
            //printf("Looking up routing table\n");
            //Find the longest prefix match, get its next hop
      
            mask = rTemp->mask.s_addr;
            //printf("IP Before: %s\t\t\n", inet_ntoa(ip_packet->ip_dst));
            if((ip_packet->ip_dst.s_addr & mask) == (rTemp->dest.s_addr & mask))
            {
              //printf("After: %s\t\t\n", inet_ntoa(ip_packet->ip_dst));
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
          compare = (int)sendIP.s_addr;//just to get rid of compile warning
          compare = 0;//repurpose as a flag
          while(temp)
          {
            //printf("Looking up arp cache\n");
            //sendIP is from a standard system include it is a struct with a typedef of uint32_t
            //printf("Packet ip: %s\t\t\n", inet_ntoa(ip_packet->ip_dst));
            //struct in_addr cacheIP;
            //cacheIP.s_addr = temp->ip;
            //printf("Cache ip: %s\t\t\n", inet_ntoa(temp->ip));
            if(memcmp(&temp->ip, &ip_packet->ip_dst.s_addr, sizeof(uint32_t)) == 0)//== didnt want to work
            {
              //printf("Found entry in Arp Cache\n");
              memcpy(eforward.ether_dhost, temp->ha, 6);
              memcpy(eforward.ether_shost, oface->addr, 6);//Umm might be oface->addr
              eforward.ether_type = htons(ETHERTYPE_IP);
              //TTL has been decremented, checksum should be to
              //So just send it
              unsigned int flen = (sizeof(struct sr_ethernet_hdr) + ntohs(ip_packet->ip_len));
              //printf("Size of flen: %d\n", flen);
              uint8_t freply[flen];
              memcpy(freply, &eforward, sizeof(struct sr_ethernet_hdr));
              memcpy((freply + sizeof(eforward)), ip_packet, ntohs(ip_packet->ip_len));
              //printf("HA found in cache, forwarding packet\n");
              sr_send_packet(sr, freply, flen, oface->name);
              compare = 1;
              break;
            }
            temp = temp->next;
          }
          if(!compare)//Reusing compare as a flag
          {
            //printf("Didnt find in Cache, sending arp request\n");
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
            memcpy(arpReq.ar_sha, oface->addr, 6);
            memset(arpReq.ar_tha, 0x0000, 6 * sizeof(arpReq.ar_tha[0]));//Target all 0s from BZhang
            arpReq.ar_sip = oface->ip;

            //printf("Send iP = %lu\n", (unsigned long) sendIP.s_addr);
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

          if(compare)//If we found it in the cache, ha has been set, ok to send
          {
            return;
            
          }
          else//If we didnt find ha in cache, add it to queue
          {
            //printf("Not in cache, adding to queue\n");
            int j;
            for(j = 0; j < 10; j++)
            {
              if(queue[j].header.ip_ttl == 0)
              {
                memcpy(&queue[j], ip_packet, ntohs(ip_packet->ip_len));
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
 void addList(uint8_t *ha, struct in_addr ip, char * inteface)
 {
  //printf("Running add list\n");
    struct node *temp = root;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t life = tv.tv_sec;
    int flag = 1;
    
    //printf("iMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ha[0], ha[1], ha[2], ha[3], ha[4], ha[5]);
    //printf("AddList IP: %s\t\t\n", inet_ntoa(ip));
    while(temp)
    {
      //If its in our list, but marked dead reset ttl, bring back to life
      
      //printf("lMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", temp->ha[0], temp->ha[1], temp->ha[2], temp->ha[3], temp->ha[4], temp->ha[5]);
      if(memcmp(temp->ha, ha, 6) == 0)
      {
        //printf("Packet life reset\n");
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
      memcpy(&next->ip, &ip, sizeof(struct in_addr));
      //printf("Node IP: %s\t\t\n", inet_ntoa(next->ip));
      next->name = inteface;
      temp->next = next;
      //printf("Packet added to cache\n");
    }
 }


 void cleanList()
 {
  //printf("Running clean list\n");
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
        //printf("Marking packet as expired\n");
      }
      temp = temp->next;
    }
  
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
