#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h> //arp헤더
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <netinet/in.h> //htons: 엔디안 변경
#include <pcap.h> //pcap 헤더

struct eth_hdr{ //이더넷 헤더
        unsigned char h_dest[6]; //이더넷 목적지 주소 6바이트
        unsigned char h_source[6]; //이더넷 출발지 주소 6바이트
        unsigned short h_type; //다음 패킷 타입 정보 2바이트
} __attribute__((packed));

struct arp_hdr{ //arp헤더
        unsigned short ar_hrd; //하드웨어 주소 타입. 이더넷은 1
        unsigned short ar_pro; //프로토콜 타입. IP는 0x0800
        unsigned char  ar_hln; //하드웨어 주소 길이 1바이트. MAC주소 길이는 6
        unsigned char  ar_pln; //프로토콜 주소 길이 1바이트. IP주소 길이는 4
        unsigned short ar_op; //op코드. 요청or응답 패킷 확인. ARP요청0001 응답0002
        unsigned char  ar_sha[6]; //출발지 MAC주소
        unsigned char  ar_sip[4];  //출발지 IP주소
        unsigned char  ar_tha[6]; //목적지 MAC주소(이걸 채우려고 ARP쓰므로 처음엔 비어있다)
        unsigned char  ar_tip[4]; //목적지 IP주소
} __attribute__((packed));

static unsigned char g_buf[sizeof(struct eth_hdr)+sizeof(struct arp_hdr)]; //패킷 총 길이

int main(int argc, char *argv[]) {
        struct eth_hdr ether;
        struct arp_hdr arp;

        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        int i;

            /* Open the output device */
        if((fp= pcap_open_live(argv[1],    // name of the device
                100,    // portion of the packet to capture (only the first 100 bytes)
                PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                1000,   // read timeout
                errbuf  // error buffer
                )) == NULL)
        {
                fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
                return -1;
        }

        //이더넷의 목적지 주소 6바이트를 브로드캐스트로 채움
        ether.h_dest[0] = 0xff;
        ether.h_dest[1] = 0xff;
        ether.h_dest[2] = 0xff;
        ether.h_dest[3] = 0xff;
        ether.h_dest[4] = 0xff;
        ether.h_dest[5] = 0xff;

        //이더넷 출발지 주소 6바이트. 어차피 내가 만드는 헤더라 임의로
        ether.h_source[0] = 0x00;
        ether.h_source[1] = 0x0a;
        ether.h_source[2] = 0x29;
        ether.h_source[3] = 0xf7;
        ether.h_source[4] = 0x62;
        ether.h_source[5] = 0x11;

        //short형 호스트 바이트 순서 데이터를 네트워크 바이트 순서값으로 변경(호스트 엔디안 맞춤)
        ether.h_type = htons(0x0806);

        arp.ar_hrd = htons(0x0001); //하드웨어 주소 타입-이더넷은 1
        arp.ar_pro = htons(0x0800); //프로토콜 주소 타입-IP는 0x0800
        arp.ar_hln = 0x06; //하드웨어 주소 길이-MAC주소 길이 6
        arp.ar_pln = 0x04; //프로토콜 주소 길이-IP 주소 길이 4
        arp.ar_op  = htons(0x0001); //op코드-ARP요청 0x0001

        //출발지 MAC주소-내가 헤더 만들고 있으니까 임의로 채움
        arp.ar_sha[0] = 0x00;
        arp.ar_sha[1] = 0x0a;
        arp.ar_sha[2] = 0x29;
        arp.ar_sha[3] = 0xf7;
        arp.ar_sha[4] = 0x62;
        arp.ar_sha[5] = 0x11;

        //출발지 IP주소
        arp.ar_sip[0] = 0xc0;
        arp.ar_sip[1] = 0xa8;
        arp.ar_sip[2] = 0x99;
        arp.ar_sip[3] = 0x33;

        //목적지 MAC주소-처음 통신할 때는 비어있다
        arp.ar_tha[0] = 0x00;
        arp.ar_tha[1] = 0x00;
        arp.ar_tha[2] = 0x00;
        arp.ar_tha[3] = 0x00;
        arp.ar_tha[4] = 0x00;
        arp.ar_tha[5] = 0x00;

        //목적지 IP주소
        arp.ar_tip[0] = 0xc0;
        arp.ar_tip[1] = 0xa8;
        arp.ar_tip[2] = 0x99;
        arp.ar_tip[3] = 0x32;

        memcpy(g_buf, &ether, sizeof(struct eth_hdr)); //헤더만큼 메모리 잡음
        memcpy(g_buf+14, &arp, sizeof(struct arp_hdr)); //헤더만큼 메모리 잡음

            /* Send down the packet */
        if (pcap_sendpacket(fp, g_buf, sizeof(struct eth_hdr)+sizeof(struct arp_hdr)) != 0) {
                fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
                return -1;
        }

        return 0;
}
