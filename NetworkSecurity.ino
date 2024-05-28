/********************************************************
 Function   : Progetto esame Network Security
 Studente   : Sergio Parigi
 Derivato da https://github.com/RicardoOliveira/FriendDetector.git
 
*********************************************************/

#include "./esppl_functions.h"

/*
 * Define you friend's list size here
 */
#define LIST_SIZE 3
/*
 * This is your friend's MAC address list
 */
uint8_t friendmac[LIST_SIZE][ESPPL_MAC_LEN] = {
   {0xD0, 0x3F, 0xAA, 0xDC, 0x36, 0x23}
  ,{0x23, 0x36, 0xD0, 0xDC, 0x3F, 0xAA}
  ,{0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
  };
/*
 * This is your friend's name list
 * put them in the same order as the MAC addresses
 */
String friendname[LIST_SIZE] = {
   "Sergio"
   ,"oigreS"
  ,"Friend 2"
  };

//the led is connected to pin D2
const int ledFriend = 4;
bool friend_detect = false;
int last_rssi=-9999;

/********************************************************
 Function   : print_info
 type       : void
 parameter  : info *esppl_frame_info
 description: print the type|subtype of frame sniffed
                that has addr of a friend
*********************************************************/
void print_info(esppl_frame_info *info) {
    Serial.printf("[");
    for (int i=0;i<6;i++)
      Serial.printf(" 0x%02x",info->sourceaddr[i]);
    Serial.printf("] -> [");
    for (int i=0;i<6;i++)
      Serial.printf(" 0x%02x",info->receiveraddr[i]);
    Serial.printf("]\n");

    switch (info->frametype) {
        case ESPPL_MANAGEMENT:
            Serial.printf("Frame Type: Management\n");
            switch (info->framesubtype) {
                case ESPPL_MANAGEMENT_ASSOCIATION_REQUEST:    Serial.printf("Subtype: Association Request\n"); break;
                case ESPPL_MANAGEMENT_ASSOCIATION_RESPONSE:   Serial.printf("Subtype: Association Response\n"); break;
                case ESPPL_MANAGEMENT_REASSOCIATION_REQUEST:  Serial.printf("Subtype: Reassociation Request\n"); break;
                case ESPPL_MANAGEMENT_REASSOCIATION_RESPONSE: Serial.printf("Subtype: Reassociation Response\n"); break;
                case ESPPL_MANAGEMENT_PROBE_REQUEST:          Serial.printf("Subtype: Probe Request\n"); break;
                case ESPPL_MANAGEMENT_PROBE_RESPONSE:         Serial.printf("Subtype: Probe Response\n"); break;
                case ESPPL_MANAGEMENT_TIMMING_ADVERTISEMENT:  Serial.printf("Subtype: Timing Advertisement\n"); break;
                case ESPPL_MANAGEMENT_RESERVED1:              Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_MANAGEMENT_BEACON:                 Serial.printf("Subtype: Beacon\n"); break;
                case ESPPL_MANAGEMENT_ATIM:                   Serial.printf("Subtype: ATIM\n"); break;
                case ESPPL_MANAGEMENT_DISASSOCIATION:         Serial.printf("Subtype: Disassociation\n"); break;
                case ESPPL_MANAGEMENT_AUTHENTICATION:         Serial.printf("Subtype: Authentication\n"); break;
                case ESPPL_MANAGEMENT_DEAUTHENTICATION:       Serial.printf("Subtype: Deauthentication\n"); break;
                case ESPPL_MANAGEMENT_ACTION:                 Serial.printf("Subtype: Action\n"); break;
                case ESPPL_MANAGEMENT_ACTION_NO_ACK:          Serial.printf("Subtype: Action No Ack\n"); break;
                case ESPPL_MANAGEMENT_RESERVED2:              Serial.printf("Subtype: Reserved\n"); break;
                default:                                      Serial.printf("Subtype: Unknown\n"); break;
            }
            break;
        case ESPPL_CONTROL:
            Serial.printf("Frame Type: Control\n");
            switch (info->framesubtype) {
                case ESPPL_CONTROL_RESERVED1:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_RESERVED2:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_RESERVED3:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_RESERVED4:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_RESERVED5:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_RESERVED6:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_RESERVED7:                 Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_CONTROL_CONTROL_WRAPPER:           Serial.printf("Subtype: Control Wrapper\n"); break;
                case ESPPL_CONTROL_BLOCK_ACK_REQUEST:         Serial.printf("Subtype: Block Ack Request\n"); break;
                case ESPPL_CONTROL_BLOCK_ACK:                 Serial.printf("Subtype: Block Ack\n"); break;
                case ESPPL_CONTROL_PS_POLL:                   Serial.printf("Subtype: PS Poll\n"); break;
                case ESPPL_CONTROL_RTS:                       Serial.printf("Subtype: RTS\n"); break;
                case ESPPL_CONTROL_CTS:                       Serial.printf("Subtype: CTS\n"); break;
                case ESPPL_CONTROL_ACK:                       Serial.printf("Subtype: ACK\n"); break;
                case ESPPL_CONTROL_CF_END:                    Serial.printf("Subtype: CF End\n"); break;
                case ESPPL_CONTROL_CF_END_CF_ACK:             Serial.printf("Subtype: CF End CF Ack\n"); break;
                default:                                      Serial.printf("Subtype: Unknown\n"); break;
            }
            break;
        case ESPPL_DATA:
            Serial.printf("Frame Type: Data\n");
            switch (info->framesubtype) {
                case ESPPL_DATA_DATA:                         Serial.printf("Subtype: Data\n"); break;
                case ESPPL_DATA_DATA_CF_ACK:                  Serial.printf("Subtype: Data CF Ack\n"); break;
                case ESPPL_DATA_DATA_CF_POLL:                 Serial.printf("Subtype: Data CF Poll\n"); break;
                case ESPPL_DATA_DATA_CF_ACK_CF_POLL:          Serial.printf("Subtype: Data CF Ack CF Poll\n"); break;
                case ESPPL_DATA_NULL:                         Serial.printf("Subtype: Null\n"); break;
                case ESPPL_DATA_CF_ACK:                       Serial.printf("Subtype: CF Ack\n"); break;
                case ESPPL_DATA_CF_POLL:                      Serial.printf("Subtype: CF Poll\n"); break;
                case ESPPL_DATA_CF_ACK_CF_POLL:               Serial.printf("Subtype: CF Ack CF Poll\n"); break;
                case ESPPL_DATA_QOS_DATA:                     Serial.printf("Subtype: QoS Data\n"); break;
                case ESPPL_DATA_QOS_DATA_CF_ACK:              Serial.printf("Subtype: QoS Data CF Ack\n"); break;
                case ESPPL_DATA_QOS_DATA_CF_ACK_CF_POLL:      Serial.printf("Subtype: QoS Data CF Ack CF Poll\n"); break;
                case ESPPL_DATA_QOS_NULL:                     Serial.printf("Subtype: QoS Null\n"); break;
                case ESPPL_DATA_RESERVED1:                    Serial.printf("Subtype: Reserved\n"); break;
                case ESPPL_DATA_QOS_CF_POLL:                  Serial.printf("Subtype: QoS CF Poll\n"); break;
                case ESPPL_DATA_QOS_CF_ACK_CF_POLL:           Serial.printf("Subtype: QoS CF Ack CF Poll\n"); break;
                default:                                      Serial.printf("Subtype: Unknown\n"); break;
            }
            break;
        default:
            Serial.printf("Frame Type: Unknown\n");
            break;
    }
}

/********************************************************
 Function   : maccmp
 type       : bool
 parameter  : int8_t *mac1, uint8_t *mac2
 description: compare two mac return true if equal
*********************************************************/
bool maccmp(uint8_t *mac1, uint8_t *mac2) {
  for (int i=0; i < ESPPL_MAC_LEN; i++) {
    if (mac1[i] != mac2[i]) {
      return false;
    }
  }
  return true;
}

/********************************************************
 Function   : cb
 type       : void
 parameter  : esppl_frame_info *info
 description: callback function from esppl
*********************************************************/
void cb(esppl_frame_info *info) {
  char friend_beaviour[20];
  
  for (int i=0; i<LIST_SIZE; i++) {
    if (maccmp(info->sourceaddr, friendmac[i]) || maccmp(info->receiveraddr, friendmac[i])) {
      if (last_rssi < info->rssi)
        sprintf(friend_beaviour,"APPROACHING");
      else  
        sprintf(friend_beaviour,"LEAVING");
      last_rssi=info->rssi;


      if ((info->ssid_length>0) && (info->channel>0))
          Serial.printf("[CH:%x][SSID %s] %s is %s! :)\n", info->channel, info->ssid,friendname[i].c_str(),friend_beaviour);
      else 
        if (info->ssid_length>0)
          Serial.printf("[SSID:%s] %s is %s! :)\n", info->ssid, friendname[i].c_str(),friend_beaviour);
        else
          if (info->channel>0)
            Serial.printf("[CH:%x] %s is %s! :)\n", info->channel, friendname[i].c_str(),friend_beaviour);
          else
            Serial.printf("%s is %s! :)\n",friendname[i].c_str(),friend_beaviour);
      Serial.printf("Power %dBm\n",info->rssi);
      print_info(info);
      Serial.printf("\n");

      friend_detect=true;
      
    }
  }
}
/********************************************************
 Function   : led_up
 type       : void
 parameter  : none
 description: light up the led
*********************************************************/
void led_up()
{
    analogWrite(ledFriend, 1023);
 
}
/********************************************************
 Function   : led_dimming
 type       : void
 parameter  : none
 description: dim to off the led
*********************************************************/
void led_dimming()
{
    for (int j=1023; j>0; j-= 25) {
      analogWrite(ledFriend, j);
      delay(10);
    }
    analogWrite(ledFriend, 0);
}
/********************************************************
 Function   : setup
 type       : void
 parameter  : none
 description: setup of board
*********************************************************/
void setup() {
  delay(500);
  Serial.begin(115200);
  esppl_init(cb);
  Serial.printf("\nNetwork Security\nAA 2023/24\n\nSergio Parigi 138771\n\n");

  pinMode(ledFriend, OUTPUT);

  for (int k=0; k<3; k++) {
    led_up();
    delay(10); 
    led_dimming();
  }
  
  
}


/********************************************************
 Function   : loop
 type       : void
 parameter  : none
 description: loop function
*********************************************************/
void loop() {
  esppl_sniffing_start();
  while (true) {
    for (int i = ESPPL_CHANNEL_MIN; i <= ESPPL_CHANNEL_MAX; i++ ) {
      esppl_set_channel(i);
      while (esppl_process_frames()) {


      }

      if (friend_detect) {
        
        led_up();
        delay(10); 
        led_dimming();

        friend_detect=false;
      }
    }
  }  
}
