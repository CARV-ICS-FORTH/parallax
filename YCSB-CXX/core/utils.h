//
//  utils.h
//  YCSB-C
//
//  Created by Jinglei Ren on 12/5/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#ifndef YCSB_C_UTILS_H_
#define YCSB_C_UTILS_H_

#include <cstdint>
#include <random>
#include <algorithm>
#include <exception>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <assert.h>
#include <linux/if.h>
#include <linux/sockios.h>

namespace utils {

const uint64_t kFNVOffsetBasis64 = 0xCBF29CE484222325;
const uint64_t kFNVPrime64 = 1099511628211;

inline uint64_t FNVHash64(uint64_t val) {
  uint64_t hash = kFNVOffsetBasis64;

  for (int i = 0; i < 8; i++) {
    uint64_t octet = val & 0x00ff;
    val = val >> 8;

    hash = hash ^ octet;
    hash = hash * kFNVPrime64;
  }
  return hash;
}

inline uint64_t Hash(uint64_t val) { return FNVHash64(val); }

inline unsigned short hashMacAddress(unsigned char* mac)
{
  unsigned short hash = 0;
  for(unsigned int i = 0; i < 6; i++)    
    hash += ( mac[i] << (( i & 1 ) * 8 )); 
  return hash;    
} 

inline unsigned getMacHash(void)
{ 
  unsigned mac1 = 0, mac2 = 0;
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if(sock < 0){ 
    assert(0);
    return 0;  
  }

  // enumerate all IP addresses of the system         
  struct ifconf conf;
  char ifconfbuf[128 * sizeof(struct ifreq)];
  memset(ifconfbuf, 0, sizeof(ifconfbuf));
  conf.ifc_buf = ifconfbuf;
  conf.ifc_len = sizeof( ifconfbuf );

  if(ioctl(sock, SIOCGIFCONF, &conf)){    
    assert(0);    
    return 0;
  }    

  // get MAC address        
  bool foundMac1 = false;   
  struct ifreq* ifr;

  for(ifr = conf.ifc_req; (char*)ifr < (char*)conf.ifc_req + conf.ifc_len; ifr++){
    if(ifr->ifr_addr.sa_data == (ifr+1)->ifr_addr.sa_data)
      continue;  // duplicate, skip it     
    if(ioctl(sock, SIOCGIFFLAGS, ifr))
      continue;  // failed to get flags, skip it
    if(ioctl(sock, SIOCGIFHWADDR, ifr) == 0){ 
      if(!foundMac1){
        foundMac1 = true;    
        mac1 = hashMacAddress((unsigned char*)&(ifr->ifr_addr.sa_data));
      }else{
        mac2 = hashMacAddress((unsigned char*)&(ifr->ifr_addr.sa_data));
        break;    
      }   
    }    
  }    

  close(sock);
  return mac1 + mac2;
} 

inline double RandomDouble(double min = 0.0, double max = 1.0) {
  static std::default_random_engine generator(getMacHash());
  static std::uniform_real_distribution<double> uniform(min, max);
  return uniform(generator);
}

///
/// Returns an ASCII code that can be printed to desplay
///
inline char RandomPrintChar() {
  return rand() % 94 + 33;
}

class Exception : public std::exception {
 public:
  Exception(const std::string &message) : message_(message) { }
  const char* what() const noexcept {
    return message_.c_str();
  }
 private:
  std::string message_;
};

inline bool StrToBool(std::string str) {
  std::transform(str.begin(), str.end(), str.begin(), ::tolower);
  if (str == "true" || str == "1") {
    return true;
  } else if (str == "false" || str == "0") {
    return false;
  } else {
    throw Exception("Invalid bool string: " + str);
  }
}

inline std::string Trim(const std::string &str) {
  auto front = std::find_if_not(str.begin(), str.end(), [](int c){ return std::isspace(c); });
  return std::string(front, std::find_if_not(str.rbegin(), std::string::const_reverse_iterator(front),
      [](int c){ return std::isspace(c); }).base());
}

} // utils

#endif // YCSB_C_UTILS_H_
