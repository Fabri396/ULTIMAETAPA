#ifndef TICA_AUTO_DISCOVERY_H
#define TICA_AUTO_DISCOVERY_H
// Zero-configuration discovery for a trusted, single-broadcast-domain laboratory.
// The first discovery reply is NOT authenticated. This is TOFU, not secure enrollment.
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <fstream>
#include <string>
#include <thread>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <vector>

namespace AutoDiscovery {
static const int PORT=2026;
static const char* REQUEST="TICAMAZON_DISCOVER_V2";
static const char* PREFIX="TICAMAZON_INT_V2\n";
struct Server { std::string ip; std::string ca; };
inline std::string readCa(){std::ifstream in("certs/siqp-trust.crt",std::ios::binary);return std::string((std::istreambuf_iterator<char>(in)),std::istreambuf_iterator<char>());}
inline bool validCa(const std::string& pem){if(pem.size()<200||pem.size()>6000)return false;BIO* bio=BIO_new_mem_buf(pem.data(),(int)pem.size());X509* cert=PEM_read_bio_X509(bio,nullptr,nullptr,nullptr);BIO_free(bio);if(!cert)return false;bool ok=X509_check_ca(cert)>0;X509_free(cert);return ok;}
inline void responder(){
 int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)throw std::runtime_error("UDP discovery socket");
 int yes=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
 sockaddr_in local{};local.sin_family=AF_INET;local.sin_port=htons(PORT);local.sin_addr.s_addr=INADDR_ANY;
 if(bind(fd,(sockaddr*)&local,sizeof(local))!=0){close(fd);throw std::runtime_error("Puerto UDP discovery 2026 ocupado");}
 std::cout<<"[INT-01] Descubrimiento UDP activo en puerto 2026"<<std::endl;
 for(;;){char buf[256]{};sockaddr_in peer{};socklen_t len=sizeof(peer);ssize_t n=recvfrom(fd,buf,sizeof(buf),0,(sockaddr*)&peer,&len);
  if(n!=(ssize_t)strlen(REQUEST)||std::memcmp(buf,REQUEST,n)!=0)continue;
  std::string ca=readCa();if(!validCa(ca))continue;
  std::string answer=std::string(PREFIX)+ca;
  sendto(fd,answer.data(),answer.size(),0,(sockaddr*)&peer,len);
 }
}
inline std::vector<in_addr> targets(){
 std::vector<in_addr> ips;in_addr broadcast{};inet_pton(AF_INET,"255.255.255.255",&broadcast);ips.push_back(broadcast);
 struct ifaddrs* ifs=nullptr;if(getifaddrs(&ifs)==0){for(auto i=ifs;i;i=i->ifa_next){if(!i->ifa_addr||!i->ifa_broadaddr||i->ifa_addr->sa_family!=AF_INET||!(i->ifa_flags&IFF_BROADCAST)||!(i->ifa_flags&IFF_UP))continue;ips.push_back(((sockaddr_in*)i->ifa_broadaddr)->sin_addr);}freeifaddrs(ifs);}return ips;
}
inline Server find(int attempts=6){
 int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)throw std::runtime_error("UDP discovery socket");
 int yes=1;setsockopt(fd,SOL_SOCKET,SO_BROADCAST,&yes,sizeof(yes));
 timeval wait{};wait.tv_sec=1;wait.tv_usec=0;setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&wait,sizeof(wait));
 for(int a=0;a<attempts;a++){
  for(auto ip:targets()){sockaddr_in dest{};dest.sin_family=AF_INET;dest.sin_port=htons(PORT);dest.sin_addr=ip;sendto(fd,REQUEST,strlen(REQUEST),0,(sockaddr*)&dest,sizeof(dest));}
  for(int i=0;i<3;i++){char buf[8192];sockaddr_in peer{};socklen_t len=sizeof(peer);ssize_t n=recvfrom(fd,buf,sizeof(buf),0,(sockaddr*)&peer,&len);
    if(n<=0)break;std::string answer(buf,(size_t)n);if(answer.compare(0,strlen(PREFIX),PREFIX)!=0)continue;
    std::string ca=answer.substr(strlen(PREFIX));if(!validCa(ca))continue;
    char ip[INET_ADDRSTRLEN]{};inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip));close(fd);return {ip,ca};
  }
 }
 close(fd);throw std::runtime_error("No se encontro el intermediario en la red local (UDP 2026)");
}
} // namespace AutoDiscovery
#endif
