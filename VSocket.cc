/**
  *  Universidad de Costa Rica
  *  ECCI
  *  CI0123 Proyecto integrador de redes y sistemas operativos
  *  2026-ii
  *  Grupos: 2 y 5
  *
  *******   VSocket base class implementation
  *
  * (Fedora version)
  *
 **/

#include <sys/socket.h>
#include <arpa/inet.h>		// ntohs, htons
#include <stdexcept>            // runtime_error
#include <cstring>		// memset
#include <netdb.h>		// getaddrinfo, freeaddrinfo
#include <unistd.h>		// close
#include <iostream>
/*
#include <cstddef>
#include <cstdio>

//#include <sys/types.h>
*/
#include "VSocket.h"


/**
  *  Class creator (constructor)
  *     use Unix socket system call
  *
  *  @param     char t: socket type to define
  *     's' for stream
  *     'd' for datagram
  *  @param     bool ipv6: if we need a IPv6 socket
  *
 **/
void VSocket::Init( char t, bool IPv6 ){


   int domain,socketType,st ;

   this->IPv6 = IPv6;
   this->type=t;

   if(this->IPv6){
      domain = AF_INET6;
   }else{
      domain = AF_INET;
   }

   if(type=='s'){
      socketType=SOCK_STREAM;
   }else if(type=='d'){
      socketType=SOCK_DGRAM;
   }else{
      throw std::runtime_error( "INVALID TYPE" );
   }

   st = socket(domain, socketType, 0);

   if ( -1 == st ) {
      throw std::runtime_error( "VSocket::Init, (reason)" );
   }
   
   sockId=st;
}

void VSocket::Init(int id){
   this->sockId=id;
   this->IPv6=false;
   this->type='s';

}

/**
  * Class destructor
  *
 **/
VSocket::~VSocket() {

   this->Close();

}


/**
  * Close method
  *    use Unix close system call (once opened a socket is managed like a file in Unix)
  *
 **/
void VSocket::Close(){
   int st = -1;

   if (sockId==-1){
      return;
   }else{
      st = close(this->sockId);
      if ( -1 == st ) {
         throw std::runtime_error( "VSocket::Close()" );
      }
      sockId=-1;
   }
}


/**
  * TryToConnect method
  *   use "connect" Unix system call
  *
  * @param      char * host: host address in dot notation, example "10.84.166.62"
  * @param      int port: process address, example 80
  *
 **/
int VSocket::TryToConnect( const char * hostip, int port ) {

   int st = -1;
   if (!this->IPv6){
   struct sockaddr_in host4;
   memset((char*) &host4, 0, sizeof (host4));
   host4.sin_family=AF_INET;
   st=inet_pton(AF_INET, hostip, &host4.sin_addr);
   if(st<=0){
      throw(std::runtime_error("VSocket::TryToConnect, inet_pton"));
   }
   host4.sin_port =htons (port);
   st = connect(sockId, (sockaddr *) &host4, sizeof (host4));
   }else{

      struct sockaddr_in6  host6;
      struct sockaddr * ha;

      memset( &host6, 0, sizeof( host6 ) );
      host6.sin6_family = AF_INET6;
      st = inet_pton( AF_INET6, hostip, &host6.sin6_addr );
      if ( 0 >= st ) {
         throw std::runtime_error( "Socket::Connect( const char *, int ) [inet_pton]" );
      }
      host6.sin6_port = htons( port );
      ha = (struct sockaddr *) &host6;
      st = connect( sockId, ha, sizeof(host6));
   }

   if ( -1 == st ) {
      throw std::runtime_error( "VSocket::TryToConnect" );
   }

   return st;

}


/**
  * TryToConnect method
  *   use "connect" Unix system call
  *
  * @param      char * host: host address in dns notation, example "os.ecci.ucr.ac.cr"
  * @param      char * service: process address, example "http"
  *
 **/
int VSocket::TryToConnect( const char *host, const char *service ) {
   int st = -1;
   struct addrinfo hints, *result, *rp;

   memset(&hints, 0, sizeof(struct addrinfo));
   if (this->IPv6) {
      hints.ai_family = AF_INET6;    /* Allow IPv4 or IPv6 */
   } else {
      hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
   }
   hints.ai_socktype = SOCK_STREAM; 
   hints.ai_flags = 0;
   hints.ai_protocol = 0; 

   st = getaddrinfo( host, service, &hints, &result );
   if(st!=0){
      std::cerr << "getaddrinfo st = " << st
              << ": " << gai_strerror(st) << std::endl;
      throw std::runtime_error( "VSocket::TryToConnect( const char *, const char * ) [getaddrinfo]" );
   }

   for ( rp = result; rp; rp = rp->ai_next ) {
      st = connect( sockId, rp->ai_addr, rp->ai_addrlen );
      if ( 0 == st )
         break;
   }

   freeaddrinfo( result );


   if (st==-1){
      throw std::runtime_error( "VSocket::TryToConnect" );
   }
   return st;

}


/**
  *  method
  *    use "bind" Unix system call (man 3 bind) (server mode)
  *
  * @param      int port: bind a unamed socket to a port defined in sockaddr structure
  *
  *  Links the calling process to a service at port
  *
 **/
int VSocket::Bind( int port ) {
   int st = -1;

   struct sockaddr_in addr;
   addr.sin_family = AF_INET;
   addr.sin_port =htons(port);
   addr.sin_addr.s_addr = htonl(INADDR_ANY);

   st=bind(this->sockId,(sockaddr*)&addr, sizeof(addr));
   
   if (st==-1){
      throw std::runtime_error( "VSocket::BIND(int) [bind]" );
   }

   return st;

}

int VSocket::MarkPassive( int backlog ) {
   int st = -1;

   st=listen(this->sockId,backlog);

   if (st==-1){
      throw std::runtime_error( "VSocket::MarkPassive(int) [listen]" );
   }

   return st;

}

int VSocket::Shutdown( int how ) {
   int st = -1;

   st=shutdown(this->sockId,how);

   if (st==-1){
      throw std::runtime_error( "VSocket::Shutdown(int) [shutdown]" );
   }

   return st;

}



/**
  *  sendTo method
  *
  *  @param	const void * buffer: data to send
  *  @param	size_t size data size to send
  *  @param	void * addr address to send data
  *
  *  Send data to another network point (addr) without connection (Datagram)
  *
 **/
size_t VSocket::sendTo( const void * buffer, size_t size, void * addr ) {
   int st = -1;

   st=sendto(this->sockId, buffer, size, 0, (sockaddr*) addr, sizeof(struct sockaddr_in));

   if (st==-1){
      throw std::runtime_error( "VSocket::SEND(int) [send]" );
   }

   return st;

}


/**
  *  recvFrom method
  *
  *  @param	const void * buffer: data to send
  *  @param	size_t size data size to send
  *  @param	void * addr address to receive from data
  *
  *  @return	size_t bytes received
  *
  *  Receive data from another network point (addr) without connection (Datagram)
  *
 **/
size_t VSocket::recvFrom( void * buffer, size_t size, void * addr ) {
   int st = -1;

   socklen_t addrSize = sizeof(struct sockaddr_in);

   st=recvfrom(this->sockId, buffer, size ,0, (sockaddr*)addr, &addrSize);
   
   if (st == -1) {
        throw std::runtime_error("VSocket::recvFrom [recvfrom]");
    }
   
   return st;

}

