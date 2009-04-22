#ifndef LINCOLN_DATATYPES_H
#define LINCOLN_DATATYPES_H


#include <arpa/inet.h>

struct eqstr
{
  bool operator()(const char* s1, const char* s2) const
  {
    return strcmp(s1, s2) == 0;
  }
};


template< typename T_TypeToHash >
struct SizeTCastHasher
{
  size_t operator()( const T_TypeToHash& i_TypeToHash ) const
  {
      return size_t( i_TypeToHash );
  }
};

 struct Window
 {
     u_short id;
     u_short stream_id;

     time_t start_time;
     time_t end_time;
     int num_packets_incoming;
     int num_packets_outgoing;

     int size_packets_incoming;
     int size_packets_outgoing;

 };


 struct Stream
 {
     u_short id;
     in_addr raw_ip_incoming;
     in_addr raw_ip_outgoing;
     u_short port_incoming;
     u_short port_outgoing;

     time_t last_time;

     Window current_window;

 };

struct StreamHasher
{
  size_t operator()( const Stream& s ) const
  {
      return 1;
      //return size_t( i_TypeToHash );
  }
};


 struct SameStream
{
    bool operator()(Stream s1, Stream s2) const
    {
        return( s1.raw_ip_incoming.s_addr == s2.raw_ip_incoming.s_addr &&
            s1.port_incoming   == s2.port_incoming   &&
            s1.raw_ip_outgoing.s_addr == s2.raw_ip_outgoing.s_addr &&
            s1.port_outgoing   == s2.port_outgoing   );
    }
};

 struct SameWindow
{
    bool operator()(Window w1, Window w2) const
    {
        return( w1.stream_id == w2.stream_id );
    }
};


struct StreamKey
 {
     in_addr raw_ip_incoming;
     in_addr raw_ip_outgoing;
     u_short port_incoming;
     u_short port_outgoing;
 };

 struct LessStreamKey
 {
     bool operator()(const StreamKey& s1, const StreamKey& s2) const
     {
         return( s1.raw_ip_incoming.s_addr < s2.raw_ip_incoming.s_addr ||
            s1.port_incoming   < s2.port_incoming   ||
            s1.raw_ip_outgoing.s_addr < s2.raw_ip_outgoing.s_addr ||
            s1.port_outgoing  < s2.port_outgoing );

     }
 };

 #endif

