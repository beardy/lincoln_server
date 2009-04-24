// LINCOLN_SERVER
// ~~ This program is responsible for sniffing traffic on the host machine, aggregating it over a time period,
// ~~ and uploading into the database. The client side is reponsible for generating all visualizations and analysis.
//
// Team: The Beard Progression-
// Mark Calnon
// Adam Nagle
// Brien Smith-Martinez
// Jim Vallandingham
//
// DatabaseInterface.cpp ~ This class handles communication with the mysql server. Uses mysql and mysql++ libs.

#include "DatabaseInterface.h"
#include <stdio.h>
using namespace std;

int DatabaseInterface::EstablishConnection(const char* db, const char* server, const char* user, const char* pass)
{

    conn = mysqlpp::Connection(false);
    if (conn.connect(db, server, user, pass))
    {
        return 0;
    }
    else
    {
        cerr << "DB connection failed: " << conn.error() << endl;
        return 1;
    }



}

int DatabaseInterface::InsertStream(const Stream& s)
{
    mysqlpp::Query query = conn.query();

    char buff[256];

    sprintf( buff, "INSERT INTO streams VALUES(NULL, '%u', '%u', '%d', '%d', 6 );",
    s.raw_ip_incoming.s_addr, s.raw_ip_outgoing.s_addr, ntohs(s.port_incoming), ntohs(s.port_outgoing) );


    mysqlpp::SimpleResult result = query.execute(buff);
    printf( "%s \n", result.info());

    return query.insert_id();

}

int DatabaseInterface::InsertWindow(const Window& w)
{
    mysqlpp::Query query = conn.query();



    query << "INSERT INTO windows VALUES(NULL, '" << w.stream_id << "' , '"
    << mysqlpp::DateTime(w.start_time) << "' , '" << mysqlpp::DateTime(w.end_time) << "' , '"
    << w.num_packets_incoming  << "' , '" << w.num_packets_outgoing << "' , '"
    << w.size_packets_incoming << "' , '" << w.size_packets_outgoing << "' );";

    mysqlpp::SimpleResult result = query.execute();
    printf( "%s \n", result.info());

    return query.insert_id();

}
