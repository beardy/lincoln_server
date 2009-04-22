
#include "DatabaseInterface.h"
#include <stdio.h>
using namespace std;

int DatabaseInterface::EstablishConnection()
{
    // Connect to the sample database.
    const char* db = 0, *server = 0, *user = 0, *pass = "";
    db = "lincoln";
    server = "localhost";
    user = "goat";


    conn = mysqlpp::Connection(false);
    if (conn.connect(db, server, user, pass))
    {
        // ~~~This is example code:
        // Retrieve a subset of the sample stock table set up by resetdb
        // and display it.
        /*
        mysqlpp::Query query = conn.query("select item from stock");
        if (mysqlpp::StoreQueryResult res = query.store())
        {
            cout << "We have:" << endl;
            for (size_t i = 0; i < res.num_rows(); ++i)
            {
                cout << '\t' << res[i][0] << endl;
            }
        }
        else
        {
            cerr << "Failed to get item list: " << query.error() << endl;
            return 1;
        }*/

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


    //sprintf( buff, "INSERT INTO streams VALUES(NULL, '%u', '%u', '%d', '%d', %d, %d );",

    query << "INSERT INTO windows VALUES(NULL, '" << w.stream_id << "' , '"
    << mysqlpp::DateTime(w.start_time) << "' , '" << mysqlpp::DateTime(w.end_time) << "' , '"
    << w.num_packets_incoming  << "' , '" << w.num_packets_outgoing << "' , '"
    << w.size_packets_incoming << "' , '" << w.size_packets_outgoing << "' );";

    //query.execute();

   // w.start_time, w.end_time, w.num_packets_incoming, w.num_packets_outgoing, w.size_packets_incoming, w.size_packets_outgoing );

    mysqlpp::SimpleResult result = query.execute();
    printf( "%s \n", result.info());

    return query.insert_id();

}
