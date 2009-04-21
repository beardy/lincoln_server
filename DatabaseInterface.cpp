
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
        //t.integer "raw_ip_incoming"
        //t.integer "raw_ip_outgoing"
        //t.integer "port_incoming"
        //t.integer "port_outgoing"
        //t.integer "protocol"
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
        }

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

     mysqlpp::String q;

     q = "INSERT INTO streams VALUES(NULL, '4414187441', '2089506384', '110', '25', '89');";

     query.execute(q);

     return query.insert_id();

}
