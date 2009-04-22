
#ifndef DBINTERFACE_H
#define DBINTERFACE_H

#include <mysql++/mysql++.h>
#include "LincolnDatatypes.h"

class DatabaseInterface
{

     public:
     mysqlpp::Connection conn;

     int EstablishConnection(const char* db, const char* server, const char* user, const char* pass);
     int InsertStream(const Stream& s);
     int InsertWindow(const Window& w);


};

#endif
