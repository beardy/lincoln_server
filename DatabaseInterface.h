
#ifndef DBINTERFACE_H
#define DBINTERFACE_H

#include <mysql++/mysql++.h>
#include "LincolnDatatypes.h"

class DatabaseInterface
{

     public:
     mysqlpp::Connection conn;

     int EstablishConnection();
     int InsertStream(const Stream& s);


};

#endif
