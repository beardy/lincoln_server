
#ifndef DBINTERFACE_H
#define DBINTERFACE_H

#include <mysql++/mysql++.h>

class DatabaseInterface
{
     mysqlpp::String test;
     public:

     mysqlpp::Connection conn;

     int EstablishConnection();
     void InsertString();


};

#endif
