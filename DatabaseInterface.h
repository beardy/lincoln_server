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
// DatabaseInterface.h ~ This class handles communication with the mysql server. Uses mysql and mysql++ libs.

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
