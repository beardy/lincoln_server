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
// Config.h ~ This class loads and stores our configuration for the server.

#ifndef LINCOLN_CONFIG_H
#define LINCOLN_CONFIG_H

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

struct IPRange
{
    bool isRange;
    string ip1;
    string ip2;
};



class Config
{
private:
    vector<IPRange> local_ips;

public:
    int window_time;
    string device;
    string database_name;
    string server;
    string user;
    string pass;

    bool IsLocal( string ip );

    void Load( const char* filename );



};

 #endif
