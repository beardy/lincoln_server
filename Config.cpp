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
// Config.cpp ~ This class loads and stores our configuration for the server.

#include "Config.h"

#include <stdlib.h>

bool Config::IsLocal( string ip )
{

  bool result = false;

  for (int i=0; i < local_ips.size(); i++)
  {

    //if single ip address

    if( local_ips[i].isRange == false )
    {

        //null-terminated cstrs causing problem here
        //if (ip == local_ips[i].ip1)
        if (ip.compare( local_ips[i].ip1) == 0 || ip.compare( local_ips[i].ip1) == -1)
        {
            result = true;
        }

    }

    //if a range of ip addresses
    // Buggy...
    //if( local_ips[i].isRange == true )
      //if ( local_ips[i].ip1 <= ip <= local_ips[i].ip2 )
        //result = true;
  }

  return result;
}


void Config::Load( const char* filename)
{

    // ## PARSING PART

    ifstream in ( filename );

    if ( in.is_open() )
    {
        string line;

        while ( getline ( in, line ) )
        {

            if( line.find("$window_time") != string::npos )
            {
                getline( in, line );
                window_time = atoi( line.c_str() );
            }
            if( line.find("$device") != string::npos )
            {
                getline( in, line );
                device = line.c_str();
            }

            if( line.find("$database_name") != string::npos )
            {
                getline( in, line );
                database_name = line;
            }

            if( line.find("$server") != string::npos )
            {
                getline( in, line );
                server = line;
            }

            if( line.find("$user") != string::npos )
            {
                getline( in, line );
                user = line;
            }

            if( line.find("$pass") != string::npos )
            {
                getline( in, line );
                pass = line;
            }


            if( line.find("$local_ips") != string::npos )
            {

                getline( in, line );

                int seperator = line.find(":");

                if( seperator != string::npos )
                {
                    // colon detected -> range

                    string ip1 = line.substr(0, seperator);
                    string ip2 = line.substr(seperator+1, 1+line.length()/2);

                    //save ip1 and ip2 as a range
                    IPRange local_ip;
                    local_ip.isRange = true;
                    local_ip.ip1 = ip1;
                    local_ip.ip2 = ip2;
                    local_ips.push_back( local_ip );
                }
                else
                {
                    // only single value
                    //save line as a single ip

                    IPRange local_ip;
                    local_ip.isRange = false;
                    local_ip.ip1 = line;

                    cout << "LOCAL IP: " << local_ip.ip1 << endl;
                    local_ips.push_back( local_ip );

                }
            }

        }
    }
    else
    {
          cerr << "Failed to load file." << endl;
    }
}
