
#include "Config.h"

bool Config::IsLocal( string ip )
{

  bool result = false;

  for (int i=0; i < local_ips.size(); i++)
  {

    //if single ip address
    if( local_ips[i].isRange == false )
      if (ip == local_ips[i].ip1)
          result = true;

    //if a range of ip addresses
    // Buggy...
    //if( local_ips[i].isRange == true )
      //if ( local_ips[i].ip1 <= ip <= local_ips[i].ip2 )
        //result = true;
  }

  return result;
}


void Config::Load( string filename)
{

    // ## PARSING PART

    ifstream in ( "config.txt" );

    if ( in.is_open() )
    {
        string line;

        while ( getline ( in, line ) )
        {

          int seperator = line.find(":");

          if( seperator != string::npos )
          {
            // colon detected -> range

            string ip1 = line.substr(0, seperator);
            string ip2 = line.substr(seperator+1, 1+line.length()/2);

            //save ip1 and ip2 as a range
            IPRange * local_ip = new IPRange;
            local_ip->isRange = true;
            local_ip->ip1 = ip1;
            local_ip->ip2 = ip2;

          }
          else
          {
            // only single value

            //save line as a single ip
            IPRange * local_ip = new IPRange;
            local_ip->isRange = false;
            local_ip->ip1 = line;
          }


        }

      }
}
