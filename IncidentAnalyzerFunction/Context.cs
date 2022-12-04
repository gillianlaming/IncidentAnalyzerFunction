using Kusto.Data;
using Microsoft.Azure.Services.AppAuthentication;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity;
using Kusto.Ingest;

namespace IncidentAnalyzerFunction
{
    internal class Context
    {
        public string StampName { get; private set; }
        public string StartTime { get; set; }
        public string EndTime { get; set; }
        public string SiteName { get; set; }
        public string Cluster { get; set; }
        public string Database { get; set; }
        public string OutputStartTime { get; set; }
        public string OutputEndTime { get; set; }

        public Dictionary<string, string> ClusterDictionary = new Dictionary<string, string>()
        {
            { "am2", "wawsweu" },
            { "blu", "wawseus" },
            { "bn1", "wawseus" },
            { "yq1", "wawseus" },
            { "bm1", "wawseas" },
            { "hk1", "wawseas" },
            { "kw1", "wawseas" },
            { "ma1", "wawseas" },
            { "ml1", "wawseas" },
            { "os1", "wawseas" },
            { "pn1", "wawseas" },
            { "sg1", "wawseas" },
            { "sy1", "wawseas" },
            { "ty1", "wawseas" },
            { "ch1", "wawscus" },
            { "cq1", "wawscus" },
            { "cy4", "wawscus" },
            { "dm1", "wawscus" },
            { "sn1", "wawscus" },
            { "yt1", "wawscus" },
            { "db3", "wawsneu" },
            { "ln1", "wawsneu" },
            { "cw1", "wawsneu" },
            { "bay", "wawswus" },
            { "par", "wawsweu" },
            { "euapbn1", "wawseus" },
            { "euapdm1", "wawscus" },
            { "msftinthk1", "wawseas" },
            { "msftintch1", "wawseus"},
            { "msftintdm3", "wawscus" },
            { "msftintsg1", "wawseas" },
            { "dxb", "wawseas" },
            { "sy3", "wawseas" },
            { "se1", "wawseas" }
        };

        public Context(string stampName, string startTime, string endTime, string cluster, string database, string siteName = "")
        {
            StampName = stampName;
            StartTime = startTime;
            // for live incident, EndTime is when the incident happens
            EndTime = endTime;
            SiteName = siteName;

            if (string.IsNullOrEmpty(cluster))
            {
                string stampLocationCode = GetStampLocationCode();

                if (ClusterDictionary.TryGetValue(stampLocationCode, out string clusterValue))
                {
                    Cluster = clusterValue;
                }
                else
                {
                    throw new Exception("Can't find cluster");
                }
            }
            else
            {
                Cluster = cluster;
            }

            if (string.IsNullOrEmpty(database))
            {
                Database = "wawsprod";
            }
            else
            { 
                Database = database;
            }
        }

        public Context(Context c)
        {
            StampName = c.StampName;
            Cluster = c.Cluster;
            Database = c.Database;
            StartTime = c.StartTime;
            EndTime = c.EndTime;
        }

        private string GetStampLocationCode()
        {
            string stampLocationCode;
            if (StampName.Contains("euap"))
            {
                stampLocationCode = StampName.Substring(10, 7);
            }
            else if (StampName.Contains("msftint"))
            {
                stampLocationCode = StampName.Substring(10, 10);
            }
            else
            {
                stampLocationCode = StampName.Substring(10, 3);
            }

            return stampLocationCode;
        }

        public KustoConnectionStringBuilder GetKustoConnectionString()
        {
            var serviceUri = String.Format("https://{0}.kusto.windows.net/{1};Fed=true", Cluster, Database);
            return new KustoConnectionStringBuilder(serviceUri).WithAadUserManagedIdentity("75ef2f23-abca-48b4-bd61-e7714b19c55c");
        }

    }
}
