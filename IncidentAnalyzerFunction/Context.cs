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
            { "bay", "wawswus" },
            { "blu", "wawseus" },
            { "bm1", "wawseas" },
            { "bn1", "wawseus" },
            { "brse", "wawscus" },
            { "cbr20", "wawseas" },
            { "cbr21", "wawseas" },
            { "ch1", "wawscus" },
            { "chw", "wawsweu" },
            { "cpt20", "wawseas" },
            { "cq1", "wawscus" },
            { "cw1", "wawsneu" },
            { "cy4", "wawscus" },
            { "db3", "wawsneu" },
            { "dm1", "wawscus" },
            { "dxb", "wawseas" },
            { "euapbn1", "wawseus" },
            { "euapdm1", "wawscus" },
            { "fra", "wawsweu" },
            { "hk1", "wawseas" },
            { "jinc", "wawseas" },
            { "jnb21", "wawseas" },
            { "jinw", "wawseas" },
            { "kw1", "wawseas" },
            { "ln1", "wawsneu" },
            { "ma1", "wawseas" },
            { "ml1", "wawseas" },
            { "mrs", "wawsweu" },
            { "msftbay", "wawswus" },
            { "msftblu", "wawseus" },
            { "msftdb3", "wawsneu" },
            { "msfthk1", "wawseas" },
            { "msftintch1", "wawseus"},
            { "msftintdm3", "wawscus" },
            { "msftinthk1", "wawseas" },
            { "msftintsg1", "wawseas" },
            { "msftintsn1", "wawscus" },
            { "mwh", "wawswus" },
            { "os1", "wawseas" },
            { "osl", "wawsweu" },
            { "par", "wawsweu" },
            { "pn1", "wawseas" },
            { "ps1", "wawseas" },
            { "qac", "wawsneu" },
            { "se1", "wawseas" },
            { "sec", "wawsneu" },
            { "ses", "wawsneu" },
            { "sg1", "wawseas" },
            { "sn1", "wawscus" },
            { "svg", "wawsweu" },
            { "sy3", "wawseas" },
            { "ty1", "wawseas" },
            { "usw3", "wawswus" },
            { "xyz", "wawscus" },
            { "yq1", "wawseus" },
            { "yt1", "wawscus" },
            { "zrh", "wawsweu" }
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
            string[] stampLocationParts = StampName.Split('-');

            return stampLocationParts[2];
        }

        public KustoConnectionStringBuilder GetKustoConnectionString()
        {
            var serviceUri = String.Format("https://{0}.kusto.windows.net/{1};Fed=true", Cluster, Database);
            return new KustoConnectionStringBuilder(serviceUri).WithAadUserManagedIdentity("75ef2f23-abca-48b4-bd61-e7714b19c55c");
        }

    }
}
