using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Threading;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using Microsoft.Azure.Services.AppAuthentication;
using System.Text;

namespace IncidentAnalyzerFunction
{
    public static class Function1
    {
        // note: look into changing the authorization level
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            try
            {
                string stampName = ParseStampNameFromIncidentName(req.Query["incidentName"]);
                //string startTime = ParseTimeStampFromIncidentName(req.Query["incidentName"]);
                 
                string startTime = req.Query["timeStamp"];
                log.LogInformation($"stampname is {stampName}");
                log.LogInformation($"starttime is {startTime}");

                AutoTriager autoTriager = new AutoTriager(stampName, startTime, AutoTriager.IncidentType.CanaryTwoPercent);
                autoTriager.Run();

                while (autoTriager.IsRunning)
                {
                    Thread.Sleep(1000 * 10);
                }

                string[] lines = File.ReadAllLines(autoTriager.OutputFilePath);

                StringBuilder sb = new StringBuilder();
                
                foreach (string line in lines)
                {
                    sb.AppendLine(line);
                    sb.Append("<br>");
                }
                sb.Append("<br>");
                sb.Append("-----------------Finishing Auto Triage-----------------");
                sb.Append("<br>");
                sb.Append("To manually run this query, please click the below link (you can change the timeStamp):");
                sb.Append("<br>");
                sb.Append($"https://incidentanalyzer-staging.azurewebsites.net/api/Function1?incidentName={stampName}&timeStamp={startTime}");

                string responseMessage = sb.ToString();
                return new OkObjectResult(responseMessage);
            }
            catch (Exception ex)
            {
                log.LogInformation($"Encountered exception {ex.ToString()}");
                return new OkObjectResult($"Encountered exception {ex.ToString()}");
            }
            
        }

        public static string ParseStampNameFromIncidentName(string incidentName)
        {
            if (String.IsNullOrEmpty(incidentName))
            {
                throw new ArgumentNullException("Incident name");
            }

            int stampNameLength = 17; // standard length of stamp name for stamps in format waws-prod-xx#-###
            if (incidentName.Contains("euap", StringComparison.OrdinalIgnoreCase))
            {
                stampNameLength = 21;
            }
            else if (incidentName.Contains("msftint", StringComparison.OrdinalIgnoreCase))
            {
                stampNameLength = 24;
            }

            int start = incidentName.IndexOf("waws");
            return incidentName.Substring(start, stampNameLength);
        }

        //public static string ParseTimeStampFromIncidentName(string incidentName)
        //{
        //    int startIndex = incidentName.IndexOf("StartTime:") + "StartTime:".Length;
        //    return incidentName.Substring(startIndex).Trim();
        //}
    }
}
