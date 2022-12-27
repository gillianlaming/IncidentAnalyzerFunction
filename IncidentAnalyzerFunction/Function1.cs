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
    public class Function1
    {
        [FunctionName("Function1")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            try
            {
                string stampName = ParseStampNameFromIncidentName(req.Query["incidentName"]);
                string startTime = req.Query["timeStamp"];

                if (string.IsNullOrEmpty(startTime))
                {
                    startTime = DateTime.UtcNow.ToString("s");
                }

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
                sb.AppendLine("-----------------Finishing Auto Triage-----------------");
                sb.Append("<br>");
                sb.AppendLine("To manually run this query, please click the below link (you can change the timeStamp or specify no timestamp to run for the current time):");
                sb.Append("<br>");
                sb.AppendLine($"https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={req.Query["incidentName"]}&timeStamp={startTime}");

                string responseMessage = sb.ToString();
                return new OkObjectResult(responseMessage);
            }
            catch (Exception ex)
            {
                log.LogInformation($"Encountered exception {ex.ToString()}");
                return new OkObjectResult($"Encountered exception {ex.ToString()}");
            }
            
        }

        public string ParseStampNameFromIncidentName(string incidentName)
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

            // TODO: add support for national clouds 
            int start = incidentName.IndexOf("waws");

            if (start == -1)
            {
                throw new ArgumentException("Stamp name");
            }
            return incidentName.Substring(start, stampNameLength);
        }

    }
}
