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
                string stampName = ParseStampNameFromIncidentName(req.Query["stampName"]);
                string startTime = req.Query["startTime"];
                log.LogInformation($"stampname is {stampName}");
                log.LogInformation($"starttime is {startTime}");

                AutoTriager autoTriager = new AutoTriager(stampName, startTime);
                autoTriager.Run();

                while (autoTriager.IsRunning)
                {
                    Thread.Sleep(1000 * 10);
                }

                IEnumerable<string> lines = File.ReadLines(autoTriager.OutputFilePath);
                Console.WriteLine(String.Join(Environment.NewLine, lines));

                string responseMessage = String.Join(Environment.NewLine, lines);
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
    }
}
