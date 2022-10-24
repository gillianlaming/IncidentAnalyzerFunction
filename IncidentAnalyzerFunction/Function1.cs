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
            string stampName = ParseStampNameFromIncidentName(req.Query["incidentName"]);
            string startTime = ParseTimeStampFromIncidentName(req.Query["incidentName"]);
            log.LogInformation($"stampname is {stampName}");
            log.LogInformation($"starttime is {startTime}");

            //string applicationFilePath = @"C:\Users\glaming\source\repos\IncidentAnalyzerFunction\IncidentAnalyzerFunction\AutoAnalyzerExe\ExptKustoQuery.exe";
            string applicationFilePath = @"c:\home\site\wwwroot\ExptKustoQuery.exe";
            Process autoAnalyzerJob = Process.Start(applicationFilePath, $"{stampName} {startTime}");

            autoAnalyzerJob.WaitForExit();

            //string fileName = @"C:\Users\glaming\source\repos\IncidentAnalyzerFunction\IncidentAnalyzerFunction\AutoAnalyzerExe\Output.txt";
            string fileName = @"c:\home\LogFiles\Output.txt";

            string[] lines = File.ReadAllLines(fileName);
            StringBuilder sb = new StringBuilder();

            foreach (string line in lines)
            {
                sb.AppendLine(line);
                sb.Append("<br>");
            }

            //IEnumerable<string> lines = File.ReadLines(fileName);
            //Console.WriteLine(String.Join(Environment.NewLine, lines));

            string responseMessage = sb.ToString();
            return new OkObjectResult(responseMessage);
        }

        private static string ParseTimeStampFromIncidentName(string incidentName)
        {
            int startIndex = incidentName.IndexOf("StartTime:") + "StartTime:".Length;
            return incidentName.Substring(startIndex).Trim();
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
