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
            string startTime = req.Query["startTime"];
            log.LogInformation($"stampname is {stampName}");
            log.LogInformation($"starttime is {startTime}");

            /*
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            string name = name ?? data?.name;
            */

            //string applicationFilePath = @"C:\Users\glaming\source\repos\IncidentAnalyzerFunction\IncidentAnalyzerFunction\AutoAnalyzerExe\ExptKustoQuery.exe";
            string applicationFilePath = @"c:\home\site\wwwroot\ExptKustoQuery.exe";
            Process autoAnalyzerJob = Process.Start(applicationFilePath, $"{stampName} {startTime}");

            // TODO: implement timeout
            while (!autoAnalyzerJob.HasExited)
            {
                Thread.Sleep(5000); // sleep for 5 seconds to avoid tight while loop
            }

            //string fileName = @"C:\Users\glaming\source\repos\IncidentAnalyzerFunction\IncidentAnalyzerFunction\AutoAnalyzerExe\Output.txt";
            string fileName = @"c:\home\LogFiles\Output.txt";

            IEnumerable<string> lines = File.ReadLines(fileName);
            Console.WriteLine(String.Join(Environment.NewLine, lines));

            string responseMessage = String.Join(Environment.NewLine, lines);
            return new OkObjectResult(responseMessage);

            
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
