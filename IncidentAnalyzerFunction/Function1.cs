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
            string stampName = req.Query["stampName"];
            string startTime = req.Query["startTime"];
            log.LogInformation($"stampname is {stampName}");
            log.LogInformation($"starttime is {startTime}");

            /*
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            string name = name ?? data?.name;
            */

            // this needs to be an absolute path. consider uploading to network share?
            string applicationFilePath = @"C:\Users\glaming\source\repos\IncidentAnalyzerFunction\IncidentAnalyzerFunction\AutoAnalyzerExe\ExptKustoQuery.exe";

            Process autoAnalyzerJob = Process.Start(applicationFilePath, $"{stampName} {startTime}");

            // TODO: implement timeout
            while (!autoAnalyzerJob.HasExited)
            {
                Thread.Sleep(5000); // sleep for 5 seconds to avoid tight while loop
            }

            string fileName = @"C:\Users\glaming\source\repos\IncidentAnalyzerFunction\IncidentAnalyzerFunction\AutoAnalyzerExe\Output.txt";

            IEnumerable<string> lines = File.ReadLines(fileName);
            Console.WriteLine(String.Join(Environment.NewLine, lines));

            string responseMessage = String.Join(Environment.NewLine, lines);
            return new OkObjectResult(responseMessage);

            
        }
    }
}
