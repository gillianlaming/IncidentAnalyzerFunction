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
                    string formattedLine = line;

                    if (line.Contains("Passed", StringComparison.OrdinalIgnoreCase) || line.Contains("True", StringComparison.OrdinalIgnoreCase))
                    {
                        formattedLine = FormatLine(line, LineFormat.Passed);
                    }
                    else if (line.Contains("ProblemDetected", StringComparison.OrdinalIgnoreCase))
                    {
                        formattedLine = FormatLine(line, LineFormat.ProblemDetected);
                    }
                    else if (line.StartsWith("--"))
                    {
                        formattedLine = FormatLine(line, LineFormat.Heading);
                    }
                    else if (line.StartsWith("Incident"))
                    {
                        formattedLine = FormatLine(line, LineFormat.Title);
                    }
                    else if (line.StartsWith("*"))
                    {
                        formattedLine = FormatLine(line, LineFormat.Result);
                    }
                    else
                    {
                        formattedLine += "<br>";
                    }

                    sb.AppendLine(formattedLine);
                }

                sb.Append("<br>");
                sb.AppendLine("<h1 style='font-size:19px;'> ----------------------------Finishing Auto Triage-----------------</h1><br>");
                sb.AppendLine("To re-run AutoTriage, please click one of the below links:<br>");
                sb.AppendLine($"<a href='https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={req.Query["incidentName"]}&timeStamp={startTime}' target = \"_blank\"> Re-Run AutoTriage for incident start time </a><br>");
                sb.AppendLine($"<a href='https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={req.Query["incidentName"]}' target = \"_blank\"> Re-Run AutoTriage for current time </a>");

                string responseMessage = sb.ToString();
                return new OkObjectResult(responseMessage);
            }
            catch (Exception ex)
            {
                log.LogInformation($"Encountered exception {ex.ToString()}");
                return new OkObjectResult($"Encountered exception {ex.ToString()}");
            }
        }

        private string FormatLine(string line, LineFormat lineFormat)
        {
            if (lineFormat == LineFormat.Passed)
            {
                line = "<p style='color:green;'>" + line + "</p>";
            }
            else if (lineFormat == LineFormat.ProblemDetected)
            {
                line = "<p style='color:red;'>" + line + "</p>";
            }
            else if (lineFormat == LineFormat.Heading)
            {
                line = "<h1 style='font-size:19px;'>" + line + "</h1>";
            }
            else if (lineFormat == LineFormat.Title)
            {
                line = "<h1 style='font-size:30px; color:blue;'>" + line + "</h1>";
            }
            else if (lineFormat == LineFormat.Result)
            {
                line = "<p style='color:orange; font-size:20px'>" + line + "<br>";
            }

            return line;
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

        public enum LineFormat
        {
            Passed,
            ProblemDetected,
            Heading,
            Title,
            Result
        }

    }
}
