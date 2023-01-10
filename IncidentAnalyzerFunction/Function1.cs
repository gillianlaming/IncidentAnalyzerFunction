using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
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
using System.Net.Http;
using Microsoft.AspNetCore.Mvc.Formatters;
using Azure.Core;
using System.Net.Http.Formatting;

namespace IncidentAnalyzerFunction
{
    public class Function1
    {
        [FunctionName("Function1")]
        public async Task<HttpResponseMessage> Run(
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
                }

                sb.Append("<br>");
                sb.AppendLine("<h1 style='font-size:19px;'> ----------------------------Finishing Auto Triage-----------------</h1><br>");
                sb.AppendLine("To re-run AutoTriage, please click one of the below links:<br>");
                sb.AppendLine($"<a href='https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={req.Query["incidentName"]}&timeStamp={startTime}' target = \"_blank\"> Re-Run AutoTriage for incident start time </a><br>");
                sb.AppendLine($"<a href='https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={req.Query["incidentName"]}' target = \"_blank\"> Re-Run AutoTriage for current time </a><br>");

                sb.AppendLine("<br> Did you encounter a bug with auto triage or have feedback? Report it");
                sb.AppendLine($"<a href='https://forms.office.com/Pages/ResponsePage.aspx?id=v4j5cvGGr0GRqy180BHbR9yuUd7I4DxFkOM_Cds2QHpUMDFHSjlFNU82NkJCWFJWOVU3NUxFRzQ4NC4u' target = \"_blank\"> here </a><br>");
               
                
                FileStream ostrm = new FileStream(autoTriager.OutputFilePath, FileMode.OpenOrCreate, FileAccess.Write);
                StreamWriter writer = new StreamWriter(ostrm);

                writer.Write(sb);

                writer.Close();
                ostrm.Close();

                var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
                var stream = new FileStream(autoTriager.OutputFilePath, FileMode.Open);
                response.Content = new StreamContent(stream);
                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/html");
                return response;
            }
            catch (Exception ex)
            {
                log.LogInformation($"Encountered exception {ex.ToString()}");
                return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
            }
        }

        public string ParseStampNameFromIncidentName(string incidentName)
        {
            if (String.IsNullOrEmpty(incidentName))
            {
                throw new ArgumentNullException("Incident name");
            }

            // TODO: add support for national clouds 
            int start = incidentName.IndexOf("waws");

            if (start == -1)
            {
                throw new ArgumentException("Stamp name");
            }

            int end = start;

            while (end < incidentName.Length && incidentName[end] != ' ')
            {
                end++;
            }
            
            return incidentName.Substring(start, end - start);
        }

        public enum LineFormat
        {
            Passed,
            ProblemDetected,
            Heading,
            Title,
            ReportResult
        }

    }
}
