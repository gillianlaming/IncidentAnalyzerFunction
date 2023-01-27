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

                FileStream ostrm = new FileStream(autoTriager.OutputFilePath, FileMode.OpenOrCreate, FileAccess.Write);
                StreamWriter writer = new StreamWriter(ostrm);

                writer.Write(sb);

                writer.Close();
                ostrm.Close();

                var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
                var stream = new FileStream(autoTriager.OutputFilePath, FileMode.Open);
                response.Content = new StreamContent(stream);
                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/html");

                // Send over the results of auto triage as a header
                string results = "";
                foreach (var code in autoTriager.ResultCodes)
                {
                    results += code.Description + " ";
                }

                response.Headers.Add("AutoTriageResult", results);
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
