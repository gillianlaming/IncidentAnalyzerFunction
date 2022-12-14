using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Kusto.Cloud.Platform.Data;
using Kusto.Data;
using Kusto.Data.Common;
using Kusto.Data.Net.Client;
using Microsoft.Azure.Services.AppAuthentication;

namespace IncidentAnalyzerFunction
{
    class AutoTriager
    {
        public ICslQueryProvider KustoClient;
        public Context Context;
        public List<TestCase> TestsRun = new List<TestCase>();
        public List<ResultCode> ResultCodes = new List<ResultCode>();
        public ClientRequestProperties Properties = new ClientRequestProperties();
        public List<string> ActionSuggestions = new List<string>();
        public List<DeploymentInfo> RecentDeployments = new List<DeploymentInfo>();
        private string _outputFile;
        public string OutputFilePath;
        public bool IsRunning = false;
        public IncidentType KindOfIncident;
        public StreamWriter Writer;

        public AutoTriager()
        {

        }

        public AutoTriager(string stampName, string startTime, IncidentType incidentType)
        {
            GetInputsAndInitializeContext(stampName, startTime);
            _outputFile = "Output" + Guid.NewGuid() + ".txt";
            OutputFilePath = Path.Combine(@"c:\home\LogFiles", _outputFile);
            KindOfIncident = incidentType;
        }

        public void Run()
        {
            try
            {
                IsRunning = true;
                FileStream ostrm;
                
                try
                {
                    ostrm = new FileStream(OutputFilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    Writer = new StreamWriter(ostrm);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Cannot open {_outputFile} for writing");
                    Console.WriteLine(e.Message);
                    return;
                }

                Writer.WriteLine(FormattingHelper.FormatTitle("Incident Auto-Triage Report:"));

                if (KindOfIncident == IncidentType.CanaryTwoPercent)
                {
                    RunTestsForCanaryTwoPercent();
                }
                else if (KindOfIncident == IncidentType.RunnersHotsite)
                {
                    RunTestsForRunnersHotsite();
                }

                ListTestsRunAndRevealResults();

                GetStampInformation();

                PrintRerunAndFeedbackInfo();

                Writer.Close();
                ostrm.Close();
            }
            catch (Exception ex)
            {
                Writer.WriteLine("Hit Exception:\r<br>{0}", ex.ToString());
            }
            finally
            {
                IsRunning = false;
            }
        }

        #region Private helpers
        private void GetInputsAndInitializeContext(string stampName, string startTime)
        {
            DateTime adjustedStartTime = Convert.ToDateTime(startTime);
            adjustedStartTime = adjustedStartTime.Subtract(TimeSpan.FromHours(1));
            DateTime adjustedEndTime = adjustedStartTime.Add(TimeSpan.FromHours(2));

            Context = new Context(stampName, adjustedStartTime.ToString(), adjustedEndTime.ToString(), "", "");
            
            KustoConnectionStringBuilder connectionString = Context.GetKustoConnectionString();
            KustoClient = KustoClientFactory.CreateCslQueryProvider(connectionString);

            Properties.SetOption(ClientRequestProperties.OptionDeferPartialQueryFailures, true);
        }

        private void PrintResultCodes()
        {
            if (ResultCodes.Count() != 0)
            {
                Writer.WriteLine(FormattingHelper.FormatHeading("----------------------------Results Summary and Queries-------------------------"));
            }

            // List of the result code and the description mapping
            foreach (ResultCode code in ResultCodes)
            {
                Writer.WriteLine(FormattingHelper.FormatFailedTest(code.ToString()));
                PrintResultCodeKustoQueries(code.Value);
                Writer.WriteLine("");
            }
        }

        private void PrintResultCodeKustoQueries(int resultCodeValue)
        {
            if (resultCodeValue == 1)
            {
                Writer.WriteLine(KustoQueries.NoAvailableWorkersQuery(Context.StampName, Context.StartTime, Context.EndTime) + "<br>");
            }

            if (resultCodeValue == 2)
            {
                Writer.WriteLine(KustoQueries.FrontEndTrafficSpikeQuery(Context.StampName, Context.StartTime));
            }

            if (resultCodeValue == 3)
            {
                Writer.WriteLine(KustoQueries.FrontEndSpikesErrorQuery(Context.StampName, Context.StartTime));
            }

            if (resultCodeValue == 4)
            {
                Writer.WriteLine(KustoQueries.TrafficSpikeForSpecificHostQuery(Context.StampName, Context.StartTime));
            }
            
            if (resultCodeValue == 5)
            {
                Writer.WriteLine(KustoQueries.AzureStorageErrorQuery(Context.StampName, Context.StartTime, Context.EndTime));
            }

            if (resultCodeValue == 6)
            {
                Writer.WriteLine(KustoQueries.StorageOverallAvaiabilityQuery(Context.StampName, Context.StartTime, Context.EndTime));
            }

            if (resultCodeValue == 7)
            {
                Writer.WriteLine(KustoQueries.FileServerRwLatencyQuery(Context.StampName, Context.StartTime, Context.EndTime));
            }

            if (resultCodeValue == 8)
            {
                Writer.WriteLine(KustoQueries.DetectErrorsOnWorkerForSLASites(Context.StampName, Context.StartTime));
            }

            if (resultCodeValue == 9)
            {
                Writer.WriteLine(KustoQueries.HighlyCongestedSMBPoolQuery(Context.StampName, Context.StartTime));
            }
        }

        private void PrintActionSuggesions()
        {
            if (ActionSuggestions.Count() != 0)
            {
                Writer.WriteLine(FormattingHelper.FormatActionSuggestion("Action suggestions:"));
            }

            // List of the result code and the description mapping
            foreach (string actionSuggestion in ActionSuggestions)
            {
                Writer.WriteLine(FormattingHelper.FormatActionSuggestion(actionSuggestion));
            }
        }

        private async Task<string> GetAzureStorageAccountName()
        {
            string storageAccountName = "";
            string storageAccountQuery = KustoQueries.GetAzureStorageAccountName(Context.StampName);
            IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, storageAccountQuery, Properties);

            while (r.Read())
            {
                storageAccountName = r[0].ToString();
            }

            return storageAccountName;
        }

        private void PrintRerunAndFeedbackInfo()
        {
            DateTime adjustedStartTime = Convert.ToDateTime(Context.StartTime).Add(TimeSpan.FromHours(1));
            Writer.WriteLine("<br>");
            Writer.WriteLine("<h1 style='font-size:19px;'> ----------------------------Finishing Auto Triage-----------------</h1><br>");
            Writer.WriteLine("To re-run AutoTriage, please click one of the below links:<br>");
            Writer.WriteLine($"<a href='https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={Context.StampName}&timeStamp={adjustedStartTime.ToString()}' target = \"_blank\"> Re-Run AutoTriage for incident start time </a><br>");
            Writer.WriteLine($"<a href='https://incidentanalyzer.azurewebsites.net/api/Function1?incidentName={Context.StampName}' target = \"_blank\"> Re-Run AutoTriage for current time </a><br>");
            Writer.WriteLine("<br> Did you encounter a bug with auto triage or have feedback? Report it");
            Writer.WriteLine($"<a href='https://forms.office.com/Pages/ResponsePage.aspx?id=v4j5cvGGr0GRqy180BHbR9yuUd7I4DxFkOM_Cds2QHpUMDFHSjlFNU82NkJCWFJWOVU3NUxFRzQ4NC4u' target = \"_blank\"> here </a><br>");

        }

        #endregion

        #region Orchestration Methods

        private async void RunTestsForCanaryTwoPercent()
        {
            Task.WaitAll(TestFor503_65(),
                         TestForSpikeInFrontEndTraffic(),
                         TestForStorageIssue(),
                         TestSpikeInFrontEndErrors(),
                         TestForCongestedSMBPool(),
                         GetRecentDeploymentInformation());
        }

        private async void RunTestsForRunnersHotsite()
        {
            Task.WaitAll(TestForProblemWorkersForSLASites());
        }

        private void ListTestsRunAndRevealResults()
        {
            string testsRun = "";
            bool isProblemFound = false;


            // Sort the tests by which ones passed and which didn't to make the output pretty :-)
            TestsRun.Sort();
            foreach (TestCase tc in TestsRun)
            {
                if (tc.Code.Value != 0)
                {
                    testsRun += FormattingHelper.FormatFailedTest(tc.ToString());
                    isProblemFound = true;
                    ResultCodes.Add(tc.Code);
                }
                else
                {
                    testsRun += FormattingHelper.FormatPassedTest(tc.ToString());
                }

                if (tc.ActionSuggestions.Count() != 0)
                {
                    ActionSuggestions.AddRange(tc.ActionSuggestions);
                }
            }

            // Print action suggestions at the very top of the report
            if (ActionSuggestions.Count > 0)
            {
                PrintActionSuggesions();
            }

            if (!isProblemFound && ActionSuggestions.Count == 0)
            {
                Writer.WriteLine(FormattingHelper.FormatActionSuggestion("The investigation was inconclusive. Manual investigation is needed!"));
            }

            Writer.WriteLine(FormattingHelper.FormatHeading("----------------------------Tests have completed. Please see your results below------------------"));

            Writer.WriteLine(testsRun);

            if (ResultCodes.Count > 0)
            {
                PrintResultCodes();
            }

            PrintRecentDeploymentInfo();
        }

        private void GetStampInformation()
        {
            try
            {
                Writer.WriteLine(FormattingHelper.FormatHeading("----------------------------Stamp Information-----------------------------------"));

                string query = KustoQueries.GetStampInformationQuery(Context.StampName);

                IDataReader r = KustoClient.ExecuteQuery(query);
                while (r.Read())
                {
                    string line = r[0].ToString();
                    for (int i = r[0].ToString().Length; i < 25; i++)
                    {
                        line += "&nbsp;";
                    }

                    if (r[1].ToString().Contains("True", StringComparison.OrdinalIgnoreCase))
                    {
                        Writer.Write(FormattingHelper.FormatPassedTest(line + r[1]));
                    }
                    else
                    {
                        Writer.Write(line + r[1] + "<br>");
                    }
                }

                Writer.WriteLine($"<br> Cluster:  {Context.Cluster} <br>");
                Writer.WriteLine($"Database: {Context.Database} <br>");
            }
            catch (Exception ex)
            {
                Writer.WriteLine($"There was a query failure when getting recent deployments. <br> {ex.ToString()} <br>");
            }

        }

        private async Task GetRecentDeploymentInformation()
        {
            try
            {
                string query = KustoQueries.GetRecentDeploymentInformationQuery(Context.StampName, Context.StartTime);
                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);
                bool recentDeploymentsFound = false;
                while (r.Read())
                {
                    DeploymentInfo di = new DeploymentInfo(r[0].ToString(), r[1].ToString(), r[2].ToString(), r[3].ToString(), r[4].ToString());
                    RecentDeployments.Add(di);
                }

                if (RecentDeployments.Count > 0)
                {
                    ActionSuggestions.Add("We detected a recent deployment on this stamp. Please investigate if this incident could have been caused by the deployment.");
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when getting recent deployments <br>");
            }

        }

        private void PrintRecentDeploymentInfo()
        {
            Writer.WriteLine(FormattingHelper.FormatHeading("----------------------------Recent Deployments (past 5 days) -------------------"));

            if (RecentDeployments.Count == 0)
            {
                Writer.WriteLine("No recent deployments found <br>");
                return;
            }

            foreach (var deployment in RecentDeployments)
            {
                Writer.WriteLine("DeploymentId:  &emsp; " + deployment.DeploymentId + "<br>");
                Writer.WriteLine("StartTime:     &emsp; " + deployment.StartTime + "<br>");
                Writer.WriteLine("EndTime:       &emsp; " + deployment.EndTime + "<br>");
                Writer.WriteLine("TemplateName:  &emsp; " + deployment.TemplateName + "<br>");
                Writer.WriteLine("Details:       &emsp; " + deployment.Details + "<br>");
                Writer.WriteLine();
            }
        }

        #endregion

        #region TestMethods

        private async Task TestFor503_65()
        {
            try
            {
                TestCase tc = new TestCase("TestFor503_65:NotEnoughWorkersAvailable");
                int countOf503_65 = 0;

                string query = KustoQueries.NoAvailableWorkersQuery(Context.StampName, Context.StartTime, Context.EndTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                while (r.Read())
                {
                    countOf503_65 = Int32.Parse(r[0].ToString());
                }

                if (countOf503_65 > 50)
                {
                    tc.Result = TestCase.TestResult.ProblemDetected;
                    tc.ResultMessage.Add($"<br> &emsp; - There were {countOf503_65} 503.65 errors on the frontend were detected. Manual action to scale out the worker pool may be needed.");
                    tc.ActionSuggestions.Add("&emsp; - Scale out the worker pool for 503.65 errors. &emsp Scaling instructions: https://microsoft.sharepoint.com/teams/Antares/_layouts/OneNote.aspx?id=%2Fteams%2FAntares%2FShared%20Documents%2FAntares%20Feature%20Crew&wd=target%28VMSS.one%7CBCC6352F-9470-4187-82B4-0854365710F0%2FScaling%20in%20Vmss%7C3DD5048D-ADA3-4A58-B33E-24A7CB6BAF98%2F%29");
                }
                else
                {
                    tc.Result = TestCase.TestResult.Passed;
                }

                TestsRun.Add(tc);
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestFor503_65:NotEnoughWorkersAvailable <br>");
            }
        }

        private async Task TestForSpikeInFrontEndTraffic()
        {
            try
            {

                TestCase tc = new TestCase("TestForSpikeInFrontEndTraffic");
                bool isSuspectedDDOS = false;

                List<Context> childContexts = new List<Context>();

                string query = KustoQueries.FrontEndTrafficSpikeQuery(Context.StampName, Context.StartTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                while (r.Read())
                {
                    isSuspectedDDOS = true;
                    Context childContext = new Context(Context);
                    childContext.StartTime = r[2].ToString();
                    childContexts.Add(childContext);
                }

                if (isSuspectedDDOS)
                {
                    tc.Result = TestCase.TestResult.ProblemDetected;
                    tc.ResultMessage.Add("<br> - There was a major spike in frontend traffic. This could be a DDOS attack.");
                    tc.ActionSuggestions.Add("&emsp; - Investigate the spike in traffic, and if it is a DDOS attack, take appropriate action. It might self-heal in a few minutes. <br> DDOS dashboard: https://portal.microsoftgeneva.com/dashboard/CNS/DDoSSflowCountersProd/Main");
                }
                else
                {
                    tc.Result = TestCase.TestResult.Passed;
                }

                TestsRun.Add(tc);

                foreach (Context childContext in childContexts)
                {
                    await TestTrafficSpikeForSpecificHost(childContext);
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestForSpikeInFrontEndTraffic <br>");
            }
        }

        private async Task TestForStorageIssue()
        {
            try
            {
                //Define some thresholds:
                const int MinutesOfStorageGlitchyToDeclareStorageOutage = 3;
                const double AvailabilityThreshold = 0.98;
                
                TestCase tc = new TestCase("TestForStorageIssue");

                string query = KustoQueries.StorageOverallAvaiabilityQuery(Context.StampName, Context.StartTime, Context.EndTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);
                bool storageIssueDuringPreviousMinute = false;
                int maxNumMinutesStorageDowntime = 0;
                int numMinutesStorageAvailDropped = 0;
                
                while (r.Read())
                {
                    if (double.Parse(r[1].ToString()) <= AvailabilityThreshold)
                    {
                        numMinutesStorageAvailDropped = storageIssueDuringPreviousMinute ? numMinutesStorageAvailDropped+1 : 1;
                        maxNumMinutesStorageDowntime = Math.Max(maxNumMinutesStorageDowntime, numMinutesStorageAvailDropped);
                        storageIssueDuringPreviousMinute = true;
                    }
                    else
                    {
                        storageIssueDuringPreviousMinute = false;
                    }
                }


                if (maxNumMinutesStorageDowntime >= MinutesOfStorageGlitchyToDeclareStorageOutage)
                {
                    tc.Result = TestCase.TestResult.ProblemDetected;
                    tc.ResultMessage.Add("<br> - We detected that storage availability dipped below 98% for a period of 5 minutes or longer.");
                    TestsRun.Add(tc);
                    await TestForAzureStorageIssue();
                    await TestForFileServerIssue();
                }
                else
                {
                    tc.Result = TestCase.TestResult.Passed;
                    TestsRun.Add(tc);
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestForStorageIssue <br>");
            }
        }

        private async Task TestForFileServerIssue()
        {
            // look for file server with high RW latency
            try
            {
                const int SlowReadThreshold = 1000;
                const int SlowWriteThreshold = 1000;
                TestCase tc = new TestCase("TestForFileServerIssue");
                bool isFileServerReadSlow = false;
                bool isFileServerWriteSlow = true;
                string query = KustoQueries.FileServerRwLatencyQuery(Context.StampName, Context.StartTime, Context.EndTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                (string, double) fileServerSlowRead = ("", 0.0);
                (string, double) fileServerSlowWrite = ("", 0.0);

                while (r.Read())
                {
                    if (string.IsNullOrEmpty(fileServerSlowRead.Item1) || fileServerSlowRead.Item2 < double.Parse(r[1].ToString()))
                    {
                        fileServerSlowRead.Item1 = r[0].ToString();
                        fileServerSlowRead.Item2 = double.Parse(r[1].ToString());
                    }

                    if (string.IsNullOrEmpty(fileServerSlowWrite.Item1) || fileServerSlowWrite.Item2 < double.Parse(r[2].ToString()))
                    {
                        fileServerSlowWrite.Item1 = r[0].ToString();
                        fileServerSlowWrite.Item2 = double.Parse(r[2].ToString());
                    }
                }
                
                if (fileServerSlowRead.Item2 > SlowReadThreshold || fileServerSlowWrite.Item2 > SlowWriteThreshold)
                {
                    tc.Result = TestCase.TestResult.ProblemDetected;
                    StringBuilder sb = new StringBuilder();
                    sb.Append("<br> - There was a File Server issue.");
                    
                    if (fileServerSlowRead.Item2 > SlowReadThreshold)
                    {
                        isFileServerReadSlow = true;
                        sb.Append($"<br> - The slowest read was {fileServerSlowRead.Item2} ms on {fileServerSlowRead.Item1}");
                    }

                    if (fileServerSlowWrite.Item2 > SlowWriteThreshold)
                    {
                        isFileServerWriteSlow = true;
                        sb.Append($"<br> - The slowest write was {fileServerSlowWrite.Item2} ms on {fileServerSlowWrite.Item1}");
                    }

                    if (isFileServerReadSlow && isFileServerWriteSlow && fileServerSlowRead.Item1 == fileServerSlowWrite.Item1)
                    {
                        sb.Append($"<br> - The slowest read and write were colocated on the same file server. We suggest you reboot {fileServerSlowRead.Item1}");
                        tc.ActionSuggestions.Add($"&emsp; - Reboot the file server {fileServerSlowRead.Item1}");
                    }

                    tc.ResultMessage.Add(sb.ToString());
                }
                else
                {
                    tc.Result = TestCase.TestResult.Passed;
                }

                TestsRun.Add(tc);
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestForFileServerIssue <br>");
            }
        }

        private async Task TestForAzureStorageIssue()
        {
            try
            {
                const int ErrorCountThreshold = 10;
                //bool azureStorageIssue = false;

                TestCase tc = new TestCase("TestForAzureStorageIssue");
                string query = KustoQueries.AzureStorageErrorQuery(Context.StampName, Context.StartTime, Context.EndTime);
                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                Dictionary<string, string> errorAndCount = new Dictionary<string, string>();

                while (r.Read())
                {
                    if (int.Parse(r[1].ToString()) > ErrorCountThreshold)
                    {
                        errorAndCount.Add(r[0].ToString(), r[1].ToString());
                    }
                }

                if (errorAndCount.Count > 0)
                {
                    string storageAccountName = await GetAzureStorageAccountName();

                    //azureStorageIssue = true;
                    tc.Result = TestCase.TestResult.ProblemDetected;
                    string result = "<br> &emsp; - Azure Storage side problem detected.";
                    foreach (KeyValuePair<string, string> kvp in errorAndCount)
                    {
                        result += $"<br> &emsp; - NtStatusInfo : {kvp.Key}, Count: {kvp.Value}";
                    }

                    result += $"<br> &emsp; - We suggest you request assistance from XStore team (XStore/Triage). The storage account name is {storageAccountName}";

                    tc.ResultMessage.Add(result);
                    tc.ActionSuggestions.Add($"&emsp; - Request assistance from XStore team (XStore/Triage). The storage account name is {storageAccountName}");
                }

                TestsRun.Add(tc);
            }
            catch (Exception ex)
            {
                Writer.WriteLine($"There was a query failure when running TestForAzureStorageIssue: {ex.ToString()} <br>");
            }
        }


        private async Task TestTrafficSpikeForSpecificHost(Context scopedContext)
        {
            try
            {
                TestCase tc = new TestCase("TestTrafficSpikeForSpecificHost");
                Dictionary<string, int> resultSet = new Dictionary<string, int>();
                string result = "";
                string query = KustoQueries.TrafficSpikeForSpecificHostQuery(scopedContext.StampName, scopedContext.StartTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(scopedContext.Database, query, Properties);

                while (r.Read())
                {
                    resultSet.Add(r[0].ToString(), Int32.Parse(r[1].ToString()));
                    tc.Result = TestCase.TestResult.ProblemDetected;
                }

                if (resultSet.Count() == 0)
                {
                    tc.Result = TestCase.TestResult.Passed;
                }
                else
                {
                    result = $"<br> &emsp; - We detected high traffic from the following hostnames at the following time {scopedContext.StartTime}";
                    foreach (var item in resultSet)
                    {
                        result += $"<br> &emsp; Hostname {item.Key}   Max number of requests {item.Value}";
                    }

                    tc.ResultMessage.Add(result);
                }

                // This test could be run multiple times so ensure the test case is only added once
                if (!TestsRun.Contains(tc))
                {
                    TestsRun.Add(tc);
                }
                else
                {
                    TestCase preexistingTestCase = TestsRun.FirstOrDefault(testCase => testCase.TestName == tc.TestName);
                    if (preexistingTestCase != null)
                    {
                        preexistingTestCase.ResultMessage.Add(result);
                    }
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestTrafficSpikeForSpecificHost <br>");
            }
        }

        private async Task TestSpikeInFrontEndErrors()
        {
            try
            {
                TestCase tc = new TestCase("TestSpikeInFrontEndErrors");
                string result = $"<br> - We detected a high number of errors on the frontends during the following times:";

                string query = KustoQueries.FrontEndSpikesErrorQuery(Context.StampName, Context.StartTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                while (r.Read())
                {
                    result += $"<br> &emsp; - {r[0].ToString()},   Avg number of FE errors {r[1].ToString()}";
                    tc.Result = TestCase.TestResult.ProblemDetected;
                }

                if (tc.Result == TestCase.TestResult.ProblemDetected)
                {
                    tc.ResultMessage.Add(result);
                }
                else
                {
                    result = "";
                }

                if (!TestsRun.Contains(tc))
                {
                    TestsRun.Add(tc);
                }
                else
                {
                    TestCase preexistingTestCase = TestsRun.FirstOrDefault(testCase => testCase.TestName == tc.TestName);
                    if (preexistingTestCase != null)
                    {
                        preexistingTestCase.ResultMessage.Add(result);
                    }
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestSpikeInFrontEndErrors <br>");
            }
        }

        private async Task TestForCongestedSMBPool()
        {
            try
            {
                TestCase tc = new TestCase("TestForCongestedSMBPool");

                // During initialization, we adjusted the start time by an hour
                // Add that time back so we have the exact time passed through on execution
                DateTime adjustedStartTime = Convert.ToDateTime(Context.StartTime).Add(TimeSpan.FromHours(1));
                string query = KustoQueries.HighlyCongestedSMBPoolQuery(Context.StampName, adjustedStartTime.ToString());
                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);
                string result = "";
                string fileServersToReboot = "";
                while (r.Read())
                {
                    result += $"<br> &emsp; - Detecting SMB pool congestion on {r[1]}";
                    fileServersToReboot += $" {r[1]}";
                    tc.Result = TestCase.TestResult.ProblemDetected;
                }

                if (tc.Result == TestCase.TestResult.ProblemDetected)
                {
                    tc.ResultMessage.Add(result);
                    tc.ActionSuggestions.Add($"&emsp; - SMB pool congestion identified, we suggest rebooting the following fileservers:{fileServersToReboot}");
                }
                else
                {
                    result = "";
                }

                if (!TestsRun.Contains(tc))
                {
                    TestsRun.Add(tc);
                }
                else
                {
                    TestCase preexistingTestCase = TestsRun.FirstOrDefault(testCase => testCase.TestName == tc.TestName);
                    if (preexistingTestCase != null)
                    {
                        preexistingTestCase.ResultMessage.Add(result);
                    }
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestForCongestedSMBPool <br>");
            }
        }

        private async Task TestForProblemWorkersForSLASites()
        {
            try
            {
                TestCase tc = new TestCase("TestForProblemWorkersForSLASites");
                string result = $"<br> - We detected SLA site failures on the following workers:<br>";

                string query = KustoQueries.DetectErrorsOnWorkerForSLASites(Context.StampName, Context.StartTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                while (r.Read())
                {
                    result += "Sc_status:     \t" + r[0] + "<br>";
                    result += "Sc_substatus:  \t" + r[1] + "<br>";
                    result += "win32_status:  \t" + r[2] + "<br>";
                    result += "EventIpAddress:\t" + r[3] + "<br>";
                    result += "Count:         \t" + r[4] + "<br><br>";
                    tc.Result = TestCase.TestResult.ProblemDetected;
                }

                if (tc.Result != TestCase.TestResult.ProblemDetected)
                {
                    tc.Result = TestCase.TestResult.Passed;
                    result = "";
                }
                else
                {
                    tc.ResultMessage.Add(result);
                }

                TestsRun.Add(tc);

            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestForProblemWorkersForSLASites <br>");
            }
        }

        #endregion

        public enum IncidentType
        {
            CanaryTwoPercent,
            RunnersHotsite
        }
    }
}
