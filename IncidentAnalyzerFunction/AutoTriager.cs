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

                Writer.WriteLine("Incident Auto-Triage Report:");

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
                GetRecentDeploymentInformation();

                Writer.Close();
                ostrm.Close();
            }
            catch (Exception ex)
            {
                Writer.WriteLine("Hit Exception:\r\n{0}", ex.ToString());
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
                Writer.WriteLine("Results summary:");
            }

            // List of the result code and the description mapping
            foreach (ResultCode code in ResultCodes)
            {
                Writer.WriteLine(code.ToString());
            }
        }

        private void PrintActionSuggesions()
        {
            if (ActionSuggestions.Count() != 0)
            {
                Writer.WriteLine("*Action suggestions:");
            }

            // List of the result code and the description mapping
            foreach (string actionSuggestion in ActionSuggestions)
            {
                Writer.WriteLine(actionSuggestion);
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

        #endregion

        #region Orchestration Methods

        private async void RunTestsForCanaryTwoPercent()
        {
            Task.WaitAll(TestFor503_65(),
                         TestForSpikeInFrontEndTraffic(),
                         TestForStorageIssue(),
                         TestSpikeInFrontEndErrors(),
                         TestForCongestedSMBPool());
        }

        private async void RunTestsForRunnersHotsite()
        {
            Task.WaitAll(TestForProblemWorkersForSLASites());
        }

        private void ListTestsRunAndRevealResults()
        {
            string testsRun = "\n";
            bool isProblemFound = false;

            // Sort the tests by which ones passed and which didn't to make the output pretty :-)
            TestsRun.Sort();
            foreach (TestCase tc in TestsRun)
            {
                //Writer.WriteLine(tc.ToString());
                testsRun += tc.ToString() + "\n";
                if (tc.Code.Value != 0)
                {
                    isProblemFound = true;
                    ResultCodes.Add(tc.Code);
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
                Writer.WriteLine("*The investigation was inconclusive. Manual investigation is needed!");
            }

            Writer.WriteLine("----------------------------Tests have completed. Please see your results below------------------");

            Writer.WriteLine(testsRun);

            if (ResultCodes.Count > 0)
            {
                PrintResultCodes();
            }
        }

        private void GetStampInformation()
        {
            try
            {
                Writer.WriteLine("----------------------------Stamp Information-----------------------------------");

                string query = KustoQueries.GetStampInformationQuery(Context.StampName);

                IDataReader r = KustoClient.ExecuteQuery(query);
                while (r.Read())
                {
                    string line = r[0].ToString();
                    for (int i = r[0].ToString().Length; i < 25; i++)
                    {
                        line += " ";
                    }
                    Writer.WriteLine(line + "\t" + r[1]);
                }

                Writer.WriteLine($"\nCluster:  {Context.Cluster}");
                Writer.WriteLine($"Database: {Context.Database}");
            }
            catch (Exception ex)
            {
                Writer.WriteLine($"There was a query failure when getting recent deployments. {ex.ToString()}");
            }

        }

        private void GetRecentDeploymentInformation()
        {
            try
            {
                Writer.WriteLine("----------------------------Recent Deployments (past 5 days) -------------------");

                string query = KustoQueries.GetRecentDeploymentInformationQuery(Context.StampName, Context.StartTime);
                IDataReader r = KustoClient.ExecuteQuery(query);
                bool recentDeploymentsFound = false;
                while (r.Read())
                {
                    recentDeploymentsFound = true;
                    Writer.WriteLine("DeploymentId: \t" + r[0]);
                    Writer.WriteLine("StartTime:    \t" + r[1]);
                    Writer.WriteLine("EndTime:      \t" + r[2]);
                    Writer.WriteLine("TemplateName: \t" + r[3]);
                    Writer.WriteLine("Details:      \t" + r[4]);
                    Writer.WriteLine();
                }

                if (!recentDeploymentsFound)
                {
                    Writer.WriteLine("No recent deployments found");
                }
                else
                {
                    ActionSuggestions.Add("We detected a recent deployment on this stamp. Please investigate if this incident could have been caused by the deployment.");
                }
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when getting recent deployments");
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
                    tc.ResultMessage.Add($"\n \t - There were {countOf503_65} 503.65 errors on the frontend were detected. Manual action to scale out the worker pool may be needed.");
                    tc.ActionSuggestions.Add("\t - Scale out the worker pool for 503.65 errors. \n Scaling instructions: https://microsoft.sharepoint.com/teams/Antares/_layouts/OneNote.aspx?id=%2Fteams%2FAntares%2FShared%20Documents%2FAntares%20Feature%20Crew&wd=target%28VMSS.one%7CBCC6352F-9470-4187-82B4-0854365710F0%2FScaling%20in%20Vmss%7C3DD5048D-ADA3-4A58-B33E-24A7CB6BAF98%2F%29");
                }
                else
                {
                    tc.Result = TestCase.TestResult.Passed;
                }

                TestsRun.Add(tc);
            }
            catch (Exception ex)
            {
                Writer.WriteLine("There was a query failure when running TestFor503_65:NotEnoughWorkersAvailable");
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
                    tc.ResultMessage.Add("\n - There was a major spike in frontend traffic. This could be a DDOS attack.");
                    tc.ActionSuggestions.Add("\t - Investigate the spike in traffic, and if it is a DDOS attack, take appropriate action. It might self-heal in a few minutes. \n DDOS dashboard: https://portal.microsoftgeneva.com/dashboard/CNS/DDoSSflowCountersProd/Main");
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
                Writer.WriteLine("There was a query failure when running TestForSpikeInFrontEndTraffic");
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
                    tc.ResultMessage.Add("\n - We detected that storage availability dipped below 98% for a period of 5 minutes or longer.");
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
                Writer.WriteLine("There was a query failure when running TestForStorageIssue");
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
                    sb.Append("\n - There was a File Server issue.");
                    
                    if (fileServerSlowRead.Item2 > SlowReadThreshold)
                    {
                        isFileServerReadSlow = true;
                        sb.Append($"\n - The slowest read was {fileServerSlowRead.Item2} ms on {fileServerSlowRead.Item1}");
                    }

                    if (fileServerSlowWrite.Item2 > SlowWriteThreshold)
                    {
                        isFileServerWriteSlow = true;
                        sb.Append($"\n - The slowest write was {fileServerSlowWrite.Item2} ms on {fileServerSlowWrite.Item1}");
                    }

                    if (isFileServerReadSlow && isFileServerWriteSlow && fileServerSlowRead.Item1 == fileServerSlowWrite.Item1)
                    {
                        sb.Append($"\n - The slowest read and write were colocated on the same file server. We suggest you reboot {fileServerSlowRead.Item1}");
                        tc.ActionSuggestions.Add($"\t - Reboot the file server {fileServerSlowRead.Item1}");
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
                Writer.WriteLine("There was a query failure when running TestForFileServerIssue");
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
                    string result = "\n \t - Azure Storage side problem deteced.";
                    foreach (KeyValuePair<string, string> kvp in errorAndCount)
                    {
                        result += $"\n \t - NtStatusInfo : {kvp.Key}, Count: {kvp.Value}";
                    }

                    result += $"\n \t - We suggest you request assistance from XStore team (XStore/Triage). The storage account name is {storageAccountName}";

                    tc.ResultMessage.Add(result);
                    tc.ActionSuggestions.Add($"\t - Request assistance from XStore team (XStore/Triage). The storage account name is {storageAccountName}");
                }

                TestsRun.Add(tc);
            }
            catch (Exception ex)
            {
                Writer.WriteLine($"There was a query failure when running TestForAzureStorageIssue: {ex.ToString()}");
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
                    result = $"\n \t - We detected high traffic from the following hostnames at the following time {scopedContext.StartTime}";
                    foreach (var item in resultSet)
                    {
                        result += $"\n \t Hostname {item.Key}   Max number of requests {item.Value}";
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
                Writer.WriteLine("There was a query failure when running TestTrafficSpikeForSpecificHost");
            }
        }

        private async Task TestSpikeInFrontEndErrors()
        {
            try
            {
                TestCase tc = new TestCase("TestSpikeInFrontEndErrors");
                string result = $"\n - We detected a high number of errors on the frontends during the following times:";

                string query = KustoQueries.FrontEndSpikesErrorQuery(Context.StampName, Context.StartTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                while (r.Read())
                {
                    result += $"\n \t - {r[0].ToString()},   Avg number of FE errors {r[1].ToString()}";
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
                Writer.WriteLine("There was a query failure when running TestSpikeInFrontEndErrors");
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
                    result += $"\n \t - Detecting SMB pool congestion on {r[1]}";
                    fileServersToReboot += $" {r[1]}";
                    tc.Result = TestCase.TestResult.ProblemDetected;
                }

                if (tc.Result == TestCase.TestResult.ProblemDetected)
                {
                    tc.ResultMessage.Add(result);
                    tc.ActionSuggestions.Add($"\t - SMB pool congestion identified, we suggest rebooting the following fileservers:{fileServersToReboot}");
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
                Writer.WriteLine("There was a query failure when running TestForCongestedSMBPool");
            }
        }

        private async Task TestForProblemWorkersForSLASites()
        {
            try
            {
                TestCase tc = new TestCase("TestForProblemWorkersForSLASites");
                string result = $"\n - We detected SLA site failures on the following workers:\n";

                string query = KustoQueries.DetectErrorsOnWorkerForSLASites(Context.StampName, Context.StartTime);

                IDataReader r = await KustoClient.ExecuteQueryAsync(Context.Database, query, Properties);

                while (r.Read())
                {
                    result += "Sc_status:     \t" + r[0] + "\n";
                    result += "Sc_substatus:  \t" + r[1] + "\n";
                    result += "win32_status:  \t" + r[2] + "\n";
                    result += "EventIpAddress:\t" + r[3] + "\n";
                    result += "Count:         \t" + r[4] + "\n\n";
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
                Writer.WriteLine("There was a query failure when running TestForProblemWorkersForSLASites");
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
